// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package admission

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/endpoint"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
)

const (
	logPreviousEndpoint = "previousEndpoint"
	logPreviousBoot     = "previousBoot"
)

type durableRecorder struct {
	mu        lock.Mutex
	stateDir  string
	clusterID uint32
	nodeName  func() string
	logger    *slog.Logger
	store     *IntentStore
	closed    bool
}

// No IO occurs at construction. The real agent creates StateDir in initEnv
// before Hive.Run, while Populate-only tests/subcommands need no filesystem.
func newRequiredRecorder(stateDir string, clusterID uint32, nodeName func() string, logger *slog.Logger) requiredRecorder {
	return &durableRecorder{stateDir: stateDir, clusterID: clusterID, nodeName: nodeName, logger: logger}
}
func (r *durableRecorder) openLocked() error {
	if r.closed {
		return errRequiredClosed
	}
	if r.store == nil {
		s, err := OpenIntentStore(r.stateDir)
		if err != nil {
			return err
		}
		s.onReplace = func(old, replacement RequiredIntent) {
			r.logger.Info("Replaced durable Required intent of a sandbox that no longer exists",
				logfields.K8sNamespace, replacement.Namespace,
				logfields.Pod, replacement.PodName,
				logfields.K8sUID, replacement.PodUID,
				logPreviousEndpoint, old.EndpointID,
				logfields.EndpointID, replacement.EndpointID,
				logPreviousBoot, old.BootID,
				logfields.BootID, replacement.BootID)
		}
		r.store = s
	}
	return nil
}
func (r *durableRecorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.store != nil {
		return r.store.Close()
	}
	return nil
}
func (r *durableRecorder) Lookup(ctx context.Context, podUID string) (string, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	if err := r.openLocked(); err != nil {
		return "", false, err
	}
	records, err := r.store.List()
	if err != nil {
		return "", false, err
	}
	var namespaceUID string
	found := false
	seen := map[string]bool{}
	for _, record := range records {
		if record.ClusterID != r.clusterID || record.NodeName != r.nodeName() {
			return "", false, fmt.Errorf("%w: journal belongs to another cluster or node", errRequiredConflict)
		}
		if seen[record.PodUID] {
			return "", false, fmt.Errorf("%w: duplicate immutable Pod identity", errRequiredConflict)
		}
		seen[record.PodUID] = true
		if record.PodUID == podUID {
			namespaceUID = record.NamespaceUID
			found = true
		}
	}
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	return namespaceUID, found, nil
}

type pinnedSandbox struct {
	ns                    *netns.NetNS
	device, inode, cookie uint64
}

func pinSandbox(path string) (*pinnedSandbox, error) {
	ns, err := netns.OpenPinned(path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*pinnedSandbox, error) { ns.Close(); return nil, err }
	kind, err := unix.IoctlRetInt(ns.FD(), unix.NS_GET_NSTYPE)
	if err != nil {
		return fail(err)
	}
	if kind != unix.CLONE_NEWNET {
		return fail(fmt.Errorf("%w: not a network namespace", errRequiredInvalid))
	}
	var stat unix.Stat_t
	if err := unix.Fstat(ns.FD(), &stat); err != nil {
		return fail(err)
	}
	var cookie uint64
	if err := ns.Do(func() error { var err error; cookie, err = netns.GetNetNSCookie(); return err }); err != nil {
		return fail(err)
	}
	if cookie == 0 {
		return fail(fmt.Errorf("%w: missing namespace cookie", errRequiredInvalid))
	}
	return &pinnedSandbox{ns: ns, device: uint64(stat.Dev), inode: stat.Ino, cookie: cookie}, nil
}
func (s *pinnedSandbox) matches(other *pinnedSandbox) bool {
	return s.device == other.device && s.inode == other.inode && s.cookie == other.cookie
}

func (r *durableRecorder) Record(ctx context.Context, ep *endpoint.Endpoint, namespaceUID string, pod *slimv1.Pod) (func() error, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if ep == nil || pod == nil || namespaceUID == "" {
		return nil, nil, fmt.Errorf("%w: missing immutable identity", errRequiredInvalid)
	}
	pod = pod.DeepCopy()
	identity := RequiredIdentity{ClusterID: r.clusterID, NodeName: pod.Spec.NodeName,
		Namespace: pod.Namespace, NamespaceUID: namespaceUID, PodName: pod.Name,
		PodUID: string(pod.UID), ServiceAccount: pod.Spec.ServiceAccountName,
		EndpointID: ep.GetID16(), ContainerID: ep.GetContainerID(), NetnsPath: ep.GetContainerNetnsPath()}
	cookie := ep.GetEndpointNetNsCookie()
	if identity.PodUID == "" || identity.PodUID != ep.K8sUID || identity.Namespace != ep.GetK8sNamespace() ||
		identity.PodName != ep.GetK8sPodName() || identity.NodeName == "" || identity.NodeName != r.nodeName() ||
		identity.ServiceAccount == "" || pod.DeletionTimestamp != nil || pod.Spec.HostNetwork {
		return nil, nil, fmt.Errorf("%w: live Pod does not bind immutable endpoint identity", errRequiredInvalid)
	}
	unchanged := func() bool {
		return ep.GetContainerNetnsPath() == identity.NetnsPath && ep.GetContainerID() == identity.ContainerID &&
			ep.GetID16() == identity.EndpointID && ep.K8sUID == identity.PodUID && ep.GetEndpointNetNsCookie() == cookie
	}
	sandbox, err := pinSandbox(identity.NetnsPath)
	if err != nil {
		return nil, nil, err
	}
	release := func() { sandbox.ns.Close() }
	fail := func(err error) (func() error, func(), error) { release(); return nil, nil, err }
	if cookie == 0 || cookie != sandbox.cookie || !unchanged() {
		return fail(fmt.Errorf("%w: endpoint differs from pinned sandbox", errRequiredConflict))
	}
	identity.NetnsDevice, identity.NetnsInode, identity.NetnsCookie = sandbox.device, sandbox.inode, sandbox.cookie
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	r.mu.Lock()
	err = ctx.Err()
	if err == nil {
		err = r.openLocked()
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && !unchanged() {
		err = fmt.Errorf("%w: endpoint changed before persistence", errRequiredConflict)
	}
	if err == nil {
		_, err = r.store.PersistRequired(identity)
	}
	r.mu.Unlock()
	if err != nil {
		return fail(err)
	}
	// Persistence is synchronous: honor cancellation before entering the write
	// transaction. Once it starts, a committed intent survives cancellation;
	// cancellation must never erase Required or become enrollment success.
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	recheck := func() error {
		current, err := pinSandbox(identity.NetnsPath)
		if err != nil {
			return err
		}
		defer current.ns.Close()
		if !sandbox.matches(current) || !unchanged() {
			return fmt.Errorf("%w: sandbox changed during admission", errRequiredConflict)
		}
		return nil
	}
	if err := recheck(); err != nil {
		return fail(err)
	}
	return recheck, release, nil
}

func isRequiredConflict(err error) bool { return errors.Is(err, errRequiredConflict) }

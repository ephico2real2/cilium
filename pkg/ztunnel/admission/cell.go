// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	slimcore "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/core/v1"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

const (
	logStage              = "stage"
	logDeadline           = "deadline"
	logNamespaceUID       = "namespaceUID"
	logEnrollmentRequired = "enrollmentRequired"
	logSourcePublisher    = "ztunnel-source-membership-publisher"
)

var Cell = cell.Module(
	"ztunnel-admission",
	"ztunnel new-pod startup admission",
	cell.Provide(
		func(p membershipRegistryParams) *membership.Registry {
			return membership.NewRegistry(p.ClusterInfo.ID)
		},
		newGate,
	),
)

type membershipRegistryParams struct {
	cell.In
	ClusterInfo cmtypes.ClusterInfo
}

type params struct {
	cell.In
	Lifecycle   cell.Lifecycle
	ClusterInfo cmtypes.ClusterInfo
	Config      config.Config
	Clientset   k8sclient.Clientset
	Server      *zds.Server
	AgentConfig *option.DaemonConfig
	Logger      *slog.Logger
	Registry    *membership.Registry
	JobGroup    job.Group
	KVStore     kvstore.Client                  `optional:"true"`
	Endpoints   endpointmanager.EndpointManager `optional:"true"`
}

type out struct {
	cell.Out
	Gate             endpointmanager.EndpointCreationGate `group:"endpoint-creation-gates"`
	Revalidator      membership.EndpointRevalidator       `group:"ztunnel-endpoint-revalidators"`
	PolicyTransition endpoint.ZtunnelPolicyTransitioner   `group:"ztunnel-policy-transitions"`
}

type gate struct {
	serverDisabledForExecution bool
	policyOwnership            zds.PolicyOwnershipInspector
	policyDrainer              zds.LivePolicyDrainCleaner
	recorder                   requiredRecorder
	enabled                    bool
	core                       slimcore.CoreV1Interface
	enroll                     func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error
	validateNetns              func(string) error
	nodeName                   func() string
	agentNamespace             string
	logger                     *slog.Logger
	membership                 *membership.Registry
	budget                     time.Duration
	attemptTimeout             time.Duration
	initialBackoff             time.Duration
}

type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }
func permanent(format string, args ...any) error {
	return &permanentError{err: fmt.Errorf(format, args...)}
}

func newGate(p params) (out, error) {
	enabled := p.Config.EnableZTunnel && p.Config.RequireMTLS
	g := &gate{enabled: enabled, logger: p.Logger, nodeName: nodetypes.GetName,
		budget: 30 * time.Second, attemptTimeout: 5 * time.Second, initialBackoff: 100 * time.Millisecond,
		validateNetns: validateNetworkNamespace,
		membership:    p.Registry,
	}
	g.serverDisabledForExecution = !p.Config.EnableZTunnel && p.Server == nil
	g.policyOwnership = p.Server // Also inspect retained ADDs when configuration is disabled.
	if p.AgentConfig != nil {
		g.agentNamespace = p.AgentConfig.K8sNamespace
	}
	if enabled {
		if p.Clientset == nil || !p.Clientset.IsEnabled() || p.Server == nil || g.agentNamespace == "" || g.membership == nil {
			return out{}, fmt.Errorf("strict ztunnel admission requires Kubernetes, ZDS, a membership registry, and configured agent namespace")
		}
		g.core = p.Clientset.Slim().CoreV1()
		g.enroll = p.Server.EnrollEndpointForOwnerContext
		g.policyDrainer = p.Server
		g.recorder = newRequiredRecorder(p.AgentConfig.StateDir, p.ClusterInfo.ID, g.nodeName)
		p.Lifecycle.Append(cell.Hook{OnStop: func(cell.HookContext) error { return g.recorder.Close() }})
		if p.Config.EnableRemoteWorkloadMembership {
			if p.KVStore == nil || !p.KVStore.IsEnabled() || p.Endpoints == nil {
				return out{}, fmt.Errorf("remote workload membership requires an enabled KVStore and endpoint manager")
			}
			publisher, err := membership.NewSourcePublisher(g.membership, p.Endpoints, []membership.EndpointRevalidator{g}, p.KVStore, p.Logger,
				membership.SourcePublisherConfig{ClusterInfo: p.ClusterInfo, NodeName: g.nodeName()})
			if err != nil {
				return out{}, fmt.Errorf("remote workload membership cannot start without a short-lease KVStore backend: %w", err)
			}
			p.JobGroup.Add(job.OneShot(logSourcePublisher, func(ctx context.Context, _ cell.Health) error {
				return publisher.Run(ctx)
			}))
		}
	}
	return out{Gate: g, Revalidator: g, PolicyTransition: g}, nil
}

// ShouldRevalidate selects namespace-enrolled endpoints and endpoints still
// present in the durable Required ledger. It lets restored endpoints rebuild
// process-local membership before ztunnel's initial snapshot is seeded.
func (g *gate) ShouldRevalidate(ctx context.Context, ep *endpoint.Endpoint, namespaceEnrolled bool) (bool, error) {
	if !g.enabled {
		return false, nil
	}
	if ep == nil || ep.GetK8sPodUID() == "" {
		return false, fmt.Errorf("endpoint restore admission requires immutable Pod UID")
	}
	if namespaceEnrolled {
		return true, nil
	}
	if g.recorder == nil {
		return false, fmt.Errorf("durable Required intent recorder is unavailable")
	}
	_, required, err := g.recorder.Lookup(ctx, ep.GetK8sPodUID())
	if err != nil {
		return false, fmt.Errorf("reading durable Required intent for restored endpoint: %w", err)
	}
	return required, nil
}

func (g *gate) RevalidateEndpoint(ctx context.Context, ep *endpoint.Endpoint) error {
	return g.WaitForEndpoint(ctx, ep)
}

type membershipAttempt struct {
	ref        membership.Reference
	generation uint64
}

func (g *gate) WaitForEndpoint(parent context.Context, ep *endpoint.Endpoint) (resultErr error) {
	if !g.enabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, g.budget)
	defer cancel()
	started := time.Now()
	deadline, _ := ctx.Deadline()
	var namespaceUID types.UID
	var attempt int
	required := false // Never downgrade an observed enrolled request on retry.
	token := membershipAttempt{}
	if ep != nil && g.membership != nil {
		if ref, state, ok := g.membership.CurrentForPodUID(ep.GetK8sPodUID()); ok && state.EndpointID == ep.GetID16() && state.NetnsPath == ep.GetContainerNetnsPath() {
			token = membershipAttempt{ref, state.ZDSGeneration}
		}
	}
	namespace, name, uid := "", "", ""
	var endpointID uint16
	if ep != nil {
		namespace, name, uid = ep.GetK8sNamespace(), ep.GetK8sPodName(), ep.K8sUID
		endpointID = ep.GetID16()
	}
	// Every exit, including cancellation before an attempt or during backoff,
	// records one terminal outcome. An admission ACK is not Protected status.
	defer func() {
		if resultErr != nil && ep != nil && g.membership != nil && g.membership.InvalidateCaptureGeneration(token.ref, token.generation) {
			g.publishMembership(ep, token.ref, "", "")
		}
		attrs := []any{logStage, "cni-startup-admission", logfields.Attempt, attempt,
			logfields.ElapsedDuration, time.Since(started), logDeadline, deadline,
			logfields.EndpointID, endpointID, logfields.K8sUID, uid,
			logfields.Pod, name, logfields.K8sNamespace, namespace,
			logNamespaceUID, namespaceUID, logEnrollmentRequired, required}
		if resultErr != nil {
			g.logger.Error("Endpoint startup admission failed", append(attrs, logfields.Error, resultErr)...)
		} else {
			g.logger.Info("Endpoint startup admission completed", attrs...)
		}
	}()
	if ep == nil {
		return permanent("endpoint startup admission requires an endpoint")
	}
	// This gate belongs to API/CNI creation. Health, host and ingress
	// endpoints use the trusted internal creator and EndpointManager directly;
	// blank metadata on this path is not authenticated internal provenance.
	if namespace == "" || name == "" || uid == "" {
		return permanent("Kubernetes CNI endpoint has incomplete immutable identity")
	}
	backoff := g.initialBackoff
	var lastErr error
	for attempt = 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, lastErr)
		}
		if !ep.IsAlive() {
			return permanent("managed endpoint disconnected during CNI admission")
		}
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, g.attemptTimeout)
		err := g.once(attemptCtx, ep, &namespaceUID, &required, &token)
		if err == nil {
			err = attemptCtx.Err()
		}
		if err == nil {
			err = ctx.Err()
		}
		lastErr = err
		cancelAttempt() // ZDS joins its cancellation callback before publishing success.
		if err == nil && !ep.IsAlive() {
			err = permanent("managed endpoint disconnected during CNI admission")
		}
		if err == nil {
			return nil
		}
		var terminal *permanentError
		if errors.As(err, &terminal) || apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) || ctx.Err() != nil {
			return errors.Join(ctx.Err(), err)
		}
		g.logger.Warn("Endpoint startup admission retry",
			logStage, "cni-startup-admission",
			logfields.Attempt, attempt,
			logfields.ElapsedDuration, time.Since(started),
			logfields.Backoff, backoff,
			logDeadline, deadline,
			logfields.EndpointID, endpointID,
			logfields.K8sUID, uid,
			logfields.Pod, name,
			logfields.K8sNamespace, namespace,
			logfields.Error, err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ctx.Err(), err)
		case <-timer.C:
		}
		backoff = min(2*time.Second, 2*backoff)
	}
}

func (g *gate) once(ctx context.Context, ep *endpoint.Endpoint, pinnedUID *types.UID, required *bool, token *membershipAttempt) (retErr error) {
	namespace, name := ep.GetK8sNamespace(), ep.GetK8sPodName()
	if g.recorder == nil {
		return permanent("durable Required intent recorder is unavailable")
	}
	durableUID, durableRequired, err := g.recorder.Lookup(ctx, ep.K8sUID)
	if err != nil {
		return fmt.Errorf("reading durable Required intent: %w", err)
	}
	if durableRequired {
		ep.ObserveZtunnelRequired()
		if *pinnedUID != "" && string(*pinnedUID) != durableUID {
			return permanent("durable namespace identity changed during admission")
		}
		*pinnedUID = types.UID(durableUID)
		*required = true
		if ref, state, ok := g.membership.CurrentForPodUID(ep.K8sUID); ok && state.EndpointID == ep.GetID16() {
			g.membership.InvalidateCapture(ref)
			g.publishMembership(ep, ref, "", "")
		} else {
			// A Required journal entry from before this process epoch is intent,
			// never proof of capture. Publish an incomplete Required marker so a
			// consumer rejects any stale serialized Captured record.
			ep.SetZtunnelMembership(endpoint.ZtunnelMembership{
				Version: 1, State: endpoint.ZtunnelMembershipRequired,
				NamespaceUID: durableUID,
			})
		}
	}
	before, err := g.core.Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading live namespace intent: %w", err)
	}
	if before.UID == "" || before.ResourceVersion == "" || before.DeletionTimestamp != nil {
		return permanent("namespace identity is empty or terminating")
	}
	if *pinnedUID == "" {
		*pinnedUID = before.UID
	}
	if before.UID != *pinnedUID {
		return permanent("namespace was recreated during CNI admission")
	}
	enrolled := before.Labels["io.cilium/mtls-enabled"] == "true"
	if *required && !enrolled {
		return permanent("enrollment intent changed during required CNI admission")
	}
	*required = *required || enrolled

	pod, err := g.core.Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading live Pod identity: %w", err)
	}
	if string(pod.UID) != ep.K8sUID || pod.DeletionTimestamp != nil || pod.Name != name || pod.Namespace != namespace {
		return permanent("live Pod does not match immutable CNI identity")
	}
	if pod.Spec.ServiceAccountName == "" || pod.Spec.NodeName == "" || pod.Spec.NodeName != g.nodeName() {
		return permanent("live Pod service account or node binding is invalid")
	}
	// Require the managed Pod metadata to name this immutable CNI identity
	// before admitting startup; wire metadata below comes from the live API.
	if enrolled {
		managedPod := ep.GetPod()
		if managedPod == nil || string(managedPod.UID) != ep.K8sUID ||
			managedPod.Name != name || managedPod.Namespace != namespace {
			return fmt.Errorf("managed endpoint metadata is not synchronized to immutable CNI identity")
		}
	}
	var finalSandboxCheck func() error
	if enrolled && (pod.Spec.HostNetwork || namespace == g.agentNamespace) {
		return permanent("enrolled host-network or agent-namespace Pods are outside initial admission qualification")
	}
	if enrolled {
		path := ep.GetContainerNetnsPath()
		if path == "" {
			return permanent("enrolled CNI endpoint has no network namespace")
		}
		if err := g.validateNetns(path); err != nil {
			return fmt.Errorf("validating CNI network namespace: %w", err)
		}
		recheck, release, err := g.recorder.Record(ctx, ep, string(*pinnedUID), pod)
		if err != nil {
			if isRequiredConflict(err) {
				return permanent("durable Required sandbox conflict: %w", err)
			}
			return fmt.Errorf("persisting durable Required intent: %w", err)
		}
		if release == nil || recheck == nil {
			if release != nil {
				release()
			}
			return permanent("durable Required recorder returned no sandbox lease")
		}
		defer release()
		finalSandboxCheck = recheck
		ep.ObserveZtunnelRequired()
		ref, err := g.membership.Require(string(*pinnedUID), ep.K8sUID, ep.GetID16(), path)
		if err != nil {
			return permanent("creating exact required membership: %w", err)
		}
		generation, ok := g.membership.BeginZDS(ref)
		if !ok {
			return permanent("starting a fresh ZDS membership generation failed")
		}
		*token = membershipAttempt{ref, generation}
		defer func() {
			if retErr != nil {
				g.membership.InvalidateCaptureGeneration(ref, generation)
				g.publishMembership(ep, ref, pod.Spec.NodeName, pod.Spec.ServiceAccountName)
			}
		}()
		if !g.publishMembership(ep, ref, pod.Spec.NodeName, pod.Spec.ServiceAccountName) {
			return permanent("Required membership could not be published before enrollment")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := recheck(); err != nil {
			return permanent("sandbox changed before enrollment: %w", err)
		}
		// This view is private to this attempt: background metadata updates
		// cannot alter the Pod UID/SA that the legacy converter sends.
		view := &endpoint.Endpoint{ID: ep.GetID16(), K8sUID: ep.K8sUID,
			K8sNamespace: namespace, K8sPodName: name}
		view.SetContainerNetnsPath(path)
		view.SetPod(pod.DeepCopy())
		if err := g.enroll(zds.WithCaptureReference(ctx, ref, generation), ep, view); err != nil {
			return fmt.Errorf("capture/proxy enrollment: %w", err)
		}
		if err := recheck(); err != nil {
			return permanent("sandbox changed after enrollment: %w", err)
		}
		if err := g.validateNetns(path); err != nil {
			return permanent("CNI network namespace is invalid after enrollment: %w", err)
		}
	}
	currentPod, err := g.core.Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("rechecking live Pod: %w", err)
	}
	if string(currentPod.UID) != ep.K8sUID || currentPod.DeletionTimestamp != nil ||
		currentPod.Spec.ServiceAccountName != pod.Spec.ServiceAccountName || currentPod.Spec.NodeName != pod.Spec.NodeName {
		return permanent("Pod identity changed during CNI admission")
	}
	after, err := g.core.Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("rechecking live namespace intent: %w", err)
	}
	if after.UID != *pinnedUID || after.DeletionTimestamp != nil {
		return permanent("namespace changed generation during CNI admission")
	}
	if after.ResourceVersion != before.ResourceVersion || (after.Labels["io.cilium/mtls-enabled"] == "true") != enrolled {
		return fmt.Errorf("namespace intent changed during CNI admission")
	}
	if finalSandboxCheck != nil {
		if err := finalSandboxCheck(); err != nil {
			return permanent("sandbox changed during final admission checks: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if *required {
		if !g.membership.MarkCaptured(token.ref, token.generation) || !g.membership.AcknowledgeZDS(token.ref, token.generation) {
			return permanent("final capture/ZDS evidence no longer matches the checked attempt")
		}
		ep.SetK8sNamespaceUID(string(*pinnedUID))
		ref, state, ok := g.membership.CurrentForPodUID(ep.K8sUID)
		if !ok || state.EndpointID != ep.GetID16() || ref.Key.NamespaceUID != string(*pinnedUID) || ref != token.ref || state.ZDSGeneration != token.generation || !state.ReadyForAddress() {
			return permanent("required membership disappeared before publication")
		}
		if !g.publishMembership(ep, ref, pod.Spec.NodeName, pod.Spec.ServiceAccountName) {
			return permanent("source publication was superseded before admission commit")
		}
	}
	return nil
}

func (g *gate) publishMembership(ep *endpoint.Endpoint, ref membership.Reference, nodeName, serviceAccount string) bool {
	p, ok := g.membership.Publication(ref)
	if !ok {
		return false
	}
	return ep.SetZtunnelMembership(endpoint.ZtunnelMembership{
		Revision:       p.Revision,
		Version:        p.Version,
		Epoch:          p.Epoch,
		Generation:     p.Generation,
		State:          p.State,
		NamespaceUID:   ref.Key.NamespaceUID,
		NodeName:       nodeName,
		ServiceAccount: serviceAccount,
	})
}

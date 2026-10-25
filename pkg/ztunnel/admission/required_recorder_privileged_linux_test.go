// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimmeta "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"
)

type recorderNetnsFixture struct {
	path                  string
	cookie, device, inode uint64
}

func createRecorderNetns(t *testing.T) recorderNetnsFixture {
	t.Helper()
	ns, err := netns.New()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "sandbox")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	require.NoError(t, unix.Mount(fmt.Sprintf("/proc/self/fd/%d", ns.FD()), path, "none", unix.MS_BIND, ""))
	t.Cleanup(func() { _ = unix.Unmount(path, unix.MNT_DETACH) })
	var cookie uint64
	require.NoError(t, ns.Do(func() error { var err error; cookie, err = netns.GetNetNSCookie(); return err }))
	require.NotZero(t, cookie)
	var stat unix.Stat_t
	require.NoError(t, unix.Fstat(ns.FD(), &stat))
	require.NoError(t, ns.Close())
	return recorderNetnsFixture{path: path, cookie: cookie, device: uint64(stat.Dev), inode: stat.Ino}
}
func remountRecorderNetns(t *testing.T, from recorderNetnsFixture, target string) {
	t.Helper()
	require.NoError(t, unix.Unmount(target, unix.MNT_DETACH))
	require.NoError(t, unix.Mount(from.path, target, "none", unix.MS_BIND, ""))
}
func recorderOpenFDCount(t *testing.T, device, inode uint64) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	count := 0
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) == nil && uint64(stat.Dev) == device && stat.Ino == inode {
			count++
		}
	}
	return count
}
func recorderEndpoint(t *testing.T, pod *slimv1.Pod, sandbox recorderNetnsFixture, container string) *endpoint.Endpoint {
	t.Helper()
	logger := hivetest.Logger(t)
	repo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
	ep, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{Logger: logger, PolicyRepo: repo}, nil, nil, &models.EndpointChangeRequest{ID: 71, K8sUID: string(pod.UID), K8sNamespace: pod.Namespace, K8sPodName: pod.Name, ContainerID: container, ContainerNetnsPath: sandbox.path, NetnsCookie: strconv.FormatUint(sandbox.cookie, 10)}, nil)
	require.NoError(t, err)
	ep.Options.SetBool(option.SourceIPVerification, true)
	ep.UpdateLogger(nil)
	ep.SetPod(pod.DeepCopy())
	require.True(t, ep.SetState(endpoint.StateWaitingForIdentity, "recorder test"))
	return ep
}
func realRecorderGateFixture(t *testing.T) (*gate, *durableRecorder, *endpoint.Endpoint, recorderNetnsFixture, string) {
	t.Helper()
	g, _, view := cniGateFixture(t)
	sandbox := createRecorderNetns(t)
	ep := recorderEndpoint(t, view.GetPod(), sandbox, "cri-actual-sandbox")
	// The cached fixture deliberately has stale SA metadata. Use the SAME live
	// authoritative pod properties used by cniGateFixture's fake Kubernetes API.
	pod := ep.GetPod().DeepCopy()
	pod.Spec.ServiceAccountName = "server"
	ep.SetPod(pod)
	base := t.TempDir()
	r := newRequiredRecorder(base, 17, func() string { return "node-a" }).(*durableRecorder)
	t.Cleanup(func() { _ = r.Close() })
	g.recorder = r
	g.validateNetns = validateNetworkNamespace
	return g, r, ep, sandbox, base
}

func TestPrivilegedRecorderPersistsActualSandboxBeforeEnrollment(t *testing.T) {
	testutils.PrivilegedTest(t)
	g, r, ep, sandbox, _ := realRecorderGateFixture(t)
	var enrollments atomic.Int32
	g.enroll = func(ctx context.Context, owner, view *endpoint.Endpoint) error {
		enrollments.Add(1)
		require.Same(t, ep, owner)
		records, err := r.store.List()
		require.NoError(t, err)
		require.Len(t, records, 1)
		got := records[0]
		require.Equal(t, "namespace-generation", got.NamespaceUID)
		require.Equal(t, ep.K8sUID, got.PodUID)
		require.Equal(t, ep.GetContainerID(), got.ContainerID)
		require.Equal(t, sandbox.cookie, got.NetnsCookie)
		require.Equal(t, sandbox.device, got.NetnsDevice)
		require.Equal(t, sandbox.inode, got.NetnsInode)
		require.Equal(t, "server", got.ServiceAccount)
		require.GreaterOrEqual(t, recorderOpenFDCount(t, sandbox.device, sandbox.inode), 1, "actual recorder lease must hold namespace FD through enrollment")
		return nil
	}
	require.NoError(t, g.WaitForEndpoint(t.Context(), ep))
	require.EqualValues(t, 1, enrollments.Load())
	require.Zero(t, recorderOpenFDCount(t, sandbox.device, sandbox.inode), "lease leaked after admission")
}

func TestPrivilegedRecorderRejectsPathReplacementWhileHoldingOldNamespace(t *testing.T) {
	testutils.PrivilegedTest(t)
	g, r, ep, old, _ := realRecorderGateFixture(t)
	replacement := createRecorderNetns(t)
	require.NotEqual(t, old.cookie, replacement.cookie)
	g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error {
		remountRecorderNetns(t, replacement, old.path)
		require.GreaterOrEqual(t, recorderOpenFDCount(t, old.device, old.inode), 1, "lease must keep OLD namespace alive after runtime unpins it")
		return nil
	}
	require.ErrorContains(t, g.WaitForEndpoint(t.Context(), ep), "sandbox changed")
	records, err := r.store.List()
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, old.cookie, records[0].NetnsCookie, "failed admission must retain original Required intent")
	require.Zero(t, recorderOpenFDCount(t, old.device, old.inode), "old lease FD leaked")
}

func TestPrivilegedRecorderWrongCookieFailsBeforePersistAndCorrectedRetrySucceeds(t *testing.T) {
	testutils.PrivilegedTest(t)
	g, r, ep, sandbox, _ := realRecorderGateFixture(t)
	_, _, err := r.Lookup(t.Context(), ep.K8sUID)
	require.NoError(t, err)
	ep.NetNsCookie = sandbox.cookie + 1
	_, _, err = r.Record(t.Context(), ep, "namespace-generation", ep.GetPod())
	require.Error(t, err)
	records, err := r.store.List()
	require.NoError(t, err)
	require.Empty(t, records)
	ep.NetNsCookie = sandbox.cookie
	g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error { return nil }
	require.NoError(t, g.WaitForEndpoint(t.Context(), ep))
}

func TestPrivilegedRecorderCancellationAtActualDurabilityBoundaryRetainsIntent(t *testing.T) {
	testutils.PrivilegedTest(t)
	g, r, ep, _, base := realRecorderGateFixture(t)
	_, _, err := r.Lookup(t.Context(), ep.K8sUID)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	syncDir := r.store.ops.syncDir
	r.store.ops.syncDir = func() error {
		err := syncDir()
		if err == nil {
			cancel()
		}
		return err
	}
	var enrolled atomic.Int32
	g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error { enrolled.Add(1); return nil }
	require.ErrorIs(t, g.WaitForEndpoint(ctx, ep), context.Canceled)
	require.Zero(t, enrolled.Load())
	require.NoError(t, r.Close())
	reopened, err := OpenIntentStore(base)
	require.NoError(t, err)
	defer reopened.Close()
	records, err := reopened.List()
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, ep.K8sUID, records[0].PodUID)
}

func TestPrivilegedRecorderActualSyncFailureBlocksAndRecovers(t *testing.T) {
	testutils.PrivilegedTest(t)
	g, r, ep, _, _ := realRecorderGateFixture(t)
	_, _, err := r.Lookup(t.Context(), ep.K8sUID)
	require.NoError(t, err)
	expected := errors.New("injected actual recorder file fsync failure")
	syncFile := r.store.ops.syncFile
	r.store.ops.syncFile = func(*os.File) error { return expected }
	g.budget = 25 * time.Millisecond
	var enrolled atomic.Int32
	g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error { enrolled.Add(1); return nil }
	require.ErrorIs(t, g.WaitForEndpoint(t.Context(), ep), expected)
	require.Zero(t, enrolled.Load())
	records, err := r.store.List()
	require.NoError(t, err)
	require.Empty(t, records)
	r.store.ops.syncFile = syncFile
	require.NoError(t, g.WaitForEndpoint(t.Context(), ep))
	require.EqualValues(t, 1, enrolled.Load())
}

func TestPrivilegedRecorderSamePodReplacementCannotReuseOldIntent(t *testing.T) {
	testutils.PrivilegedTest(t)
	_, r, ep, _, _ := realRecorderGateFixture(t)
	check, release, err := r.Record(t.Context(), ep, "namespace-generation", ep.GetPod())
	require.NoError(t, err)
	require.NoError(t, check())
	release()
	replacement := createRecorderNetns(t)
	next := recorderEndpoint(t, ep.GetPod(), replacement, "cri-replacement-sandbox")
	_, _, err = r.Record(t.Context(), next, "namespace-generation", next.GetPod())
	require.ErrorIs(t, err, errRequiredConflict)
	records, err := r.store.List()
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, ep.GetContainerID(), records[0].ContainerID)
}

func TestPrivilegedRecorderDirectCallsValidateAuthoritativeMetadata(t *testing.T) {
	testutils.PrivilegedTest(t)
	for _, which := range []string{"nil-endpoint", "nil-pod", "wrong-pod-uid", "wrong-pod-name", "wrong-namespace", "empty-namespace-uid", "foreign-node", "empty-service-account", "terminating-pod", "host-network"} {
		t.Run(which, func(t *testing.T) {
			_, r, ep, _, _ := realRecorderGateFixture(t)
			pod := ep.GetPod().DeepCopy()
			namespaceUID := "namespace-generation"
			switch which {
			case "nil-endpoint":
				ep = nil
			case "nil-pod":
				pod = nil
			case "wrong-pod-uid":
				pod.UID = "foreign-pod"
			case "wrong-pod-name":
				pod.Name = "other"
			case "wrong-namespace":
				pod.Namespace = "other"
			case "empty-namespace-uid":
				namespaceUID = ""
			case "foreign-node":
				pod.Spec.NodeName = "node-b"
			case "empty-service-account":
				pod.Spec.ServiceAccountName = ""
			case "terminating-pod":
				stamp := slimmeta.NewTime(time.Now())
				pod.DeletionTimestamp = &stamp
			case "host-network":
				pod.Spec.HostNetwork = true
			}
			_, _, err := r.Record(t.Context(), ep, namespaceUID, pod)
			require.Error(t, err)
			// No dereference panic and no invalid identity may commit.
			if r.store != nil {
				records, err := r.store.List()
				require.NoError(t, err)
				require.Empty(t, records)
			}
		})
	}
}

func TestRecorderLookupRejectsForeignOrCorruptJournal(t *testing.T) {
	for _, which := range []string{"foreign-cluster", "foreign-node", "corrupt"} {
		t.Run(which, func(t *testing.T) {
			base := t.TempDir()
			r := newRequiredRecorder(base, 17, func() string { return "node-a" }).(*durableRecorder)
			defer r.Close()
			_, _, err := r.Lookup(t.Context(), "unused")
			require.NoError(t, err)
			identity := testRequiredIdentity()
			if which == "foreign-cluster" {
				identity.ClusterID++
			}
			if which == "foreign-node" {
				identity.NodeName = "node-b"
			}
			persistTestIntent(t, r.store, identity)
			if which == "corrupt" {
				require.NoError(t, os.WriteFile(singleIntentFile(t, base), []byte("{incomplete"), 0600))
			}
			_, required, err := r.Lookup(t.Context(), identity.PodUID)
			require.Error(t, err)
			require.False(t, required, "failed whole snapshot cannot supply an authoritative partial lookup")
		})
	}
}

func TestRecorderConstructorAndClosedStatePerformNoFilesystemIO(t *testing.T) {
	base := filepath.Join(t.TempDir(), "not-created")
	r := newRequiredRecorder(base, 17, func() string { return "node-a" }).(*durableRecorder)
	_, err := os.Stat(base)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.NoError(t, r.Close())
	require.NoError(t, r.Close())
	_, _, err = r.Lookup(t.Context(), "pod")
	require.ErrorIs(t, err, errRequiredClosed)
	_, err = os.Stat(base)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRecorderCanceledLookupDoesNotCreateJournal(t *testing.T) {
	base := t.TempDir()
	r := newRequiredRecorder(base, 17, func() string { return "node-a" }).(*durableRecorder)
	defer r.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err := r.Lookup(ctx, "pod")
	require.ErrorIs(t, err, context.Canceled)
	_, err = os.Stat(filepath.Join(base, intentDirectory))
	require.ErrorIs(t, err, os.ErrNotExist)
}

// Capture the second pre-lock Err result before signaling the test, so cancel
// cannot change that already-observed nil. The next check must be after locking.
type recorderCheckpointContext struct {
	context.Context
	checks atomic.Int32
	ready  chan struct{}
}

func (c *recorderCheckpointContext) Err() error {
	err := c.Context.Err()
	if c.checks.Add(1) == 2 {
		close(c.ready)
	}
	return err
}
func TestPrivilegedRecorderCancellationWhileQueuedDoesNotCommit(t *testing.T) {
	testutils.PrivilegedTest(t)
	_, r, ep, sandbox, _ := realRecorderGateFixture(t)
	_, _, err := r.Lookup(t.Context(), ep.K8sUID)
	require.NoError(t, err)
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &recorderCheckpointContext{Context: parent, ready: make(chan struct{})}
	done := make(chan error, 1)
	r.mu.Lock()
	go func() {
		_, release, err := r.Record(ctx, ep, "namespace-generation", ep.GetPod())
		if release != nil {
			release()
		}
		done <- err
	}()
	select {
	case <-ctx.ready:
	case <-time.After(time.Second):
		r.mu.Unlock()
		t.Fatal("recorder did not reach pre-lock checkpoint")
	}
	cancel()
	r.mu.Unlock()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("canceled recorder did not finish")
	}
	records, err := r.store.List()
	require.NoError(t, err)
	require.Empty(t, records, "an attempt canceled before the commit lock must not create sticky intent")
	require.Zero(t, recorderOpenFDCount(t, sandbox.device, sandbox.inode))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	goiptables "github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	slimcore "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimmeta "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"
	inpodiptables "github.com/cilium/cilium/pkg/ztunnel/iptables"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

func strictCleanupServer(t *testing.T) *Server {
	t.Helper()
	return &Server{logger: hivetest.Logger(t), metrics: NewMetrics(),
		strictDeletedEndpointCleanup: true, updates: make(chan zdsUpdate, 10),
		endpointCache: make(map[uint16]*endpoint.Endpoint)}
}

func liveManagedEndpoint(t *testing.T, id uint16, uid, path string) *endpoint.Endpoint {
	t.Helper()
	// Use the real constructor: literal Endpoints lack status/logger required
	// by SetState. No Start/Delete/datapath dependencies are invoked here.
	logger := hivetest.Logger(t)
	repo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
	ep, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{Logger: logger, PolicyRepo: repo}, nil, nil,
		&models.EndpointChangeRequest{ID: int64(id), K8sUID: uid,
			K8sNamespace: "apps", K8sPodName: "server", ContainerNetnsPath: path}, nil)
	require.NoError(t, err)
	ep.UpdateLogger(nil)
	require.True(t, ep.SetState(endpoint.StateWaitingForIdentity, "test fixture"))
	return ep
}

func deletedManagedEndpoint(t *testing.T, id uint16, uid, path string) *endpoint.Endpoint {
	t.Helper()
	ep := liveManagedEndpoint(t, id, uid, path)
	require.True(t, ep.SetState(endpoint.StateDisconnecting, "test deletion"))
	require.True(t, ep.SetState(endpoint.StateDisconnected, "test deletion complete"))
	return ep
}

func acknowledgedView(id uint16, uid, path string) *endpoint.Endpoint {
	ep := &endpoint.Endpoint{ID: id, K8sUID: uid, K8sNamespace: "apps", K8sPodName: "server"}
	ep.SetContainerNetnsPath(path)
	ep.SetPod(&slimcore.Pod{ObjectMeta: slimmeta.ObjectMeta{UID: types.UID(uid), Name: "server", Namespace: "apps"},
		Spec: slimcore.PodSpec{ServiceAccountName: "server"}})
	return ep
}

func receiveCleanupUpdate(t *testing.T, s *Server) zdsUpdate {
	t.Helper()
	select {
	case update := <-s.updates:
		return update
	case <-time.After(time.Second):
		t.Fatal("cleanup failed to queue its DEL")
		return zdsUpdate{}
	}
}

func exchangeCleanupUpdate(t *testing.T, s *Server, update zdsUpdate, reply []byte) (*pb.WorkloadRequest, error) {
	t.Helper()
	connection, peer := zdsSocketPair(t)
	require.NoError(t, peer.SetDeadline(time.Now().Add(time.Second)))
	done := make(chan error, 1)
	go func() { done <- s.processUpdate(context.Background(), connection, update) }()
	request := &pb.WorkloadRequest{}
	require.NoError(t, (&ztunnelConn{conn: peer}).readMsg(request))
	_, err := peer.Write(reply)
	require.NoError(t, err)
	return request, <-done
}

func TestStrictDeletedCleanupImmutableUIDAndNoNetnsDependency(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reply     []byte
		wantError string
	}{
		{"ack", []byte{0x0a, 0x00}, ""},
		{"nack", []byte{0x0a, 0x08, 0x0a, 0x06, 'd', 'e', 'n', 'i', 'e', 'd'}, "ack error: denied"},
		{"missing-ack", []byte{0x12, 0x00}, "did not contain an acknowledgment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := strictCleanupServer(t)
			ep := deletedManagedEndpoint(t, 9, "immutable-uid", "/definitely-missing-deleted-netns")
			// Mutable managed metadata is deliberately incorrect. Cleanup must
			// not derive DEL UID from it, nor require any Pod metadata at all.
			ep.SetPod(&slimcore.Pod{ObjectMeta: slimmeta.ObjectMeta{UID: "wrong-current-pod"}})
			s.endpointCache[9] = acknowledgedView(9, "immutable-uid", ep.GetContainerNetnsPath())
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- s.CleanupDeletedEndpointContext(ctx, ep) }()
			update := receiveCleanupUpdate(t, s)
			require.Empty(t, update.netnsPath, "DEL must never open a removed sandbox")
			s.endpointCacheMutex.Lock()
			require.Empty(t, s.endpointCache, "local retirement precedes ACK and survives NACK")
			s.endpointCacheMutex.Unlock()
			request, processErr := exchangeCleanupUpdate(t, s, update, tc.reply)
			require.Equal(t, "immutable-uid", request.GetDel().Uid)
			if tc.wantError == "" {
				require.NoError(t, processErr)
				require.NoError(t, <-result)
			} else {
				require.ErrorContains(t, processErr, tc.wantError)
				require.ErrorContains(t, <-result, tc.wantError)
			}
			s.endpointCacheMutex.Lock()
			require.Empty(t, s.endpointCache)
			s.endpointCacheMutex.Unlock()
		})
	}
}

func TestStrictDeletedCleanupRetiresBeforeBlockedOperationDeadline(t *testing.T) {
	s := strictCleanupServer(t)
	ep := deletedManagedEndpoint(t, 10, "old-uid", "/removed-old-netns")
	old := acknowledgedView(10, "old-uid", ep.GetContainerNetnsPath())
	s.endpointCache[10] = old
	release, err := s.acquireEndpointOperation(t.Context())
	require.NoError(t, err)
	defer release()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	require.ErrorIs(t, s.CleanupDeletedEndpointContext(ctx, ep), context.DeadlineExceeded)
	require.Less(t, time.Since(started), time.Second)
	require.Empty(t, s.endpointCache)
	require.Empty(t, s.updates)
	// Managed owner is disconnected; its late ACK cannot resurrect it.
	s.commitStrictEnrollment(t.Context(), ep, old)
	require.Empty(t, s.endpointCache)
	// Private views never disconnect; their canceled caller is the guard.
	canceled, stop := context.WithCancel(t.Context())
	stop()
	s.commitStrictEnrollment(canceled, old, old)
	require.Empty(t, s.endpointCache)
}

func TestStrictDeletedCleanupRechecksNewSameUIDOwnerAfterSemaphoreWait(t *testing.T) {
	s := strictCleanupServer(t)
	old := deletedManagedEndpoint(t, 11, "same-pod-uid", "/old-sandbox")
	oldView := acknowledgedView(11, "same-pod-uid", "/old-sandbox")
	newView := acknowledgedView(12, "same-pod-uid", "/new-sandbox")
	s.endpointCache[11] = oldView
	release, err := s.acquireEndpointOperation(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- s.CleanupDeletedEndpointContext(ctx, old) }()
	require.Eventually(t, func() bool {
		s.endpointCacheMutex.Lock()
		defer s.endpointCacheMutex.Unlock()
		return s.endpointCache[11] == nil
	}, time.Second, time.Millisecond)
	// Represents the already-in-progress new ADD receiving its real ACK.
	// The privileged test below exercises this via actual Enroll + socket.
	s.commitStrictEnrollment(t.Context(), newView, newView)
	release()
	require.NoError(t, <-result)
	require.Empty(t, s.updates, "stale DEL must produce zero wire requests")
	require.Same(t, newView, s.endpointCache[12])
	require.Len(t, s.endpointCache, 1)
}

func TestStrictDeletedCleanupDoesNotEraseReusedEndpointID(t *testing.T) {
	s := strictCleanupServer(t)
	old := deletedManagedEndpoint(t, 13, "old-pod", "/old-sandbox")
	newView := acknowledgedView(13, "different-new-pod", "/new-sandbox")
	s.endpointCache[13] = newView
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- s.CleanupDeletedEndpointContext(ctx, old) }()
	update := receiveCleanupUpdate(t, s)
	request, err := exchangeCleanupUpdate(t, s, update, []byte{0x0a, 0x00})
	require.NoError(t, err)
	require.NoError(t, <-result)
	require.Equal(t, "old-pod", request.GetDel().Uid)
	require.Same(t, newView, s.endpointCache[13], "DEL ACK must not erase new ID owner")
}

func TestStrictDeletedCleanupRejectsLiveViewAndMissingUID(t *testing.T) {
	s := strictCleanupServer(t)
	live := acknowledgedView(14, "live-uid", "/live-sandbox")
	s.endpointCache[14] = live
	require.ErrorContains(t, s.CleanupDeletedEndpointContext(t.Context(), live), "disconnected managed endpoint")
	require.Same(t, live, s.endpointCache[14])
	ep := deletedManagedEndpoint(t, 15, "", "/old-sandbox")
	require.ErrorContains(t, s.CleanupDeletedEndpointContext(t.Context(), ep), "immutable CNI UID")
	require.Empty(t, s.updates)
}

func TestStrictInitialSeedCannotResurrectRetiredManagedEndpoint(t *testing.T) {
	s := strictCleanupServer(t)
	s.initialSnapshotSeeded = make(chan struct{})
	old := deletedManagedEndpoint(t, 51, "retired-before-seed", "/removed-before-seed")
	s.endpointCache[51] = acknowledgedView(51, old.K8sUID, old.GetContainerNetnsPath())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, s.CleanupDeletedEndpointContext(ctx, old), context.Canceled)
	require.Empty(t, s.endpointCache)
	healthy := acknowledgedView(52, "healthy-seed", "/healthy-seed")
	s.SeedInitialSnapshot(old, healthy)
	require.Len(t, s.endpointCache, 1)
	require.Same(t, healthy, s.endpointCache[52])
	select {
	case <-s.initialSnapshotSeeded:
	default:
		t.Fatal("Healthy initial seed must complete")
	}
}

func TestStrictInitialSeedCannotOverwriteAcknowledgedNewSandbox(t *testing.T) {
	s := strictCleanupServer(t)
	s.initialSnapshotSeeded = make(chan struct{})
	newOwner := acknowledgedView(62, "same-pod", "/new-sandbox")
	s.endpointCache[62] = newOwner
	oldList := acknowledgedView(61, "same-pod", "/old-sandbox")
	reusedID := acknowledgedView(62, "different-old-pod", "/old-reused-id")
	s.SeedInitialSnapshot(oldList, reusedID)
	require.Len(t, s.endpointCache, 1)
	require.Same(t, newOwner, s.endpointCache[62])
}

func TestStrictDeletedCleanupCancellationRetiresStreamAndRecovers(t *testing.T) {
	s := strictCleanupServer(t)
	ep := deletedManagedEndpoint(t, 16, "canceled-delete", "/gone-sandbox")
	s.endpointCache[16] = acknowledgedView(16, ep.K8sUID, ep.GetContainerNetnsPath())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- s.CleanupDeletedEndpointContext(ctx, ep) }()
	update := receiveCleanupUpdate(t, s)
	connection, peer := zdsSocketPair(t)
	require.NoError(t, peer.SetDeadline(time.Now().Add(time.Second)))
	processed := make(chan error, 1)
	go func() { processed <- s.processUpdate(t.Context(), connection, update) }()
	request := &pb.WorkloadRequest{}
	require.NoError(t, (&ztunnelConn{conn: peer}).readMsg(request))
	require.Equal(t, ep.K8sUID, request.GetDel().Uid)
	cancel()
	require.ErrorIs(t, <-result, context.Canceled)
	require.ErrorIs(t, <-processed, context.Canceled)
	require.Empty(t, s.endpointCache)
	_, err := peer.Write([]byte{0x0a, 0x00})
	require.Error(t, err, "late DEL ACK must not be confused with the next ADD")
	// A fresh stream remains usable after cancellation. Real ADD recovery and
	// retained capture are exercised below with a real network namespace.
	fresh, other := zdsSocketPair(t)
	ctx2, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	update2 := zdsUpdate{ctx: ctx2, errCh: make(chan error, 1), request: &pb.WorkloadRequest{
		Payload: &pb.WorkloadRequest_SnapshotSent{SnapshotSent: &pb.SnapshotSent{}}}}
	done := make(chan error, 1)
	go func() { done <- s.processUpdate(t.Context(), fresh, update2) }()
	require.NoError(t, other.SetDeadline(time.Now().Add(time.Second)))
	require.NoError(t, (&ztunnelConn{conn: other}).readMsg(&pb.WorkloadRequest{}))
	_, err = other.Write([]byte{0x0a, 0x00})
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.NoError(t, <-update2.errCh)
}

func strictCapturePresent(t *testing.T, path string) bool {
	t.Helper()
	ns, err := netns.OpenPinned(path)
	require.NoError(t, err)
	defer ns.Close()
	present := false
	require.NoError(t, ns.Do(func() error {
		var ipt *goiptables.IPTables
		var err error
		if option.Config.EnableIPv4 {
			ipt, err = goiptables.New()
		} else {
			ipt, err = goiptables.NewWithProtocol(goiptables.ProtocolIPv6)
		}
		if err != nil {
			return err
		}
		exists, err := ipt.ChainExists("nat", inpodiptables.InpodPreroutingChain)
		if err != nil || !exists {
			return err
		}
		present, err = ipt.Exists("nat", "PREROUTING", "-j", inpodiptables.InpodPreroutingChain)
		return err
	}))
	return present
}

func TestPrivilegedStrictDeletedCleanupRetainsCaptureAndFreshSandboxRecovers(t *testing.T) {
	testutils.PrivilegedTest(t)
	s := strictCleanupServer(t)
	old, cleanupOld := createTestEndpoint(t, "cleanup-same-pod", 31)
	defer cleanupOld()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- s.EnrollEndpointContext(ctx, old) }()
	add := receiveCleanupUpdate(t, s)
	request, err := exchangeCleanupUpdate(t, s, add, []byte{0x0a, 0x00})
	require.NoError(t, err)
	require.NotNil(t, request.GetAdd())
	require.NoError(t, <-result)
	require.True(t, strictCapturePresent(t, old.GetContainerNetnsPath()))
	managed := deletedManagedEndpoint(t, old.GetID16(), old.K8sUID, old.GetContainerNetnsPath())
	go func() { result <- s.CleanupDeletedEndpointContext(ctx, managed) }()
	del := receiveCleanupUpdate(t, s)
	_, err = exchangeCleanupUpdate(t, s, del, []byte{0x0a, 0x08, 0x0a, 0x06, 'd', 'e', 'n', 'i', 'e', 'd'})
	require.ErrorContains(t, err, "denied")
	require.ErrorContains(t, <-result, "denied")
	require.True(t, strictCapturePresent(t, old.GetContainerNetnsPath()), "NACK must retain capture")
	require.Empty(t, s.endpointCache)
	// Runtime retries the same Pod using a distinct sandbox path and ID.
	fresh, cleanupFresh := createTestEndpoint(t, old.K8sUID, 32)
	defer cleanupFresh()
	go func() { result <- s.EnrollEndpointContext(ctx, fresh) }()
	add = receiveCleanupUpdate(t, s)
	request, err = exchangeCleanupUpdate(t, s, add, []byte{0x0a, 0x00})
	require.NoError(t, err)
	require.Equal(t, old.K8sUID, request.GetAdd().Uid)
	require.NoError(t, <-result)
	require.True(t, strictCapturePresent(t, fresh.GetContainerNetnsPath()))
	require.Len(t, s.endpointCache, 1)
	require.True(t, sameIncarnation(s.endpointCache[32], endpointIncarnation{32, fresh.K8sUID, fresh.GetContainerNetnsPath()}))
	go func() { result <- s.CleanupDeletedEndpointContext(ctx, managed) }()
	require.NoError(t, <-result, "retry of stale old deletion must skip newer same-UID sandbox")
	require.Empty(t, s.updates)
	require.True(t, strictCapturePresent(t, fresh.GetContainerNetnsPath()))
}

func TestPrivilegedStrictDeletedNetnsCannotBlockHealthySnapshotAndQueuedDEL(t *testing.T) {
	testutils.PrivilegedTest(t)
	s, _, _, address := liveZDSAckServer(t, false)
	s.strictDeletedEndpointCleanup = true
	s.endpointCache = make(map[uint16]*endpoint.Endpoint)
	old, cleanupOld := createTestEndpoint(t, "snapshot-retired", 41)
	healthy, cleanupHealthy := createTestEndpoint(t, "snapshot-healthy", 42)
	defer cleanupHealthy()
	s.SeedInitialSnapshot(old, healthy)
	managed := deletedManagedEndpoint(t, old.GetID16(), old.K8sUID, old.GetContainerNetnsPath())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- s.CleanupDeletedEndpointContext(ctx, managed) }()
	require.Eventually(t, func() bool {
		s.endpointCacheMutex.Lock()
		defer s.endpointCacheMutex.Unlock()
		return s.endpointCache[41] == nil
	}, time.Second, time.Millisecond)
	cleanupOld() // The old pinned netns is now really gone.
	peer := dialZDSAckPeer(t, address)
	require.NoError(t, peer.conn.SetDeadline(time.Now().Add(3*time.Second)))
	sendHello(t, peer.conn)
	request := &pb.WorkloadRequest{}
	require.NoError(t, peer.readMsg(request))
	require.Equal(t, healthy.K8sUID, request.GetAdd().Uid, "healthy ADD must progress despite absent retired namespace")
	_, err := peer.conn.Write([]byte{0x0a, 0x00})
	require.NoError(t, err)
	request = &pb.WorkloadRequest{}
	require.NoError(t, peer.readMsg(request))
	require.NotNil(t, request.GetSnapshotSent())
	_, err = peer.conn.Write([]byte{0x0a, 0x00})
	require.NoError(t, err)
	request = &pb.WorkloadRequest{}
	require.NoError(t, peer.readMsg(request))
	require.Equal(t, old.K8sUID, request.GetDel().Uid)
	_, err = peer.conn.Write([]byte{0x0a, 0x00})
	require.NoError(t, err)
	require.NoError(t, <-result)
}

func TestPrivilegedStrictDeletedCleanupWaitsForNewACKAndSkipsOldDEL(t *testing.T) {
	testutils.PrivilegedTest(t)
	s := strictCleanupServer(t)
	old := deletedManagedEndpoint(t, 51, "one-pod-two-sandboxes", "/removed-old-sandbox")
	s.endpointCache[51] = acknowledgedView(51, old.K8sUID, old.GetContainerNetnsPath())
	fresh, cleanup := createTestEndpoint(t, old.K8sUID, 52)
	defer cleanup()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	enrolled := make(chan error, 1)
	go func() { enrolled <- s.EnrollEndpointContext(ctx, fresh) }()
	add := receiveCleanupUpdate(t, s) // New ADD holds the producer semaphore.
	require.NotNil(t, add.request.GetAdd())
	deleted := make(chan error, 1)
	go func() { deleted <- s.CleanupDeletedEndpointContext(ctx, old) }()
	require.Eventually(t, func() bool {
		s.endpointCacheMutex.Lock()
		defer s.endpointCacheMutex.Unlock()
		return s.endpointCache[51] == nil
	}, time.Second, time.Millisecond)
	select {
	case err := <-deleted:
		t.Fatalf("cleanup must wait for the already active ADD before deciding DEL ownership: %v", err)
	default:
	}
	request, err := exchangeCleanupUpdate(t, s, add, []byte{0x0a, 0x00})
	require.NoError(t, err)
	require.Equal(t, old.K8sUID, request.GetAdd().Uid)
	require.NoError(t, <-enrolled)
	require.NoError(t, <-deleted)
	require.Empty(t, s.updates, "old sandbox cleanup must not enqueue DEL for the fresh same-UID owner")
	require.Len(t, s.endpointCache, 1)
	require.True(t, sameIncarnation(s.endpointCache[52], endpointIncarnation{52, fresh.K8sUID, fresh.GetContainerNetnsPath()}))
	require.True(t, strictCapturePresent(t, fresh.GetContainerNetnsPath()))
}

func managedOwnerForMetadataView(t *testing.T, view *endpoint.Endpoint) *endpoint.Endpoint {
	t.Helper()
	logger := hivetest.Logger(t)
	repo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
	owner, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{Logger: logger, PolicyRepo: repo}, nil, nil,
		&models.EndpointChangeRequest{ID: int64(view.GetID16()), K8sUID: view.K8sUID,
			K8sNamespace: view.GetK8sNamespace(), K8sPodName: view.GetK8sPodName(),
			ContainerNetnsPath: view.GetContainerNetnsPath()}, nil)
	require.NoError(t, err)
	owner.UpdateLogger(nil)
	owner.SetPod(view.GetPod().DeepCopy())
	require.True(t, owner.SetState(endpoint.StateWaitingForIdentity, "owned enrollment fixture"))
	return owner
}

func disconnectManagedOwner(t *testing.T, owner *endpoint.Endpoint) {
	t.Helper()
	require.True(t, owner.SetState(endpoint.StateDisconnecting, "delete during ADD ACK wait"))
	require.True(t, owner.SetState(endpoint.StateDisconnected, "managed delete completed"))
}

func TestPrivilegedStrictOwnedADDCannotReinsertDeletedOwnerWhileCleanupWaits(t *testing.T) {
	testutils.PrivilegedTest(t)
	s := strictCleanupServer(t)
	view, cleanup := createTestEndpoint(t, "owned-delete-race", 71)
	defer cleanup()
	owner := managedOwnerForMetadataView(t, view)
	workload, err := endpointToWorkload(view)
	require.NoError(t, err)
	// Existing acknowledged state makes the first-retirement synchronization
	// observable without adding any production test hook.
	s.endpointCache[view.GetID16()] = freezeAcknowledgedEndpoint(view, workload, view.GetContainerNetnsPath())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	enrolled := make(chan error, 1)
	go func() { enrolled <- s.EnrollEndpointForOwnerContext(ctx, owner, view) }()
	add := receiveCleanupUpdate(t, s) // Producer now holds the semaphore.
	require.NotNil(t, add.request.GetAdd())
	disconnectManagedOwner(t, owner)
	require.NoError(t, ctx.Err(), "managed deletion must be tested with a still-live ADD caller")
	deleted := make(chan error, 1)
	go func() { deleted <- s.CleanupDeletedEndpointContext(ctx, owner) }()
	require.Eventually(t, func() bool {
		s.endpointCacheMutex.Lock()
		defer s.endpointCacheMutex.Unlock()
		return s.endpointCache[view.GetID16()] == nil
	}, time.Second, time.Millisecond)
	select {
	case err := <-deleted:
		t.Fatalf("cleanup must still be waiting for the active ADD producer: %v", err)
	default:
	}
	// Actual seqpacket ACK after first retirement. Metadata view remains
	// alive and ctx remains live; only the explicit managed owner is dead.
	require.True(t, view.IsAlive())
	_, err = exchangeCleanupUpdate(t, s, add, []byte{0x0a, 0x00})
	require.NoError(t, err)
	require.ErrorContains(t, <-enrolled, "disconnected during enrollment")
	del := receiveCleanupUpdate(t, s)
	require.Equal(t, owner.K8sUID, del.request.GetDel().Uid)
	s.endpointCacheMutex.Lock()
	require.Empty(t, s.endpointCache, "dead managed owner must not publish late private-view cache")
	s.endpointCacheMutex.Unlock()
	_, err = exchangeCleanupUpdate(t, s, del, []byte{0x0a, 0x00})
	require.NoError(t, err)
	require.NoError(t, <-deleted)
	require.True(t, strictCapturePresent(t, view.GetContainerNetnsPath()))
}

func TestStrictDeletedCleanupRetiresExactIncarnationAgainAfterSemaphoreWait(t *testing.T) {
	s := strictCleanupServer(t)
	owner := deletedManagedEndpoint(t, 72, "same-incarnation", "/old-sandbox")
	view := acknowledgedView(72, owner.K8sUID, owner.GetContainerNetnsPath())
	s.endpointCache[72] = view
	release, err := s.acquireEndpointOperation(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	deleted := make(chan error, 1)
	go func() { deleted <- s.CleanupDeletedEndpointContext(ctx, owner) }()
	require.Eventually(t, func() bool {
		s.endpointCacheMutex.Lock()
		defer s.endpointCacheMutex.Unlock()
		return s.endpointCache[72] == nil
	}, time.Second, time.Millisecond)
	// Models the exact historical private-view publication after phase 1.
	// The actual owned enrollment path must reject it via the test above;
	// the second retirement is independent defense against that cache race.
	s.commitStrictEnrollment(t.Context(), view, view)
	s.endpointCacheMutex.Lock()
	require.Same(t, view, s.endpointCache[72])
	s.endpointCacheMutex.Unlock()
	release()
	del := receiveCleanupUpdate(t, s)
	s.endpointCacheMutex.Lock()
	require.Empty(t, s.endpointCache, "second retirement must precede wire DEL and not depend on ACK")
	s.endpointCacheMutex.Unlock()
	request, err := exchangeCleanupUpdate(t, s, del, []byte{0x0a, 0x00})
	require.NoError(t, err)
	require.Equal(t, owner.K8sUID, request.GetDel().Uid)
	require.NoError(t, <-deleted)
	require.Empty(t, s.endpointCache)
}

func TestStrictOwnedEnrollmentRejectsMismatchedOwnerBeforeWire(t *testing.T) {
	s := strictCleanupServer(t)
	view := acknowledgedView(73, "view-uid", "/view-sandbox")
	owner := managedOwnerForMetadataView(t, view)
	wrong := acknowledgedView(74, "other-uid", "/other-sandbox")
	require.ErrorContains(t, s.EnrollEndpointForOwnerContext(t.Context(), owner, wrong), "managed endpoint incarnation")
	require.Empty(t, s.updates)
	require.Empty(t, s.endpointCache)
}

func TestPrivilegedStrictManagedMissingUIDRetainsCaptureWithoutADD(t *testing.T) {
	testutils.PrivilegedTest(t)
	s := strictCleanupServer(t)
	ep, cleanup := createTestEndpoint(t, "missing-cni-uid", 75)
	defer cleanup()
	ep.K8sUID = ""
	require.ErrorContains(t, s.EnrollEndpointContext(t.Context(), ep), "immutable CNI UID")
	require.True(t, strictCapturePresent(t, ep.GetContainerNetnsPath()), "managed retry must install capture before rejecting stale identity")
	require.Empty(t, s.updates)
	require.Empty(t, s.endpointCache)
}

func TestStrictLiveUnenrollmentNeverTouchesMissingNetnsOrQueue(t *testing.T) {
	s := strictCleanupServer(t)
	ep := acknowledgedView(81, "live-namespace-uid", "/missing-live-netns")
	s.endpointCache[81] = ep
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.ErrorIs(t, s.DisenrollEndpointContext(ctx, ep), ErrStrictLiveUnenrollment)
	require.Same(t, ep, s.endpointCache[81], "unsupported live transition must preserve acknowledged desired state")
	require.Empty(t, s.updates, "strict live unenrollment cannot issue wire DEL")
}

func TestPrivilegedStrictLiveUnenrollmentRetainsCaptureAndCanRefreshEnrollment(t *testing.T) {
	testutils.PrivilegedTest(t)
	s := strictCleanupServer(t)
	ep, cleanup := createTestEndpoint(t, "strict-unenroll-retained", 82)
	defer cleanup()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- s.EnrollEndpointContext(ctx, ep) }()
	add := receiveCleanupUpdate(t, s)
	_, err := exchangeCleanupUpdate(t, s, add, []byte{0x0a, 0x00})
	require.NoError(t, err)
	require.NoError(t, <-result)
	s.endpointCacheMutex.Lock()
	cached := s.endpointCache[ep.GetID16()]
	s.endpointCacheMutex.Unlock()
	require.ErrorIs(t, s.DisenrollEndpointContext(ctx, ep), ErrStrictLiveUnenrollment)
	require.True(t, strictCapturePresent(t, ep.GetContainerNetnsPath()))
	require.Same(t, cached, s.endpointCache[ep.GetID16()])
	require.Empty(t, s.updates)
	// A true -> false -> true label sequence cannot leave a stale DEL queued
	// behind the fresh ADD. Each refresh still requires a fresh explicit ACK.
	go func() { result <- s.EnrollEndpointContext(ctx, ep) }()
	add = receiveCleanupUpdate(t, s)
	_, err = exchangeCleanupUpdate(t, s, add, []byte{0x0a, 0x00})
	require.NoError(t, err)
	require.NoError(t, <-result)
	require.True(t, strictCapturePresent(t, ep.GetContainerNetnsPath()))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/endpoint"
	slimcore "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimmeta "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

const logCleanupDeadline = "deadline"

// EndpointDeletionCleaner is deliberately separate from namespace
// unenrollment. A deleted CNI endpoint must retain its fail-closed capture.
// The managed endpoint has already passed through Endpoint.Delete.
// Do not call this with the live private admission view.
type EndpointDeletionCleaner interface {
	CleanupDeletedEndpointContext(context.Context, *endpoint.Endpoint) error
}

var _ EndpointDeletionCleaner = (*Server)(nil)

type endpointIncarnation struct {
	id        uint16
	uid       string
	netnsPath string
}

func incarnation(ep *endpoint.Endpoint) (endpointIncarnation, error) {
	if ep == nil || ep.K8sUID == "" || ep.GetContainerNetnsPath() == "" {
		return endpointIncarnation{}, fmt.Errorf("endpoint cleanup requires immutable CNI UID and network namespace path")
	}
	return endpointIncarnation{ep.GetID16(), ep.K8sUID, ep.GetContainerNetnsPath()}, nil
}

func sameIncarnation(ep *endpoint.Endpoint, want endpointIncarnation) bool {
	got, err := incarnation(ep)
	return err == nil && got == want
}

// acquireEndpointOperation serializes producer-side capture/ADD and DEL work.
// Never acquire it from processUpdate, sendInitialSnapshot, or an ACK callback:
// the producer waits for those consumers to make progress.
// Lazy initialization supports the actual existing test Server literals.
func (s *Server) acquireEndpointOperation(ctx context.Context) (func(), error) {
	s.endpointCacheMutex.Lock()
	if s.endpointOperationGate == nil {
		s.endpointOperationGate = make(chan struct{}, 1)
	}
	gate := s.endpointOperationGate
	s.endpointCacheMutex.Unlock()
	select {
	case gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-gate
			return nil, err
		}
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// freezeAcknowledgedEndpoint caches exactly the metadata sent on this ADD.
// It does not copy Endpoint locks, atomics or mutable managed Pod metadata.
// The admission gate remains responsible for authoritative API validation.
func freezeAcknowledgedEndpoint(ep *endpoint.Endpoint, workload *pb.AddWorkload, netnsPath string) *endpoint.Endpoint {
	view := &endpoint.Endpoint{
		ID: ep.GetID16(), K8sUID: workload.Uid,
		K8sNamespace: workload.WorkloadInfo.Namespace,
		K8sPodName:   workload.WorkloadInfo.Name,
	}
	view.SetContainerNetnsPath(netnsPath)
	view.SetPod(&slimcore.Pod{
		ObjectMeta: slimmeta.ObjectMeta{UID: types.UID(workload.Uid), Name: view.K8sPodName, Namespace: view.K8sNamespace},
		Spec:       slimcore.PodSpec{ServiceAccountName: workload.WorkloadInfo.ServiceAccount},
	})
	return view
}

// commitStrictEnrollment runs only inside the ACK callback, after processUpdate
// has stopped/joined cancellation. It checks cancellation again under the same
// mutex used by local deletion retirement. Managed callers also cannot commit
// an endpoint which Endpoint.Delete has already disconnected. Admission passes
// its actual managed owner separately from its immutable private wire view.
func (s *Server) commitStrictEnrollment(ctx context.Context, owner, acknowledged *endpoint.Endpoint) {
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	if ctx.Err() != nil || !owner.IsAlive() {
		return
	}
	if s.endpointCache == nil {
		s.endpointCache = make(map[uint16]*endpoint.Endpoint)
	}
	// Wire DEL is keyed only by Pod UID. Keep one acknowledged owner per UID
	// so stale sandbox deletion can recognize the newer same-UID owner.
	for id, cached := range s.endpointCache {
		if cached.K8sUID == acknowledged.K8sUID {
			delete(s.endpointCache, id)
		}
	}
	s.endpointCache[acknowledged.GetID16()] = acknowledged
}

func (s *Server) strictSnapshotStillDesired(ep *endpoint.Endpoint) bool {
	if !s.strictDeletedEndpointCleanup {
		return true
	}
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	return s.endpointCache[ep.GetID16()] == ep
}

// CleanupDeletedEndpointContext is the strict CNI/endpoint-deletion cleanup.
// It retires an exact immutable cache incarnation BEFORE any bounded wait.
// It neither opens nor unpins the netns nor removes its capture rules.
// A failed DEL is observable, but does not put the retired cache entry back.
func (s *Server) CleanupDeletedEndpointContext(ctx context.Context, ep *endpoint.Endpoint) (resultErr error) {
	if !s.strictDeletedEndpointCleanup {
		return fmt.Errorf("strict deleted-endpoint cleanup is disabled")
	}
	key, err := incarnation(ep)
	if err != nil {
		return err
	}
	if ep.IsAlive() {
		return fmt.Errorf("strict cleanup requires a disconnected managed endpoint, not a live admission view")
	}
	started := time.Now()
	deadline, _ := ctx.Deadline()
	defer func() {
		attrs := []any{logStage, "zds-deleted-endpoint-cleanup", logfields.EndpointID, key.id,
			logfields.K8sUID, key.uid, logfields.Attempt, 1, logfields.ElapsedDuration, time.Since(started), logCleanupDeadline, deadline}
		if resultErr != nil {
			s.logger.Error("Deleted endpoint cleanup incomplete; capture retained", append(attrs, logfields.Error, resultErr)...)
		} else {
			s.logger.Info("Deleted endpoint cleanup completed; capture retained", attrs...)
		}
	}()

	// Required even when another ADD holds the operation semaphore or ctx has
	// already expired. Thus runtime netns removal cannot poison the next replay.
	s.endpointCacheMutex.Lock()
	if sameIncarnation(s.endpointCache[key.id], key) {
		delete(s.endpointCache, key.id)
	}
	s.endpointCacheMutex.Unlock()

	release, err := s.acquireEndpointOperation(ctx)
	if err != nil {
		return fmt.Errorf("cache retired; waiting for endpoint operation: %w", err)
	}
	defer release()

	// Recheck after waiting: a new sandbox may have ACKed its ADD while this
	// cleanup was blocked. Sending an old same-UID DEL would remove that proxy.
	s.endpointCacheMutex.Lock()
	// An ADD already in flight at the first retirement may have committed
	// before releasing the semaphore. Retire that exact incarnation again.
	if sameIncarnation(s.endpointCache[key.id], key) {
		delete(s.endpointCache, key.id)
	}
	superseded := false
	for _, cached := range s.endpointCache {
		if cached.K8sUID == key.uid && !sameIncarnation(cached, key) {
			superseded = true
			break
		}
	}
	s.endpointCacheMutex.Unlock()
	if superseded {
		s.logger.Info("Skipping stale deleted-endpoint DEL after sandbox replacement",
			logStage, "zds-deleted-endpoint-cleanup",
			logfields.EndpointID, key.id,
			logfields.K8sUID, key.uid,
		)
		return nil
	}

	update := zdsUpdate{
		request: &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Del{Del: &pb.DelWorkload{Uid: key.uid}}},
		errCh:   make(chan error, 1),
		// No onAck deletion: desired cache retirement already happened, guarded
		// by exact ID/UID/netns. No netnsPath: DEL needs no namespace FD.
	}
	if err := s.sendUpdateAndWaitForAck(ctx, update); err != nil {
		return fmt.Errorf("cache retired; proxy DEL not acknowledged: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

type captureContextKey struct{}
type captureReference struct {
	ref        membership.Reference
	generation uint64
}

// WithCaptureReference is only called by the native admission gate after live
// Namespace/Pod and held-sandbox checks. It is not a remote metadata input.
func WithCaptureReference(ctx context.Context, ref membership.Reference, generation uint64) context.Context {
	return context.WithValue(ctx, captureContextKey{}, captureReference{ref, generation})
}

func canonicalBindingID(s string) bool {
	if s == "" || len(s) > 128 || strings.TrimSpace(s) != s {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func validateBinding(b *pb.WorkloadBinding) error {
	if b == nil || b.Version != 1 || !canonicalBindingID(b.SourceEpoch) || !canonicalBindingID(b.NamespaceUid) || !canonicalBindingID(b.PodUid) || b.EndpointId == 0 || b.EndpointId > 65535 || b.Incarnation == 0 || b.CaptureGeneration == 0 || b.NetnsIno == 0 || len(b.ProxyEpoch) != 32 {
		return fmt.Errorf("invalid original ADD binding")
	}
	return nil
}
func bindingForCapture(ctx context.Context, ep *endpoint.Endpoint, ns *netns.NetNS) (*pb.WorkloadBinding, error) {
	c, ok := ctx.Value(captureContextKey{}).(captureReference)
	if !ok || c.ref.Key.PodUID != ep.K8sUID || c.ref.Incarnation == 0 || c.generation == 0 {
		return nil, fmt.Errorf("strict ADD requires native admission reference")
	}
	var st unix.Stat_t
	if err := unix.Fstat(ns.FD(), &st); err != nil {
		return nil, fmt.Errorf("stat actual captured sandbox FD: %w", err)
	}
	return &pb.WorkloadBinding{Version: 1, SourceEpoch: c.ref.Epoch, ClusterId: c.ref.Key.ClusterID, NamespaceUid: c.ref.Key.NamespaceUID, PodUid: c.ref.Key.PodUID, EndpointId: uint32(ep.GetID16()), Incarnation: c.ref.Incarnation, CaptureGeneration: c.generation, NetnsDev: uint64(st.Dev), NetnsIno: st.Ino}, nil
}

// A receipt can only be constructed after an exact typed wire response. Its
// fields are private; a generic ACK cannot manufacture one.
type DrainReceipt struct {
	ref        membership.Reference
	generation uint64
	forget     func()
}

func (r *DrainReceipt) Retire(registry *membership.Registry, expected membership.Reference, generation uint64) error {
	if r == nil || registry == nil || r.ref != expected || r.generation != generation {
		return fmt.Errorf("missing validated drain receipt")
	}
	state, ok := registry.Get(r.ref)
	if !ok || !state.Draining || state.DrainGeneration != r.generation {
		return fmt.Errorf("drain receipt no longer names current membership")
	}
	if !registry.CompleteDrain(r.ref, r.generation) || !registry.Retire(r.ref) {
		return fmt.Errorf("membership changed during receipt retirement")
	}
	if r.forget != nil {
		r.forget()
	}
	return nil
}

type EndpointDrainCleaner interface {
	DrainDeletedEndpointContext(context.Context, *endpoint.Endpoint, membership.Reference, uint64) (*DrainReceipt, error)
}

func (zc *ztunnelConn) sendDrain(req *pb.DrainWorkload) error {
	if err := validateBinding(req.Binding); err != nil {
		return rejectedBeforeWrite(err)
	}
	if req.DrainGeneration == 0 || len(req.Nonce) != 32 || !bytes.Equal(req.Binding.ProxyEpoch, zc.proxyEpoch) {
		return rejectedBeforeWrite(fmt.Errorf("drain request does not belong to this proxy execution"))
	}
	if err := zc.conn.SetDeadline(time.Now().Add(defaultZDSAckTimeout)); err != nil {
		return err
	}
	defer zc.conn.SetDeadline(time.Time{})
	if err := zc.sendMsg(&pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Drain{Drain: req}}, nil); err != nil {
		return err
	}
	resp, err := zc.readResponse()
	if err != nil {
		return err
	}
	if ack := resp.GetAck(); ack != nil && ack.GetError() != "" {
		return fmt.Errorf("%w: %s", errNativeDrainNACK, ack.GetError())
	}
	got := resp.GetDrained()
	if got == nil || got.DrainGeneration != req.DrainGeneration || !bytes.Equal(got.Nonce, req.Nonce) || !proto.Equal(got.Binding, req.Binding) {
		return fmt.Errorf("missing or mismatched native workload-drained receipt")
	}
	return nil
}

func (s *Server) DrainDeletedEndpointContext(ctx context.Context, ep *endpoint.Endpoint, ref membership.Reference, generation uint64) (*DrainReceipt, error) {
	if ep == nil || ep.IsAlive() {
		return nil, fmt.Errorf("native deletion drain requires disconnected endpoint")
	}
	return s.drainOriginalEndpointContext(ctx, ep, ref, generation)
}

// DrainLiveEndpointForPolicyContext is terminal for the original ADD incarnation.
// It stops actual listeners and flows; it never removes native capture rules.
// Re-enrollment of the same incarnation remains rejected by native DrainOwners.
func (s *Server) DrainLiveEndpointForPolicyContext(ctx context.Context, ep *endpoint.Endpoint, ref membership.Reference, generation uint64) (*DrainReceipt, error) {
	if ep == nil || !ep.IsAlive() {
		return nil, fmt.Errorf("native policy drain requires live endpoint")
	}
	return s.drainOriginalEndpointContext(ctx, ep, ref, generation)
}

func (s *Server) drainOriginalEndpointContext(ctx context.Context, ep *endpoint.Endpoint, ref membership.Reference, generation uint64) (*DrainReceipt, error) {
	if !s.strictDeletedEndpointCleanup || ep == nil || generation == 0 {
		return nil, fmt.Errorf("native drain requires strict original endpoint ownership")
	}
	ctx, cancel := context.WithTimeout(ctx, defaultZDSAckTimeout)
	defer cancel()
	key, err := incarnation(ep)
	if err != nil {
		return nil, err
	}
	// Retire replay intent even if the subsequent queue/receipt wait fails.
	s.endpointCacheMutex.Lock()
	if sameIncarnation(s.endpointCache[key.id], key) {
		delete(s.endpointCache, key.id)
	}
	s.endpointCacheMutex.Unlock()
	release, err := s.acquireEndpointOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	var candidates []*pb.WorkloadBinding
	for {
		s.endpointCacheMutex.Lock()
		pending := s.pendingPolicyADDCompletionsLocked(key)
		if len(pending) == 0 {
			var selectionErr error
			candidates, selectionErr = s.originalDrainCandidatesLocked(key, ref)
			if sameIncarnation(s.endpointCache[key.id], key) {
				delete(s.endpointCache, key.id)
			}
			s.endpointCacheMutex.Unlock()
			if selectionErr != nil {
				return nil, selectionErr
			}
			break
		}
		s.endpointCacheMutex.Unlock()
		// Canceled producers may have returned before their queued consumer stopped.
		// Join that consumer before declaring pre-write absence or choosing history.
		for _, done := range pending {
			select {
			case <-done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	started := time.Now()
	deadline, _ := ctx.Deadline()
	var failures []error
	for i, b := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(append(failures, err)...)
		}
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		request := &pb.DrainWorkload{Binding: b, DrainGeneration: generation, Nonce: nonce}
		update := zdsUpdate{request: &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Drain{Drain: request}}, errCh: make(chan error, 1)}
		err := s.sendUpdateAndWaitForAck(ctx, update)
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			return &DrainReceipt{ref: ref, generation: generation, forget: func() { s.forgetOriginalDrainCandidates(key, candidates) }}, nil
		}
		failures = append(failures, err)
		// A typed-owner NACK only permits another exact, pre-recorded candidate.
		// It is never evidence of absence or drain. Protocol mismatch, timeout,
		// cancellation and a changed proxy execution abort without falling back.
		if !errors.Is(err, errNativeDrainNACK) || ctx.Err() != nil {
			break
		}
		if s.logger != nil && i+1 < len(candidates) {
			s.logger.Warn("Native owner rejected a drain candidate; trying retained exact history",
				logStage, "native-original-add-drain",
				logfields.Attempt, i+1,
				logfields.ElapsedDuration, time.Since(started),
				logfields.Backoff, time.Duration(0),
				logDrainDeadline, deadline,
				logfields.Version, b.CaptureGeneration,
				logfields.Error, err)
		}
	}
	return nil, fmt.Errorf("native workload drain unavailable; capture and uncertainty retained: %w", errors.Join(failures...))

}

// The process epoch is correlation, not authentication. Strict receipt authority
// is limited to the root-owned local proxy peer, using kernel credentials.
func requireRootProxyPeer(zc *ztunnelConn) error {
	raw, err := zc.conn.SyscallConn()
	if err != nil {
		return err
	}
	var peer *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) { peer, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if socketErr != nil {
		return socketErr
	}
	return authorizeProxyPeer(peer)
}

// authorizeProxyPeer accepts a ZDS peer whose kernel credentials are root in
// the agent's user namespace; only root can reach the socket at all. The PID
// is not authority: the kernel reports it as seen from the agent's PID
// namespace, so it is 0 for a proxy in its own Pod unless the agent shares
// the node's PID namespace, and with a shared namespace it is nonzero for
// every process. Requiring it only forced hostPID on the agent.
func authorizeProxyPeer(peer *unix.Ucred) error {
	if peer == nil || peer.Uid != 0 {
		return fmt.Errorf("strict ZDS drain requires a root-owned local proxy process")
	}
	return nil
}

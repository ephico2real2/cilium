// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package zds

import (
	"fmt"

	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

// This is restrictive queue/consumer lifetime, NOT an ADD or ACK receipt.
// It closes the interval before the validated pre-write binding is recorded.
type pendingPolicyADD struct {
	key  endpointIncarnation
	done chan struct{}
}

func (s *Server) beginPendingPolicyADD(req *pb.WorkloadRequest, path string) (*pendingPolicyADD, error) {
	add := req.GetAdd()
	if add == nil || add.Binding == nil {
		return nil, nil
	}
	b := add.Binding
	if b.Version != 1 || b.EndpointId == 0 || b.EndpointId > 65535 || b.Incarnation == 0 || b.CaptureGeneration == 0 || b.NetnsIno == 0 ||
		!canonicalBindingID(b.SourceEpoch) || !canonicalBindingID(b.NamespaceUid) || !canonicalBindingID(b.PodUid) ||
		add.Uid != b.PodUid || path == "" || (len(b.ProxyEpoch) != 0 && len(b.ProxyEpoch) != 32) {
		return nil, fmt.Errorf("pending native ADD has invalid original correlation")
	}
	pending := &pendingPolicyADD{key: endpointIncarnation{id: uint16(b.EndpointId), uid: b.PodUid, netnsPath: path}, done: make(chan struct{})}
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	if len(s.policyADDPending) >= maxPolicyADDAttempts {
		return nil, fmt.Errorf("pending native ADD capacity exhausted")
	}
	if s.policyADDPending == nil {
		s.policyADDPending = make(map[*pendingPolicyADD]struct{})
	}
	s.policyADDPending[pending] = struct{}{}
	return pending, nil
}

// Called by the actual consumer after all writes/read/cancellation callbacks
// have finished, or by the producer only when it did not enqueue the request.
func (s *Server) finishPendingPolicyADD(pending *pendingPolicyADD) {
	if pending == nil {
		return
	}
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	if _, ok := s.policyADDPending[pending]; ok {
		delete(s.policyADDPending, pending)
		close(pending.done)
	}
}
func (s *Server) pendingPolicyADDCompletionsLocked(key endpointIncarnation) []<-chan struct{} {
	completions := []<-chan struct{}{}
	for pending := range s.policyADDPending {
		if pending.key.id == key.id || pending.key.uid == key.uid || pending.key.netnsPath == key.netnsPath {
			completions = append(completions, pending.done)
		}
	}
	return completions
}

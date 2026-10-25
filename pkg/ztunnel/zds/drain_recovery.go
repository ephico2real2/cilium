// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package zds

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

const (
	maxPolicyADDHistory = 8
	logDrainDeadline    = "deadline"
)

var errNativeDrainNACK = errors.New("native original owner rejected drain")

func sameOriginalADD(a, b *pb.WorkloadBinding) bool {
	if a == nil || b == nil {
		return false
	}
	x := proto.Clone(a).(*pb.WorkloadBinding)
	y := proto.Clone(b).(*pb.WorkloadBinding)
	x.CaptureGeneration = 0
	y.CaptureGeneration = 0
	return proto.Equal(x, y)
}
func bindingIn(list []*pb.WorkloadBinding, b *pb.WorkloadBinding) bool {
	return slices.ContainsFunc(list, func(other *pb.WorkloadBinding) bool { return proto.Equal(other, b) })
}

// Caller holds endpointCacheMutex. Keep every distinct unresolved send binding;
// latest-only storage can lose an installed intermediate owner after ACK loss.
func (s *Server) appendPolicyADDHistoryLocked(key endpointIncarnation, b *pb.WorkloadBinding) error {
	history := s.policyADDHistory[key]
	if len(history) > maxPolicyADDHistory {
		return fmt.Errorf("native ADD uncertainty history exceeds its bound")
	}
	if old, exists := s.policyADDAttempts[key]; exists && !bindingIn(history, old) {
		if old == nil {
			return fmt.Errorf("native ADD uncertainty has missing original binding")
		}
		if len(history) >= maxPolicyADDHistory {
			return fmt.Errorf("native ADD uncertainty history capacity exhausted")
		}
		history = append(slices.Clone(history), proto.Clone(old).(*pb.WorkloadBinding))
	}
	if !bindingIn(history, b) {
		if len(history) >= maxPolicyADDHistory {
			return fmt.Errorf("native ADD uncertainty history capacity exhausted")
		}
		history = append(slices.Clone(history), proto.Clone(b).(*pb.WorkloadBinding))
	}
	if s.policyADDHistory == nil {
		s.policyADDHistory = make(map[endpointIncarnation][]*pb.WorkloadBinding)
	}
	s.policyADDHistory[key] = history
	s.policyADDAttempts[key] = proto.Clone(b).(*pb.WorkloadBinding)
	return nil
}

// Only an actual successful ADD ACK invokes this. It identifies the current
// binding for this exact proxy execution; unrelated or newer uncertainty stays.
// Caller holds endpointCacheMutex. It grants no flow/policy protection.
func (s *Server) pruneAcknowledgedPolicyHistoryLocked(key endpointIncarnation, b *pb.WorkloadBinding) {
	if len(s.policyADDHistory[key]) == 0 {
		return
	}
	kept := make([]*pb.WorkloadBinding, 0, len(s.policyADDHistory[key]))
	for _, old := range s.policyADDHistory[key] {
		if sameOriginalADD(old, b) && old.CaptureGeneration <= b.CaptureGeneration {
			continue
		}
		kept = append(kept, old)
	}
	if len(kept) == 0 {
		delete(s.policyADDHistory, key)
	} else {
		s.policyADDHistory[key] = kept
	}
	// The acknowledged map retains b. Latest points at a newer/foreign request
	// if one was recorded; otherwise b remains a restrictive ownership marker.
}

// Caller holds endpointCacheMutex and the producer operation semaphore. A
// candidate is public pre-write correlation only; only its exact native typed
// task-drain receipt can permit retirement. Never infer success from a NACK.
func (s *Server) originalDrainCandidatesLocked(key endpointIncarnation, ref membership.Reference) ([]*pb.WorkloadBinding, error) {
	if len(s.policyADDHistory[key]) > maxPolicyADDHistory {
		return nil, fmt.Errorf("native ADD history exceeds its bound")
	}
	var candidates []*pb.WorkloadBinding
	var origin *pb.WorkloadBinding
	add := func(b *pb.WorkloadBinding) error {
		if err := validateBinding(b); err != nil {
			return fmt.Errorf("invalid retained original ADD: %w", err)
		}
		if b.PodUid != ref.Key.PodUID || key.uid != ref.Key.PodUID || b.NamespaceUid != ref.Key.NamespaceUID ||
			b.SourceEpoch != ref.Epoch || b.ClusterId != ref.Key.ClusterID || b.Incarnation != ref.Incarnation || b.EndpointId != uint32(key.id) {
			return fmt.Errorf("retained ADD does not match exact native drain reference")
		}
		if origin != nil && !sameOriginalADD(origin, b) {
			return fmt.Errorf("retained ADD bindings disagree on sandbox or proxy execution")
		}
		if origin == nil {
			origin = b
		}
		if !bindingIn(candidates, b) {
			candidates = append(candidates, proto.Clone(b).(*pb.WorkloadBinding))
		}
		return nil
	}
	if b, ok := s.drainBindings[key]; ok {
		if err := add(b); err != nil {
			return nil, err
		}
	}
	if b, ok := s.policyADDAttempts[key]; ok {
		if err := add(b); err != nil {
			return nil, err
		}
	}
	for _, b := range s.policyADDHistory[key] {
		if err := add(b); err != nil {
			return nil, err
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("missing retained original ADD binding for this incarnation")
	}
	if len(candidates) > maxPolicyADDHistory+2 {
		return nil, fmt.Errorf("native drain candidate limit exceeded")
	}
	slices.SortFunc(candidates, func(a, b *pb.WorkloadBinding) int { return cmp.Compare(b.CaptureGeneration, a.CaptureGeneration) })
	return candidates, nil
}

// forgetRefusedADD removes a bound ADD that ztunnel refused from the ADD
// uncertainty history. ztunnel installs an owner only when the ADD succeeds, so
// a refused binding is not installed and is no owner to drain. Kept, refusals
// alone would fill the history and block every later ADD of the endpoint. The
// acknowledged owner marker is never removed here.
func (s *Server) forgetRefusedADD(req *pb.WorkloadRequest, path string) {
	add := req.GetAdd()
	if add == nil || add.Binding == nil || path == "" {
		return
	}
	refused := add.Binding
	key := endpointIncarnation{id: uint16(refused.EndpointId), uid: refused.PodUid, netnsPath: path}
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	if proto.Equal(s.drainBindings[key], refused) {
		return
	}
	kept := slices.DeleteFunc(slices.Clone(s.policyADDHistory[key]), func(b *pb.WorkloadBinding) bool { return proto.Equal(b, refused) })
	if len(kept) == 0 {
		delete(s.policyADDHistory, key)
	} else {
		s.policyADDHistory[key] = kept
	}
	if proto.Equal(s.policyADDAttempts[key], refused) {
		delete(s.policyADDAttempts, key)
		if len(kept) != 0 {
			s.policyADDAttempts[key] = proto.Clone(kept[len(kept)-1]).(*pb.WorkloadBinding)
		}
	}
}

// Called only by a correlated typed receipt's retirement closure. Selection is
// frozen before drain. Exact comparison preserves ACKs and send attempts added
// after selection, including a successor using the same endpoint/Pod/path slot.
func (s *Server) forgetOriginalDrainCandidates(key endpointIncarnation, selection []*pb.WorkloadBinding) {
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	if bindingIn(selection, s.drainBindings[key]) {
		delete(s.drainBindings, key)
	}
	kept := make([]*pb.WorkloadBinding, 0, len(s.policyADDHistory[key]))
	for _, b := range s.policyADDHistory[key] {
		if !bindingIn(selection, b) {
			kept = append(kept, b)
		}
	}
	if len(kept) == 0 {
		delete(s.policyADDHistory, key)
	} else {
		s.policyADDHistory[key] = kept
	}
	if bindingIn(selection, s.policyADDAttempts[key]) {
		delete(s.policyADDAttempts, key)
		if len(kept) != 0 && kept[len(kept)-1] != nil {
			s.policyADDAttempts[key] = proto.Clone(kept[len(kept)-1]).(*pb.WorkloadBinding)
		}
	}
}

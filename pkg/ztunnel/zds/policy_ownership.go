// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package zds

import (
	"fmt"

	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

const maxPolicyADDAttempts = 4096

// Called only after sandbox-FD and original binding validation, immediately
// BEFORE the actual seqpacket write. Failure/ACK loss never becomes absence.
// The full public binding fences retirement against a successor using the same
// endpoint-ID/Pod/path slot. No ACK or success is implied by an attempted send.
func (s *Server) recordPolicyADDAttempt(req *pb.WorkloadRequest, path string) error {
	add := req.GetAdd()
	if add == nil || add.Binding == nil {
		return nil
	}
	if err := validateBinding(add.Binding); err != nil {
		return err
	}
	if path == "" || add.Uid != add.Binding.PodUid {
		return fmt.Errorf("ADD attempt has no exact workload/sandbox correlation")
	}
	key := endpointIncarnation{id: uint16(add.Binding.EndpointId), uid: add.Binding.PodUid, netnsPath: path}
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	if s.policyADDAttempts == nil {
		s.policyADDAttempts = make(map[endpointIncarnation]*pb.WorkloadBinding)
	}
	if _, exists := s.policyADDAttempts[key]; !exists && len(s.policyADDAttempts) >= maxPolicyADDAttempts {
		return fmt.Errorf("native ADD uncertainty capacity exhausted")
	}
	return s.appendPolicyADDHistoryLocked(key, add.Binding)
}

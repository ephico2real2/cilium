// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"bytes"
	"fmt"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
)

// VerifyCapture reports whether the connected ztunnel execution acknowledged
// the ADD of exactly this endpoint incarnation at this capture generation. It
// only reads retained state: nothing is sent, re-asserted or advanced. After a
// ztunnel restart the live execution differs, and the caller must re-admit the
// endpoint so that a fresh ADD binds its capture to the new execution.
func (s *Server) VerifyCapture(ep *endpoint.Endpoint, ref membership.Reference, generation uint64) error {
	if s == nil || !s.strictDeletedEndpointCleanup {
		return fmt.Errorf("strict capture verification is unavailable")
	}
	key, err := incarnation(ep)
	if err != nil {
		return err
	}
	if generation == 0 {
		return fmt.Errorf("capture generation is unset")
	}
	s.endpointCacheMutex.RLock()
	defer s.endpointCacheMutex.RUnlock()
	if len(s.liveProxyEpoch) == 0 {
		return fmt.Errorf("no ztunnel execution has completed its initial snapshot")
	}
	binding := s.drainBindings[key]
	if binding == nil {
		return fmt.Errorf("no acknowledged ADD is retained for this endpoint incarnation")
	}
	if binding.SourceEpoch != ref.Epoch || binding.ClusterId != ref.Key.ClusterID ||
		binding.NamespaceUid != ref.Key.NamespaceUID || binding.PodUid != ref.Key.PodUID ||
		binding.Incarnation != ref.Incarnation || binding.EndpointId != uint32(key.id) ||
		binding.CaptureGeneration != generation {
		return fmt.Errorf("retained ADD acknowledgment names another incarnation or capture generation")
	}
	if !bytes.Equal(binding.ProxyEpoch, s.liveProxyEpoch) {
		return fmt.Errorf("retained ADD belongs to an earlier ztunnel execution")
	}
	return nil
}

func (s *Server) setLiveProxyEpoch(epoch []byte) {
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	s.liveProxyEpoch = bytes.Clone(epoch)
}

// clearLiveProxyEpoch forgets the execution when its connection ends, unless a
// successor already replaced it.
func (s *Server) clearLiveProxyEpoch(epoch []byte) {
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	if bytes.Equal(s.liveProxyEpoch, epoch) {
		s.liveProxyEpoch = nil
	}
}

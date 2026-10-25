// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package zds

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

func TestPolicyOwnershipChecksRetainedADDReplayAndSlotReuse(t *testing.T) {
	for _, name := range []string{"no-owner", "exact-binding", "slot-reuse", "pod-reuse", "sandbox-reuse", "replay-only", "payload-conflict", "unrelated"} {
		t.Run(name, func(t *testing.T) {
			s := strictCleanupServer(t)
			id, uid, path := uint16(9), "pod", "/ns"
			key := endpointIncarnation{id: 9, uid: "pod", netnsPath: "/ns"}
			present := name != "no-owner" && name != "unrelated"
			switch name {
			case "no-owner":
			case "slot-reuse":
				uid = "new-pod"
				path = "/new-ns"
			case "pod-reuse":
				id = 10
				path = "/new-ns"
			case "sandbox-reuse":
				id = 10
				uid = "new-pod"
			case "replay-only":
				s.endpointCache[9] = &endpoint.Endpoint{K8sUID: "pod"}
			case "payload-conflict":
				key = endpointIncarnation{id: 12, uid: "different", netnsPath: "/other"}
			case "unrelated":
				id = 55
				uid = "unrelated"
				path = "/unrelated"
			}
			if name != "no-owner" && name != "replay-only" {
				s.drainBindings = map[endpointIncarnation]*pb.WorkloadBinding{key: {EndpointId: 9, PodUid: "pod"}}
			}
			observed, err := s.ObservePolicyOwnership(id, uid, path)
			require.NoError(t, err)
			if present {
				require.Equal(t, PolicyOwnershipRetained, observed)
			} else {
				require.Equal(t, PolicyOwnershipAbsent, observed)
			}
		})
	}
}
func TestPolicyOwnershipBusyFailsBoundedlyAndThenRecovers(t *testing.T) {
	s := strictCleanupServer(t)
	held, release, released := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		s.endpointCacheMutex.Lock()
		close(held)
		<-release
		s.endpointCacheMutex.Unlock()
		close(released)
	}()
	<-held
	observed, err := s.ObservePolicyOwnership(9, "pod", "/ns")
	close(release)
	<-released
	require.ErrorContains(t, err, "busy")
	require.Zero(t, observed)
	observed, err = s.ObservePolicyOwnership(9, "pod", "/ns")
	require.NoError(t, err)
	require.Equal(t, PolicyOwnershipAbsent, observed)
}
func TestStrictADDRecordsRestrictionEvenWhenCanceledBeforeIO(t *testing.T) {
	s := strictCleanupServer(t)
	owner := liveManagedEndpoint(t, 9, "pod", "/absent/ns")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, s.EnrollEndpointForOwnerContext(ctx, owner, owner), context.Canceled)
	// Real option mutation observes the negative sticky intent even though no
	// ADD or public membership copy exists and cancellation happened before I/O.
	changed, err := owner.ApplyOpts(option.OptionMap{option.SourceIPVerification: option.OptionDisabled})
	require.ErrorContains(t, err, "cannot be disabled")
	require.False(t, changed)
	require.Empty(t, s.endpointCache)
	require.Empty(t, s.drainBindings)
}

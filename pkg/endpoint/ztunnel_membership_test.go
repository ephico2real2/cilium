// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestZtunnelMembershipRejectsDelayedCapturedPublicationAfterRevocation(t *testing.T) {
	ep := &Endpoint{}
	captured := ZtunnelMembership{Version: 1, Revision: 2, Epoch: "agent-a", Generation: 7, State: ZtunnelMembershipCaptured, NamespaceUID: "ns", NodeName: "node-a", ServiceAccount: "api"}
	require.True(t, ep.SetZtunnelMembership(captured))
	start := make(chan struct{})
	done := make(chan bool, 1)
	go func() { <-start; done <- ep.SetZtunnelMembership(captured) }()
	required := captured
	required.Revision = 3
	required.Generation = 0
	required.State = ZtunnelMembershipRequired
	require.True(t, ep.SetZtunnelMembership(required))
	close(start)
	require.False(t, <-done)
	actual, ok := ep.GetZtunnelMembership()
	require.True(t, ok)
	require.Equal(t, required, actual)
	require.True(t, ep.SetZtunnelMembership(required), "exact idempotent replay is harmless")
	conflicting := required
	conflicting.State = ZtunnelMembershipCaptured
	conflicting.Generation = 7
	require.False(t, ep.SetZtunnelMembership(conflicting), "one revision cannot describe conflicting states")
	fresh := captured
	fresh.Revision = 4
	fresh.Generation = 8
	require.True(t, ep.SetZtunnelMembership(fresh))
	foreign := fresh
	foreign.Revision = 5
	foreign.Epoch = "foreign-agent"
	require.False(t, ep.SetZtunnelMembership(foreign))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package endpoint

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyBindingCarriesStickyRequiredWhenPublicationDisappears(t *testing.T) {
	for _, name := range []string{"missing-copy", "unenrolled-copy"} {
		t.Run(name, func(t *testing.T) {
			ep, _ := nativeObservationEndpoint(t)
			ep.ObserveZtunnelRequired()
			if name == "unenrolled-copy" {
				ep.ztunnelMembership.Store(&ZtunnelMembership{Version: 1, State: ZtunnelMembershipUnenrolled})
			}
			require.NoError(t, ep.lockAlive())
			b := ep.ztunnelPolicyBindingLocked()
			require.True(t, b.RequiredObserved)
			err := ep.requireZtunnelPolicyDrainLocked()
			ep.unlock()
			require.ErrorContains(t, err, "no native policy transition authority")
		})
	}
}
func TestPolicyBindingIntentStrengthensWithoutChangingSandbox(t *testing.T) {
	old := ZtunnelPolicyBinding{EndpointID: 9, PodUID: "pod", NamespaceUID: "ns", ContainerID: "container", NetNSPath: "/ns", NetNSCookie: 5}
	current := old
	current.RequiredObserved = true
	require.True(t, sameZtunnelPolicyBinding(old, current))
	require.False(t, sameZtunnelPolicyBinding(current, old))
	changed := current
	changed.PodUID = "replacement"
	require.False(t, sameZtunnelPolicyBinding(current, changed))
}

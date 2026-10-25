// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package endpoint

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Required intent is sticky: losing or downgrading the published membership
// copy does not turn a Required endpoint back into an ordinary one.
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
			ep.unlock()
			require.True(t, b.RequiredObserved)
			require.True(t, ep.IsZtunnelQuarantined())
			require.True(t, ep.IsZtunnelMeshOnly())
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/option"
)

func sourceIPGuardTestEndpoint(enabled bool) *Endpoint {
	lib := option.GetEndpointMutableOptionLibrary()
	ep := &Endpoint{Options: option.NewIntOptions(&lib)}
	ep.Options.SetBool(option.SourceIPVerification, enabled)
	return ep
}

func TestZtunnelMembershipStatesRequireSourceIP(t *testing.T) {
	cases := []ZtunnelMembership{
		{Version: 1, State: ZtunnelMembershipRequired},
		{Version: 1, Revision: 1, Epoch: "agent-a", Generation: 1, State: ZtunnelMembershipCaptured},
		{Version: 1, State: ZtunnelMembershipDraining},
	}
	for _, membership := range cases {
		t.Run(membership.State, func(t *testing.T) {
			ep := sourceIPGuardTestEndpoint(true)
			require.True(t, ep.SetZtunnelMembership(membership))
			require.True(t, ep.ztunnelRequiresSourceIPLocked())
			require.True(t, ep.sourceIPDisableDeniedLocked(option.OptionDisabled))
			require.False(t, ep.sourceIPDisableDeniedLocked(option.OptionEnabled))
		})
	}
}

func TestRequiredMembershipRejectsDisabledSourceIP(t *testing.T) {
	ep := sourceIPGuardTestEndpoint(false)
	require.False(t, ep.SetZtunnelMembership(ZtunnelMembership{Version: 1, State: ZtunnelMembershipRequired}))
	_, ok := ep.GetZtunnelMembership()
	require.False(t, ok, "required membership must not publish when source-IP enforcement is off")
}

func TestSourceIPOptionUpdatesCannotWeakenRequiredMembership(t *testing.T) {
	ep := sourceIPGuardTestEndpoint(true)
	require.True(t, ep.SetZtunnelMembership(ZtunnelMembership{Version: 1, State: ZtunnelMembershipRequired}))
	ep.mutex.Lock()
	changed := ep.applyOptsLocked(option.OptionMap{option.SourceIPVerification: option.OptionDisabled})
	ep.mutex.Unlock()
	require.False(t, changed)
	require.True(t, ep.Options.IsEnabled(option.SourceIPVerification))
}

func TestSourceIPAnnotationCannotWeakenRequiredMembership(t *testing.T) {
	ep := sourceIPGuardTestEndpoint(true)
	require.True(t, ep.SetZtunnelMembership(ZtunnelMembership{Version: 1, State: ZtunnelMembershipRequired}))
	changed := ep.ApplySourceIPVerificationFromAnnotation(
		map[string]string{annotation.DisableSourceIPVerification: "true"},
		map[string]string{annotation.DelegateSourceIPVerification: "true"},
	)
	require.False(t, changed)
	require.True(t, ep.Options.IsEnabled(option.SourceIPVerification))
}

func TestSourceIPRequirementStaysLatchedAfterUnenrollment(t *testing.T) {
	ep := sourceIPGuardTestEndpoint(true)
	require.True(t, ep.SetZtunnelMembership(ZtunnelMembership{Version: 1, State: ZtunnelMembershipRequired}))
	require.True(t, ep.SetZtunnelMembership(ZtunnelMembership{Version: 1, State: ZtunnelMembershipUnenrolled}))
	require.True(t, ep.ztunnelRequiresSourceIPLocked(), "do not weaken the guard while remote lease withdrawal may still propagate")
	require.True(t, ep.sourceIPDisableDeniedLocked(option.OptionDisabled))
}

func TestRequiredIntentIsExportedToDatapathIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required bool
	}{
		{name: "ordinary", required: false},
		{name: "required", required: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep := sourceIPGuardTestEndpoint(true)
			if tc.required {
				ep.ObserveZtunnelRequired()
			}

			ep.mutex.Lock()
			identity := ep.sourceIPDatapathIdentityLocked()
			ep.mutex.Unlock()
			require.Equal(t, tc.required, identity.ZtunnelRequired)
			require.Equal(t, tc.required, ep.IsZtunnelQuarantined(), "Required observation separately closes quarantine")
		})
	}
}

func TestMembershipTransitionsCannotReleaseQuarantine(t *testing.T) {
	ep := sourceIPGuardTestEndpoint(true)
	cases := []ZtunnelMembership{
		{Version: 1, Revision: 1, Epoch: "agent-a", Generation: 1, State: ZtunnelMembershipRequired},
		{Version: 1, Revision: 2, Epoch: "agent-a", Generation: 2, State: ZtunnelMembershipCaptured},
		{Version: 1, Revision: 3, Epoch: "agent-a", Generation: 3, State: ZtunnelMembershipDraining},
		{Version: 1, Revision: 4, Epoch: "agent-a", Generation: 4, State: ZtunnelMembershipUnenrolled},
	}
	for _, membership := range cases {
		require.True(t, ep.SetZtunnelMembership(membership), membership.State)
		require.True(t, ep.IsZtunnelQuarantined(), "membership state cannot release the datapath hold")
	}
	require.True(t, ep.ztunnelRequiresSourceIPLocked(), "SourceIP requirement remains sticky")
}

func TestEndpointAPICannotDisableSourceIPForRequiredMembership(t *testing.T) {
	ep := sourceIPGuardTestEndpoint(true)
	ep.state = StateReady
	require.True(t, ep.SetZtunnelMembership(ZtunnelMembership{Version: 1, State: ZtunnelMembershipRequired}))
	err := ep.Update(&models.EndpointConfigurationSpec{Options: models.ConfigurationMap{option.SourceIPVerification: "0"}})
	require.ErrorContains(t, err, "SourceIPVerification cannot be disabled while ztunnel membership is required")
	require.True(t, ep.Options.IsEnabled(option.SourceIPVerification))
}

func TestSetDefaultOptsCannotDisableSourceIPForRequiredMembership(t *testing.T) {
	ep := sourceIPGuardTestEndpoint(true)
	require.True(t, ep.SetZtunnelMembership(ZtunnelMembership{Version: 1, State: ZtunnelMembershipRequired}))
	lib := option.GetEndpointMutableOptionLibrary()
	defaults := option.NewIntOptions(&lib)
	defaults.SetBool(option.SourceIPVerification, false)
	ep.SetDefaultOpts(defaults)
	require.True(t, ep.Options.IsEnabled(option.SourceIPVerification))
}

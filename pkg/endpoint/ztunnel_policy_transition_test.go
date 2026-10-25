// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
)

func releasedAdmissionEndpoint(t *testing.T) (*Endpoint, ZtunnelAdmissionReceipt) {
	t.Helper()
	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))
	require.False(t, ep.IsZtunnelQuarantined())
	return ep, receipt
}

func fence(ep *Endpoint) {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()
	ep.fenceZtunnelPolicyChangeLocked()
}

// Every regeneration distills a new EndpointPolicy object. Identical enforced
// content must leave a release untouched; a pointer or revision comparison
// would re-quarantine on every periodic or release-triggered regeneration.
func TestZtunnelFenceKeepsReleaseForSameContentInANewPolicyObject(t *testing.T) {
	ep, _ := releasedAdmissionEndpoint(t)
	selector := ep.desiredPolicy.SelectorPolicy
	redistilled := selector.DistillPolicy(ep.getLogger(), ep, nil)
	require.NoError(t, redistilled.Ready())
	t.Cleanup(func() { redistilled.Detach(ep.getLogger()) })
	require.NotSame(t, ep.desiredPolicy, redistilled)
	ep.desiredPolicy = redistilled
	ep.desiredPolicyRevision++
	fence(ep)
	require.False(t, ep.IsZtunnelQuarantined(), "same content and identity keep the release")
}

// A release bound to other content, an unavailable policy, or another
// identity is withdrawn before the new policy reaches the datapath.
func TestZtunnelFenceWithdrawsWhenEnforcedInputChanges(t *testing.T) {
	t.Run("content", func(t *testing.T) {
		ep, receipt := admissionEndpoint(t)
		close(ep.hasBPFProgram)
		receipt.PolicyDigest = "content-of-an-earlier-policy"
		ep.ztunnelAdmission.Store(&receipt)
		ep.ztunnelDatapathQuarantined.Store(false)
		require.False(t, ep.IsZtunnelQuarantined())
		fence(ep)
		require.True(t, ep.IsZtunnelQuarantined())
	})
	t.Run("unavailable policy", func(t *testing.T) {
		ep, _ := releasedAdmissionEndpoint(t)
		ep.desiredPolicy = &policy.EndpointPolicy{}
		fence(ep)
		require.True(t, ep.IsZtunnelQuarantined())
	})
	t.Run("identity", func(t *testing.T) {
		ep, _ := releasedAdmissionEndpoint(t)
		ep.SecurityIdentity = identity.NewIdentity(ep.SecurityIdentity.ID+1, ep.SecurityIdentity.Labels)
		ep.mutex.Lock()
		require.True(t, ep.ztunnelQuarantinedLocked(), "the incarnation predicate binds the identity too")
		ep.mutex.Unlock()
		fence(ep)
		require.True(t, ep.IsZtunnelQuarantined())
	})
}

// The fence only acts on a released Required endpoint.
func TestZtunnelFenceIgnoresUnreleasedAndOrdinaryEndpoints(t *testing.T) {
	ep, _ := admissionEndpoint(t)
	require.True(t, ep.IsZtunnelQuarantined())
	fence(ep)
	require.True(t, ep.IsZtunnelQuarantined(), "an unreleased endpoint stays quarantined")

	ordinary, _ := nativeObservationEndpoint(t)
	fence(ordinary)
	require.False(t, ordinary.IsZtunnelQuarantined(), "an ordinary endpoint is never quarantined")
}

// Release verification binds the realized content and identity; revision
// bookkeeping alone does not block it.
func TestZtunnelReleaseVerifiesContentAndIdentityNotRevision(t *testing.T) {
	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	ep.desiredPolicyRevision++
	receipt.PolicyRevision++
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt), "revision bookkeeping does not change enforced content")

	other, otherReceipt := admissionEndpoint(t)
	close(other.hasBPFProgram)
	otherReceipt.Identity++
	require.ErrorIs(t, other.ReleaseZtunnelQuarantine(otherReceipt), ErrZtunnelAdmissionMismatch)
	otherReceipt.Identity--
	otherReceipt.PolicyDigest = "other-content"
	require.ErrorIs(t, other.ReleaseZtunnelQuarantine(otherReceipt), ErrZtunnelAdmissionMismatch)
}

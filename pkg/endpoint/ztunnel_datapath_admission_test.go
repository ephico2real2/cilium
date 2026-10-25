// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"errors"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
)

// recordingLxcMap captures the admission flags of each endpoint-map write. It
// embeds the production interface so only WriteEndpoint is implemented.
type recordingLxcMap struct {
	lxcmap.Map
	writes []admissionFlags
	fail   error
}

type admissionFlags struct{ quarantined, meshOnly bool }

func (m *recordingLxcMap) WriteEndpoint(f lxcmap.EndpointFrontend) error {
	if m.fail != nil {
		return m.fail
	}
	var flags admissionFlags
	if q, ok := f.(interface{ IsZtunnelQuarantined() bool }); ok {
		flags.quarantined = q.IsZtunnelQuarantined()
	}
	if mo, ok := f.(interface{ IsZtunnelMeshOnly() bool }); ok {
		flags.meshOnly = mo.IsZtunnelMeshOnly()
	}
	m.writes = append(m.writes, flags)
	return nil
}

const admissionNamespaceUID = "11111111-1111-4111-8111-111111111111"

func capturedMembership(revision, generation uint64) ZtunnelMembership {
	return ZtunnelMembership{Version: 1, Revision: revision, Epoch: "agent-epoch-a",
		Generation: generation, State: ZtunnelMembershipCaptured, NamespaceUID: admissionNamespaceUID}
}

// admissionEndpoint is a Required endpoint with real distilled native policy,
// captured membership and source IP verification enabled.
func admissionEndpoint(t *testing.T) (*Endpoint, ZtunnelAdmissionReceipt) {
	t.Helper()
	ep, _ := nativeObservationEndpoint(t)
	lib := option.GetEndpointMutableOptionLibrary()
	ep.Options = option.NewIntOptions(&lib)
	ep.Options.SetBool(option.SourceIPVerification, true)
	ep.hasBPFProgram = make(chan struct{})
	ep.ObserveZtunnelRequired()
	require.True(t, ep.SetZtunnelMembership(ZtunnelMembership{Version: 1, Revision: 1, Epoch: "agent-epoch-a",
		Generation: 1, State: ZtunnelMembershipRequired, NamespaceUID: admissionNamespaceUID}))
	require.True(t, ep.SetZtunnelMembership(capturedMembership(2, 1)))
	snapshot, err := ep.realizedPolicy.SnapshotZtunnelL4(ep.policyRevision)
	require.NoError(t, err)
	ep.mutex.Lock()
	binding := ep.ztunnelPolicyBindingLocked()
	ep.mutex.Unlock()
	return ep, ZtunnelAdmissionReceipt{Binding: binding, Membership: capturedMembership(2, 1),
		PolicyRevision: ep.policyRevision, PolicyDigest: snapshot.Digest(), AuthorizationVersion: 7}
}

func TestZtunnelRequiredEndpointIsQuarantinedAndMeshOnlyUntilRelease(t *testing.T) {
	ordinary := sourceIPGuardTestEndpoint(true)
	require.False(t, ordinary.IsZtunnelQuarantined(), "ordinary endpoints keep native forwarding")
	require.False(t, ordinary.IsZtunnelMeshOnly())

	// Required without any receipt is quarantined even before an explicit
	// ObserveZtunnelRequired call (membership alone asserts Required).
	viaMembership := sourceIPGuardTestEndpoint(true)
	require.True(t, viaMembership.SetZtunnelMembership(capturedMembership(1, 1)))
	require.True(t, viaMembership.IsZtunnelQuarantined())
	require.True(t, viaMembership.IsZtunnelMeshOnly())

	ep, _ := admissionEndpoint(t)
	require.True(t, ep.IsZtunnelQuarantined())
	require.True(t, ep.IsZtunnelMeshOnly())
}

func TestZtunnelReleaseRequiresExactNativeReceipt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Endpoint, *ZtunnelAdmissionReceipt)
	}{
		{"no program installed by this agent", func(ep *Endpoint, _ *ZtunnelAdmissionReceipt) { ep.hasBPFProgram = make(chan struct{}) }},
		{"different Pod UID", func(_ *Endpoint, r *ZtunnelAdmissionReceipt) {
			r.Binding.PodUID = "33333333-3333-4333-8333-333333333333"
		}},
		{"different sandbox cookie", func(_ *Endpoint, r *ZtunnelAdmissionReceipt) { r.Binding.NetNSCookie++ }},
		{"stale membership generation", func(_ *Endpoint, r *ZtunnelAdmissionReceipt) { r.Membership.Generation = 9 }},
		{"membership not captured", func(_ *Endpoint, r *ZtunnelAdmissionReceipt) { r.Membership.State = ZtunnelMembershipRequired }},
		{"stale policy revision", func(_ *Endpoint, r *ZtunnelAdmissionReceipt) { r.PolicyRevision++ }},
		{"different policy digest", func(_ *Endpoint, r *ZtunnelAdmissionReceipt) { r.PolicyDigest = "0000" }},
		{"no authorization delivered", func(_ *Endpoint, r *ZtunnelAdmissionReceipt) { r.AuthorizationVersion = 0 }},
		{"source IP verification disabled", func(ep *Endpoint, _ *ZtunnelAdmissionReceipt) {
			ep.Options.SetBool(option.SourceIPVerification, false)
		}},
		{"desired policy not realized", func(ep *Endpoint, _ *ZtunnelAdmissionReceipt) { ep.desiredPolicyRevision++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep, receipt := admissionEndpoint(t)
			close(ep.hasBPFProgram)
			tc.mutate(ep, &receipt)
			err := ep.ReleaseZtunnelQuarantine(receipt)
			require.ErrorIs(t, err, ErrZtunnelAdmissionMismatch)
			require.True(t, ep.IsZtunnelQuarantined(), "every mismatch leaves the endpoint quarantined")
			require.Nil(t, ep.ztunnelAdmission.Load())
		})
	}

	_, foreign := admissionEndpoint(t)
	fresh := sourceIPGuardTestEndpoint(true)
	fresh.logger.Store(hivetest.Logger(t)) // every real endpoint has a logger
	fresh.hasBPFProgram = make(chan struct{})
	close(fresh.hasBPFProgram)
	require.ErrorIs(t, fresh.ReleaseZtunnelQuarantine(foreign), ErrZtunnelNotRequired)

	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))
	require.False(t, ep.IsZtunnelQuarantined(), "verified receipt releases quarantine")
	require.True(t, ep.IsZtunnelMeshOnly(), "release enters mesh-only, never ordinary forwarding")
	require.True(t, ep.ztunnelRequiresSourceIPLocked(), "Required stays sticky after release")
	ep.mutex.Lock()
	require.False(t, ep.ztunnelQuarantinedLocked())
	ep.mutex.Unlock()
}

func TestZtunnelWithdrawalRewritesEndpointMapAndCannotRevive(t *testing.T) {
	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	recorder := &recordingLxcMap{}
	ep.lxcMap = recorder
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))

	// Simulate the release regeneration: cache and frontend are released.
	ep.mutex.Lock()
	cache := ep.createEpInfoCache("", "")
	ep.mutex.Unlock()
	require.False(t, cache.IsZtunnelQuarantined())
	require.True(t, cache.IsZtunnelMeshOnly())
	ep.recordZtunnelLxcFrontend(cache)

	// A new captured generation (re-enrollment) withdraws admission at once.
	require.True(t, ep.SetZtunnelMembership(capturedMembership(3, 2)))
	require.Equal(t, []admissionFlags{{quarantined: true, meshOnly: true}}, recorder.writes,
		"withdrawal rewrites the endpoint map without waiting for regeneration")
	require.True(t, ep.IsZtunnelQuarantined())
	require.True(t, cache.IsZtunnelQuarantined(), "a stale released cache merges the live quarantine")
	require.Nil(t, ep.ztunnelAdmission.Load())

	// The previous receipt names the previous generation and cannot revive.
	require.ErrorIs(t, ep.ReleaseZtunnelQuarantine(receipt), ErrZtunnelAdmissionMismatch)
	require.True(t, ep.IsZtunnelQuarantined())

	// A second withdrawal is idempotent and writes nothing new.
	ep.WithdrawZtunnelAdmission("repeat")
	require.Len(t, recorder.writes, 1)

	// A fresh receipt for the new generation releases again.
	receipt.Membership = capturedMembership(3, 2)
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))
	require.False(t, ep.IsZtunnelQuarantined())
}

func TestZtunnelIncarnationChangeQuarantinesUnderLockAndMapFailureStaysClosed(t *testing.T) {
	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))
	ep.mutex.Lock()
	ep.NetNsCookie++
	require.True(t, ep.ztunnelQuarantinedLocked(), "replacement sandbox is never released by an old receipt")
	cache := ep.createEpInfoCache("", "")
	ep.mutex.Unlock()
	require.True(t, cache.IsZtunnelQuarantined())

	// A failed endpoint-map write is logged; the state remains quarantined.
	ep2, receipt2 := admissionEndpoint(t)
	close(ep2.hasBPFProgram)
	ep2.lxcMap = &recordingLxcMap{fail: errors.New("map write failed")}
	require.NoError(t, ep2.ReleaseZtunnelQuarantine(receipt2))
	ep2.mutex.Lock()
	ep2.recordZtunnelLxcFrontend(ep2.createEpInfoCache("", ""))
	ep2.mutex.Unlock()
	ep2.WithdrawZtunnelAdmission("test map failure")
	require.True(t, ep2.IsZtunnelQuarantined())
}

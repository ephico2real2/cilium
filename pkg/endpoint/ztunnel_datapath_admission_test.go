// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

// recordingLxcMap records the cilium_lxc flag bits that lxcmap.getBPFValue
// derives from each written frontend, and injects write failures. It embeds
// the production interface so only WriteEndpoint is implemented. It is a Go
// double; the BPF programs reading these bits are covered by bpf/tests.
type recordingLxcMap struct {
	lxcmap.Map
	mu        sync.Mutex
	attempts  int
	fail      error
	committed []uint32
}

func (m *recordingLxcMap) WriteEndpoint(f lxcmap.EndpointFrontend) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts++
	if m.fail != nil {
		return m.fail
	}
	var flags uint32
	if q, ok := f.(interface{ IsZtunnelQuarantined() bool }); ok && q.IsZtunnelQuarantined() {
		flags |= lxcmap.EndpointFlagZtunnelQuarantined
	}
	if mo, ok := f.(interface{ IsZtunnelMeshOnly() bool }); ok && mo.IsZtunnelMeshOnly() {
		flags |= lxcmap.EndpointFlagZtunnelMeshOnly
	}
	m.committed = append(m.committed, flags)
	return nil
}

func (m *recordingLxcMap) setFail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fail = err
}

func (m *recordingLxcMap) state() (int, []uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.attempts, slices.Clone(m.committed)
}

const quarantinedMeshOnly uint32 = lxcmap.EndpointFlagZtunnelQuarantined | lxcmap.EndpointFlagZtunnelMeshOnly

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
		PolicyRevision: ep.policyRevision, PolicyDigest: snapshot.ContentDigest(), Identity: ep.SecurityIdentity.ID,
		AuthorizationVersion: 7}
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
		{"different security identity", func(_ *Endpoint, r *ZtunnelAdmissionReceipt) { r.Identity++ }},
		{"different policy digest", func(_ *Endpoint, r *ZtunnelAdmissionReceipt) { r.PolicyDigest = "0000" }},
		{"no authorization delivered", func(_ *Endpoint, r *ZtunnelAdmissionReceipt) { r.AuthorizationVersion = 0 }},
		{"source IP verification disabled", func(ep *Endpoint, _ *ZtunnelAdmissionReceipt) {
			ep.Options.SetBool(option.SourceIPVerification, false)
		}},
		{"desired policy not realized", func(ep *Endpoint, _ *ZtunnelAdmissionReceipt) { ep.desiredPolicy = &policy.EndpointPolicy{} }},
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
	_, committed := recorder.state()
	require.Equal(t, []uint32{quarantinedMeshOnly}, committed,
		"withdrawal rewrites the endpoint map without waiting for regeneration")
	require.True(t, ep.ztunnelQuarantineAcked())
	require.True(t, ep.IsZtunnelQuarantined())
	require.True(t, cache.IsZtunnelQuarantined(), "a stale released cache merges the live quarantine")
	require.Nil(t, ep.ztunnelAdmission.Load())

	// The previous receipt names the previous generation and cannot revive.
	require.ErrorIs(t, ep.ReleaseZtunnelQuarantine(receipt), ErrZtunnelAdmissionMismatch)
	require.True(t, ep.IsZtunnelQuarantined())

	// A second withdrawal of an acknowledged interval writes nothing new.
	ep.WithdrawZtunnelAdmission("repeat")
	attempts, committed := recorder.state()
	require.Equal(t, 1, attempts)
	require.Len(t, committed, 1)

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

	// A failed endpoint-map write leaves the released kernel entry in place:
	// the withdrawal is not acknowledged (recovery is covered in
	// ztunnel_quarantine_recovery_test.go).
	ep2, receipt2, recorder, _ := recoveryEndpoint(t)
	recorder.setFail(errors.New("map write failed"))
	require.NoError(t, ep2.ReleaseZtunnelQuarantine(receipt2))
	ep2.mutex.Lock()
	ep2.recordZtunnelLxcFrontend(ep2.createEpInfoCache("", ""))
	ep2.mutex.Unlock()
	ep2.WithdrawZtunnelAdmission("test map failure")
	require.True(t, ep2.IsZtunnelQuarantined())
	_, committed := recorder.state()
	require.Empty(t, committed, "no quarantine bit reached cilium_lxc")
	require.False(t, ep2.ztunnelQuarantineAcked())
}

func TestZtunnelReleaseRejectsZeroAddressesThenAcceptsOneFamily(t *testing.T) {
	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	ep.IPv4 = netip.IPv4Unspecified()
	ep.IPv6 = netip.IPv6Unspecified()
	require.ErrorIs(t, ep.ReleaseZtunnelQuarantine(receipt), ErrZtunnelAdmissionMismatch)
	require.True(t, ep.IsZtunnelQuarantined())
	require.Nil(t, ep.ztunnelAdmission.Load())

	ep.IPv4 = netip.Addr{}
	require.ErrorIs(t, ep.ReleaseZtunnelQuarantine(receipt), ErrZtunnelAdmissionMismatch, "no address at all")

	ep.IPv6 = netip.MustParseAddr("fd00::10")
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt), "one configured family suffices")
	require.False(t, ep.IsZtunnelQuarantined())
	require.True(t, ep.IsZtunnelMeshOnly())
}

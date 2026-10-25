// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/time"
)

// gatedLxcMap samples the flags lxcmap.getBPFValue materializes, then holds
// the first write between that sample and the kernel update, the interval in
// which a delayed writer could otherwise commit stale flags.
type gatedLxcMap struct {
	lxcmap.Map
	mu               sync.Mutex
	calls            int
	values           []uint32
	deleted          int
	firstSnapshot    chan struct{}
	allowFirstCommit chan struct{}
	once             sync.Once
}

func newGatedLxcMap() *gatedLxcMap {
	return &gatedLxcMap{firstSnapshot: make(chan struct{}), allowFirstCommit: make(chan struct{})}
}

func (m *gatedLxcMap) unblock() { m.once.Do(func() { close(m.allowFirstCommit) }) }

func (m *gatedLxcMap) WriteEndpoint(f lxcmap.EndpointFrontend) error {
	var flags uint32
	if f.(interface{ IsZtunnelQuarantined() bool }).IsZtunnelQuarantined() {
		flags |= lxcmap.EndpointFlagZtunnelQuarantined
	}
	if f.(interface{ IsZtunnelMeshOnly() bool }).IsZtunnelMeshOnly() {
		flags |= lxcmap.EndpointFlagZtunnelMeshOnly
	}
	m.mu.Lock()
	m.calls++
	first := m.calls == 1
	m.mu.Unlock()
	if first {
		close(m.firstSnapshot)
		<-m.allowFirstCommit
	}
	m.mu.Lock()
	m.values = append(m.values, flags)
	m.mu.Unlock()
	return nil
}

func (m *gatedLxcMap) DeleteElement(*slog.Logger, lxcmap.EndpointFrontend) []error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleted++
	return nil
}

func (m *gatedLxcMap) committed() []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]uint32(nil), m.values...)
}

func awaitPublication(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("controlled operation did not complete")
	}
}

// publicationBarrierHeld asserts only that a writer owns the barrier at the
// channel-fixed interval; the security assertions are the committed bits.
func publicationBarrierHeld(ep *Endpoint) bool {
	if ep.ztunnelDatapathWriteMu.TryLock() {
		ep.ztunnelDatapathWriteMu.Unlock()
		return false
	}
	return true
}

// A regeneration that sampled released flags before a withdrawal can no
// longer commit them after the withdrawal: the withdrawal waits and writes
// last.
func TestZtunnelRegenerationCannotOverwriteCompletedWithdrawal(t *testing.T) {
	ep, receipt, _, _ := recoveryEndpoint(t)
	releaseAndRealize(t, ep, receipt)
	ep.mutex.Lock()
	f := ep.createEpInfoCache("", "")
	ep.mutex.Unlock()
	m := newGatedLxcMap()
	ep.lxcMap = m
	defer m.unblock()

	published := make(chan struct{})
	publicationErr := make(chan error, 1)
	go func() { publicationErr <- ep.writeZtunnelLxcFrontend(f); close(published) }()
	awaitPublication(t, m.firstSnapshot)
	held := publicationBarrierHeld(ep)
	withdrawn := make(chan struct{})
	go func() { ep.WithdrawZtunnelAdmission("concurrent regeneration"); close(withdrawn) }()
	m.unblock()
	awaitPublication(t, published)
	awaitPublication(t, withdrawn)
	require.NoError(t, <-publicationErr)
	require.True(t, held, "the regeneration write owns the publication barrier")
	require.Equal(t, []uint32{lxcmap.EndpointFlagZtunnelMeshOnly, quarantinedMeshOnly}, m.committed(),
		"the last committed entry is quarantined")
	require.True(t, ep.IsZtunnelQuarantined())
	require.True(t, ep.ztunnelQuarantineAcked())
}

// A release cannot run between a withdrawal's flag sample and its kernel
// update; it waits, then opens a new unacknowledged interval that the next
// withdrawal acknowledges with a quarantined write.
func TestZtunnelReleaseDoesNotOvertakeInFlightWithdrawal(t *testing.T) {
	ep, receipt, _, _ := recoveryEndpoint(t)
	releaseAndRealize(t, ep, receipt)
	m := newGatedLxcMap()
	ep.lxcMap = m
	defer m.unblock()

	withdrawn := make(chan struct{})
	go func() { ep.WithdrawZtunnelAdmission("first interval"); close(withdrawn) }()
	awaitPublication(t, m.firstSnapshot)
	held := publicationBarrierHeld(ep)
	released := make(chan struct{})
	releaseErr := make(chan error, 1)
	go func() { releaseErr <- ep.ReleaseZtunnelQuarantine(receipt); close(released) }()
	m.unblock()
	awaitPublication(t, withdrawn)
	awaitPublication(t, released)
	require.True(t, held, "the withdrawal owns the barrier the release uses")
	require.NoError(t, <-releaseErr)
	require.False(t, ep.ztunnelQuarantineAcked(), "the later release opens a new interval")

	ep.WithdrawZtunnelAdmission("second interval")
	require.True(t, ep.ztunnelQuarantineAcked())
	require.Equal(t, []uint32{quarantinedMeshOnly, quarantinedMeshOnly}, m.committed())
}

// A regeneration write that samples quarantine acknowledges the interval.
func TestZtunnelQuarantinedRegenerationWriteAcknowledges(t *testing.T) {
	ep, receipt, recorder, _ := recoveryEndpoint(t)
	releaseAndRealize(t, ep, receipt)
	recorder.setFail(errors.New("injected cilium_lxc failure"))
	ep.WithdrawZtunnelAdmission("map failure")
	require.False(t, ep.ztunnelQuarantineAcked())
	ep.controllers.RemoveAllAndWait() // isolate the regeneration publication

	recorder.setFail(nil)
	ep.mutex.Lock()
	cache := ep.createEpInfoCache("", "")
	ep.mutex.Unlock()
	require.NoError(t, ep.writeZtunnelLxcFrontend(cache))
	_, committed := recorder.state()
	require.Equal(t, []uint32{quarantinedMeshOnly}, committed)
	require.True(t, ep.ztunnelQuarantineAcked())
}

// Deleting the endpoint's entries retires publication: no delayed withdrawal,
// recovery or regeneration of this endpoint object writes them again.
func TestZtunnelDeletionRetiresEndpointMapPublication(t *testing.T) {
	ep, receipt, _, _ := recoveryEndpoint(t)
	releaseAndRealize(t, ep, receipt)
	m := newGatedLxcMap()
	m.unblock()
	ep.lxcMap = m

	ep.mutex.Lock()
	require.Empty(t, ep.deleteZtunnelLxcEntries())
	cache := ep.createEpInfoCache("", "")
	ep.mutex.Unlock()

	ep.WithdrawZtunnelAdmission("after deletion")
	require.True(t, ep.IsZtunnelQuarantined())
	require.True(t, ep.ztunnelQuarantineAcked(), "no entry of this endpoint remains")
	require.ErrorIs(t, ep.writeZtunnelLxcFrontend(cache), ErrNotAlive)
	queued := true
	require.NoError(t, ep.recoverZtunnelQuarantine(context.Background(), "after deletion", &queued))
	require.Empty(t, m.committed(), "a deleted entry is never rewritten")
	require.Equal(t, 1, m.deleted)
}

// The recovery attempt itself, driven without timing: map errors keep the
// interval unacknowledged, the first successful write acknowledges it with a
// quarantined entry, and a settled attempt writes nothing.
func TestZtunnelFailedMapWriteRecoversDeterministically(t *testing.T) {
	ep, receipt, m, _ := recoveryEndpoint(t)
	releaseAndRealize(t, ep, receipt)
	m.setFail(errors.New("injected cilium_lxc failure"))
	ep.ztunnelDatapathWriteMu.Lock()
	ep.ztunnelAdmission.Store(nil)
	ep.ztunnelDatapathQuarantined.Store(true)
	ok := ep.writeZtunnelQuarantine("injected failure")
	ep.ztunnelDatapathWriteMu.Unlock()
	require.False(t, ok)
	require.False(t, ep.ztunnelQuarantineAcked())

	queued := true // isolates the map retry from the regeneration request
	require.Error(t, ep.recoverZtunnelQuarantine(context.Background(), "retry", &queued))
	m.setFail(nil)
	require.NoError(t, ep.recoverZtunnelQuarantine(context.Background(), "recovered", &queued))
	attempts, committed := m.state()
	require.Equal(t, []uint32{quarantinedMeshOnly}, committed)
	require.True(t, ep.ztunnelQuarantineAcked())
	require.NoError(t, ep.recoverZtunnelQuarantine(context.Background(), "settled", &queued))
	final, _ := m.state()
	require.Equal(t, attempts, final)
}

// A canceled attempt neither writes nor acknowledges; a live retry recovers.
func TestZtunnelCanceledRecoveryAttemptDoesNotAcknowledgeOrWrite(t *testing.T) {
	ep, receipt, m, _ := recoveryEndpoint(t)
	releaseAndRealize(t, ep, receipt)
	ep.ztunnelDatapathWriteMu.Lock()
	ep.ztunnelAdmission.Store(nil)
	ep.ztunnelDatapathQuarantined.Store(true)
	ep.ztunnelDatapathWriteMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	queued := true
	require.ErrorIs(t, ep.recoverZtunnelQuarantine(ctx, "canceled", &queued), context.Canceled)
	attempts, committed := m.state()
	require.Zero(t, attempts)
	require.Empty(t, committed)
	require.False(t, ep.ztunnelQuarantineAcked())
	require.NoError(t, ep.recoverZtunnelQuarantine(context.Background(), "live retry", &queued))
	require.True(t, ep.ztunnelQuarantineAcked())
}

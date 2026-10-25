// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/time"
)

// recordingBuildQueue is the endpoint build queue. A regeneration reaches it
// only through the endpoint's real event queue and regeneration event. It
// records the endpoint and does not build a datapath.
type recordingBuildQueue struct {
	mu     sync.Mutex
	builds []uint64
}

func (q *recordingBuildQueue) QueueEndpointBuild(_ context.Context, epID uint64) (func(), error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.builds = append(q.builds, epID)
	return nil, errors.New("test build queue does not build datapaths")
}

func (q *recordingBuildQueue) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.builds)
}

// recoveryEndpoint is a released-capable Required endpoint with the
// lifecycle parts the recovery path uses: alive context, controller manager,
// a running event queue and a build queue.
func recoveryEndpoint(t *testing.T) (*Endpoint, ZtunnelAdmissionReceipt, *recordingLxcMap, *recordingBuildQueue) {
	t.Helper()
	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	ep.status = NewEndpointStatus() // every constructed endpoint has one
	ep.aliveCtx, ep.aliveCancel = context.WithCancel(context.Background())
	ep.controllers = controller.NewManager()
	ep.initialEnvoyPolicyComputed = make(chan struct{})
	close(ep.initialEnvoyPolicyComputed)
	builds := &recordingBuildQueue{}
	ep.epBuildQueue = builds
	ep.eventQueue = eventqueue.NewEventQueueBuffered(hivetest.Logger(t), "ztunnel-recovery-test", 4)
	ep.eventQueue.Run()
	recorder := &recordingLxcMap{}
	ep.lxcMap = recorder
	t.Cleanup(func() {
		ep.controllers.RemoveAllAndWait()
		ep.aliveCancel()
		ep.eventQueue.Stop()
		ep.eventQueue.WaitToBeDrained()
	})
	return ep, receipt, recorder, builds
}

func releaseAndRealize(t *testing.T, ep *Endpoint, receipt ZtunnelAdmissionReceipt) {
	t.Helper()
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))
	ep.mutex.Lock()
	cache := ep.createEpInfoCache("", "")
	ep.mutex.Unlock()
	require.False(t, cache.IsZtunnelQuarantined())
	ep.recordZtunnelLxcFrontend(cache)
}

func triggerRecovery(ep *Endpoint) {
	ep.controllers.TriggerController(ztunnelQuarantineRecoveryControllerName(ep.GetID16()))
}

func TestZtunnelQuarantineRegenerationRecompilesDatapath(t *testing.T) {
	meta := ztunnelQuarantineRegeneration("membership withdrawn")
	require.Equal(t, regeneration.RegenerateWithDatapath, meta.RegenerationLevel)
	require.Equal(t, regeneration.ReasonEndpointUpdate, meta.Reason)
	require.Contains(t, meta.Message, "membership withdrawn")
}

// A failed write after release leaves the released entry. The withdrawal is
// retried by the recovery controller and by repeated withdrawals, one
// regeneration is queued through the endpoint event queue, and the kernel
// entry carries the quarantine bit once a write succeeds.
func TestZtunnelWithdrawalMapFailureRetriesQueuesRegenerationAndRecovers(t *testing.T) {
	ep, receipt, recorder, builds := recoveryEndpoint(t)
	releaseAndRealize(t, ep, receipt)
	recorder.setFail(errors.New("injected cilium_lxc failure"))

	ep.WithdrawZtunnelAdmission("membership withdrawn")
	require.True(t, ep.IsZtunnelQuarantined())
	require.False(t, ep.ztunnelQuarantineAcked(), "a failed write is never an acknowledgement")

	// The controller queues exactly one regeneration and keeps retrying.
	require.Eventually(t, func() bool { return builds.count() == 1 }, 5*time.Second, 10*time.Millisecond,
		"a RegenerateWithDatapath must reach the endpoint build queue")
	require.Eventually(t, func() bool { attempts, _ := recorder.state(); return attempts >= 2 }, 5*time.Second, 10*time.Millisecond)

	// A repeated withdrawal of an unacknowledged interval retries the write.
	before, _ := recorder.state()
	ep.WithdrawZtunnelAdmission("repeat while the released entry remains")
	after, committed := recorder.state()
	require.Greater(t, after, before)
	require.Empty(t, committed)

	// The map recovers: the next attempt writes the quarantine bit.
	recorder.setFail(nil)
	triggerRecovery(ep)
	require.Eventually(t, ep.ztunnelQuarantineAcked, 5*time.Second, 10*time.Millisecond)
	_, committed = recorder.state()
	require.Equal(t, []uint32{quarantinedMeshOnly}, committed)
	require.Equal(t, 1, builds.count(), "one regeneration per recovery")

	// Once acknowledged, nothing more is written.
	settled, _ := recorder.state()
	triggerRecovery(ep)
	ep.WithdrawZtunnelAdmission("repeat after acknowledgement")
	time.Sleep(50 * time.Millisecond)
	final, committed := recorder.state()
	require.Equal(t, settled, final)
	require.Len(t, committed, 1)
}

// The acknowledgement belongs to one release interval: a later release needs
// its own successful withdrawal write.
func TestZtunnelWithdrawalAcknowledgementIsPerReleaseInterval(t *testing.T) {
	ep, receipt, recorder, _ := recoveryEndpoint(t)
	releaseAndRealize(t, ep, receipt)
	ep.WithdrawZtunnelAdmission("first interval")
	require.True(t, ep.ztunnelQuarantineAcked())

	// Release again for a new captured generation.
	require.True(t, ep.SetZtunnelMembership(capturedMembership(3, 2)))
	receipt.Membership = capturedMembership(3, 2)
	releaseAndRealize(t, ep, receipt)
	require.False(t, ep.ztunnelQuarantineAcked(), "a new release interval is not acknowledged by the old write")

	recorder.setFail(errors.New("injected cilium_lxc failure"))
	ep.WithdrawZtunnelAdmission("second interval")
	require.False(t, ep.ztunnelQuarantineAcked())
	recorder.setFail(nil)
	triggerRecovery(ep)
	require.Eventually(t, ep.ztunnelQuarantineAcked, 5*time.Second, 10*time.Millisecond)
	_, committed := recorder.state()
	require.Equal(t, quarantinedMeshOnly, committed[len(committed)-1])
}

// A release that wins while recovery is pending owns the entry: recovery stops
// without writing.
func TestZtunnelQuarantineRecoveryStopsAfterVerifiedRelease(t *testing.T) {
	ep, receipt, recorder, _ := recoveryEndpoint(t)
	releaseAndRealize(t, ep, receipt)
	recorder.setFail(errors.New("injected cilium_lxc failure"))
	ep.WithdrawZtunnelAdmission("membership withdrawn")

	require.True(t, ep.SetZtunnelMembership(capturedMembership(3, 2)))
	receipt.Membership = capturedMembership(3, 2)
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))
	recorder.setFail(nil)
	settled, _ := recorder.state()
	triggerRecovery(ep)
	time.Sleep(100 * time.Millisecond)
	final, committed := recorder.state()
	require.Equal(t, settled, final, "recovery does not write after a verified release")
	require.Empty(t, committed)
	require.False(t, ep.IsZtunnelQuarantined())
}

// An entry realized for another incarnation is never rewritten by recovery;
// it writes again only after the current incarnation's entry is realized.
func TestZtunnelQuarantineRecoveryNeverWritesAnotherIncarnation(t *testing.T) {
	ep, receipt, recorder, builds := recoveryEndpoint(t)
	releaseAndRealize(t, ep, receipt)
	recorder.setFail(errors.New("injected cilium_lxc failure"))
	ep.WithdrawZtunnelAdmission("membership withdrawn")
	ep.mutex.Lock()
	ep.NetNsCookie++
	ep.mutex.Unlock()

	recorder.setFail(nil)
	require.Eventually(t, func() bool { return builds.count() == 1 }, 5*time.Second, 10*time.Millisecond)
	settled, _ := recorder.state()
	triggerRecovery(ep)
	time.Sleep(100 * time.Millisecond)
	final, committed := recorder.state()
	require.Equal(t, settled, final, "the previous incarnation's entry is not written")
	require.Empty(t, committed)
	require.False(t, ep.ztunnelQuarantineAcked())

	// The regeneration for the current incarnation realizes a new entry.
	ep.mutex.Lock()
	cache := ep.createEpInfoCache("", "")
	ep.mutex.Unlock()
	ep.recordZtunnelLxcFrontend(cache)
	triggerRecovery(ep)
	require.Eventually(t, ep.ztunnelQuarantineAcked, 5*time.Second, 10*time.Millisecond)
	_, committed = recorder.state()
	require.Equal(t, []uint32{quarantinedMeshOnly}, committed)
}

// Endpoint deletion ends recovery: no write after disconnect and the
// controller exits with the endpoint's other controllers.
func TestZtunnelQuarantineRecoveryEndsWithEndpointDeletion(t *testing.T) {
	ep, receipt, recorder, _ := recoveryEndpoint(t)
	releaseAndRealize(t, ep, receipt)
	recorder.setFail(errors.New("injected cilium_lxc failure"))
	ep.WithdrawZtunnelAdmission("membership withdrawn")
	require.Eventually(t, func() bool { attempts, _ := recorder.state(); return attempts >= 2 }, 5*time.Second, 10*time.Millisecond)

	ep.mutex.Lock()
	require.True(t, ep.setState(StateDisconnecting, "test deletion"))
	ep.mutex.Unlock()
	recorder.setFail(nil)
	settled, _ := recorder.state()
	triggerRecovery(ep)
	time.Sleep(100 * time.Millisecond)
	final, committed := recorder.state()
	require.Equal(t, settled, final, "a deleted endpoint's entry is not rewritten")
	require.Empty(t, committed)

	done := make(chan struct{})
	go func() { ep.controllers.RemoveAllAndWait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery controller did not exit")
	}
}

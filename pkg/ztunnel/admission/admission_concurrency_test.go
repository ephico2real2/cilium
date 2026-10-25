// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
)

// EnsureEndpoint changes nothing for an endpoint whose admission still
// verifies, and runs full admission when it does not.
func TestEnsureEndpointAdmitsOnlyWhenEvidenceIsNotCurrent(t *testing.T) {
	g, ep, enrolled, _ := admittedVerifyFixture(t)
	_, before, _ := g.membership.CurrentForPodUID(ep.K8sUID)
	require.NoError(t, g.EnsureEndpoint(t.Context(), ep, membership.StageNamespaceEnrollment))
	require.EqualValues(t, 1, enrolled.Load(), "a current admission is not repeated")
	_, after, _ := g.membership.CurrentForPodUID(ep.K8sUID)
	require.Equal(t, before.ZDSGeneration, after.ZDSGeneration)

	// ztunnel restarted: the live execution holds no ADD of the admitted
	// generation, and will hold the one a re-admission sends.
	g.verifyCapture = func(_ *endpoint.Endpoint, _ membership.Reference, generation uint64) error {
		if generation == before.ZDSGeneration {
			return errors.New("retained ADD belongs to an earlier ztunnel execution")
		}
		return nil
	}
	require.Error(t, g.VerifyEndpoint(t.Context(), ep))
	require.NoError(t, g.EnsureEndpoint(t.Context(), ep, membership.StageRestoredReadmission))
	require.EqualValues(t, 2, enrolled.Load(), "stale evidence is re-admitted")
	_, readmitted, _ := g.membership.CurrentForPodUID(ep.K8sUID)
	require.Greater(t, readmitted.ZDSGeneration, before.ZDSGeneration)
}

// blockingAdmission holds the first ZDS ADD of an admission open until the
// test lets it finish.
func blockingAdmission(t *testing.T) (*gate, *endpoint.Endpoint, *atomic.Int32, chan struct{}, chan struct{}) {
	t.Helper()
	g, _, ep := cniGateFixture(t)
	g.budget, g.attemptTimeout = 5*time.Second, 5*time.Second
	g.verifyCapture = func(*endpoint.Endpoint, membership.Reference, uint64) error { return nil }
	entered, proceed := make(chan struct{}), make(chan struct{})
	enrolled := new(atomic.Int32)
	g.enroll = func(ctx context.Context, _, _ *endpoint.Endpoint) error {
		if enrolled.Add(1) == 1 {
			close(entered)
			select {
			case <-proceed:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	return g, ep, enrolled, entered, proceed
}

// The order seen after an agent restart: namespace enrollment and restored
// re-admission admit the same endpoint at once. The second caller waits for
// the first instead of revoking its capture, then finds it admitted and does
// nothing: one ZDS ADD, one capture generation.
func TestConcurrentAdmissionsOfOneEndpointRunOneAtATime(t *testing.T) {
	g, ep, enrolled, entered, proceed := blockingAdmission(t)
	first := make(chan error, 1)
	go func() { first <- g.WaitForEndpoint(context.Background(), ep) }()
	<-entered
	_, inFlight, _ := g.membership.CurrentForPodUID(ep.K8sUID)

	second := make(chan error, 1)
	go func() { second <- g.EnsureEndpoint(context.Background(), ep, membership.StageRestoredReadmission) }()
	require.Eventually(t, func() bool { return g.admissions.users(ep.K8sUID) == 2 }, 5*time.Second, time.Millisecond)
	_, during, _ := g.membership.CurrentForPodUID(ep.K8sUID)
	require.Equal(t, inFlight.ZDSGeneration, during.ZDSGeneration, "the waiting caller did not start or revoke a capture")

	close(proceed)
	require.NoError(t, <-first)
	require.NoError(t, <-second)
	require.EqualValues(t, 1, enrolled.Load(), "the second caller found the endpoint admitted")
	_, after, _ := g.membership.CurrentForPodUID(ep.K8sUID)
	require.Equal(t, inFlight.ZDSGeneration, after.ZDSGeneration)
	require.True(t, after.ReadyForAddress())
	published, _ := ep.GetZtunnelMembership()
	require.Equal(t, endpoint.ZtunnelMembershipCaptured, published.State)
	require.Zero(t, g.admissions.size())
}

// A caller that gives up while another admission of the endpoint is running
// fails without touching that admission's capture generation.
func TestAdmissionWaiterThatGivesUpDoesNotRevokeTheAdmissionInProgress(t *testing.T) {
	g, ep, enrolled, entered, proceed := blockingAdmission(t)
	first := make(chan error, 1)
	go func() { first <- g.WaitForEndpoint(context.Background(), ep) }()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, g.EnsureEndpoint(ctx, ep, membership.StageSourceVerification), context.DeadlineExceeded)

	close(proceed)
	require.NoError(t, <-first)
	require.EqualValues(t, 1, enrolled.Load())
	_, state, _ := g.membership.CurrentForPodUID(ep.K8sUID)
	require.True(t, state.ReadyForAddress(), "the admission in progress kept its capture")
	published, _ := ep.GetZtunnelMembership()
	require.Equal(t, endpoint.ZtunnelMembershipCaptured, published.State)
}

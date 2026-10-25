// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package endpoint

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
)

type policyTestDrain struct {
	done chan struct{}
	err  error
}

func (d *policyTestDrain) Done() <-chan struct{} { return d.done }
func (d *policyTestDrain) Err() error            { return d.err }
func (d *policyTestDrain) finish(err error)      { d.err = err; close(d.done) }

type policyTestTransitioner struct {
	calls   atomic.Int32
	next    *policyTestDrain
	started chan struct{}
}

func (p *policyTestTransitioner) BeginPolicyTransition(ep *Endpoint, _ ZtunnelPolicyBinding) (ZtunnelPolicyDrain, error) {
	p.calls.Add(1)
	// Probe from another goroutine: recursive TryLock itself is invalid under
	// lockdebug. Only this fixture waits for that bounded local observation.
	available := make(chan bool, 1)
	go func() {
		acquired := ep.mutex.TryLock()
		if acquired {
			ep.mutex.UnlockIgnoreTime()
		}
		available <- acquired
	}()
	if <-available {
		panic("missing endpoint lock")
	}
	if p.started != nil {
		close(p.started)
		p.started = nil
	}
	return p.next, nil
}
func policyMutationResult(ep *Endpoint) *policyGenerateResult {
	return &policyGenerateResult{endpointPolicy: ep.desiredPolicy, policyRevision: ep.desiredPolicyRevision + 1,
		identity: ep.getIdentity(), identityRevision: ep.identityRevision}
}
func startPolicyMutation(t *testing.T, ep *Endpoint, res *policyGenerateResult) error {
	t.Helper()
	require.NoError(t, ep.lockAlive())
	defer ep.unlock()
	return ep.setDesiredPolicy(&datapathRegenerationContext{policyResult: res})
}
func TestNativePolicyMutationWaitsForDrainOutsideEndpointLock(t *testing.T) {
	ep, _ := nativeObservationEndpoint(t)
	d := &policyTestDrain{done: make(chan struct{})}
	adapter := &policyTestTransitioner{next: d, started: make(chan struct{})}
	ep.ztunnelPolicyTransitions = []ZtunnelPolicyTransitioner{adapter}
	res := policyMutationResult(ep)
	old := ep.desiredPolicyRevision
	require.ErrorIs(t, startPolicyMutation(t, ep, res), ErrZtunnelPolicyDrainPending)
	require.Equal(t, old, ep.desiredPolicyRevision)
	done := make(chan error, 1)
	go func() { done <- ep.prepareZtunnelPolicyChange(t.Context(), res, false) }()
	require.NoError(t, ep.lockAlive())
	ep.unlock() // No network wait under lock.
	d.finish(nil)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("drain wait stuck")
	}
	require.NoError(t, startPolicyMutation(t, ep, res))
	require.Equal(t, res.policyRevision, ep.desiredPolicyRevision)
	require.Equal(t, int32(1), adapter.calls.Load())
	// The ready receipt remains terminal, not a release or new activation.
	require.NotNil(t, ep.ztunnelPolicyDrain)
}
func TestNativePolicyCancellationCannotCommitOrUndoDrain(t *testing.T) {
	ep, _ := nativeObservationEndpoint(t)
	d := &policyTestDrain{done: make(chan struct{})}
	adapter := &policyTestTransitioner{next: d}
	ep.ztunnelPolicyTransitions = []ZtunnelPolicyTransitioner{adapter}
	res := policyMutationResult(ep)
	old := ep.desiredPolicyRevision
	require.ErrorIs(t, startPolicyMutation(t, ep, res), ErrZtunnelPolicyDrainPending)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, ep.prepareZtunnelPolicyChange(ctx, res, false), context.Canceled)
	require.Equal(t, old, ep.desiredPolicyRevision)
	require.NotNil(t, ep.ztunnelPolicyDrain)
	d.finish(nil)
	require.ErrorIs(t, ep.prepareZtunnelPolicyChange(ctx, res, false), context.Canceled)
	require.NoError(t, ep.prepareZtunnelPolicyChange(t.Context(), res, false))
	require.NoError(t, startPolicyMutation(t, ep, res))
}
func TestNativePolicyDrainRejectsChangedSandboxAndUIDReuse(t *testing.T) {
	for _, name := range []string{"namespace", "pod", "path", "cookie", "container", "endpoint"} {
		t.Run(name, func(t *testing.T) {
			ep, _ := nativeObservationEndpoint(t)
			d := &policyTestDrain{done: make(chan struct{})}
			ep.ztunnelPolicyTransitions = []ZtunnelPolicyTransitioner{&policyTestTransitioner{next: d}}
			res := policyMutationResult(ep)
			old := ep.desiredPolicyRevision
			require.ErrorIs(t, startPolicyMutation(t, ep, res), ErrZtunnelPolicyDrainPending)
			d.finish(nil)
			require.NoError(t, ep.lockAlive())
			switch name {
			case "namespace":
				ep.SetK8sNamespaceUID("replacement")
			case "pod":
				ep.K8sUID = "replacement"
			case "path":
				ep.containerNetnsPath = "/new/ns/net"
			case "cookie":
				ep.NetNsCookie++
			case "container":
				value := "replacement"
				ep.containerID.Store(&value)
			case "endpoint":
				ep.ID++
			}
			ep.unlock()
			require.ErrorContains(t, ep.prepareZtunnelPolicyChange(t.Context(), res, false), "incarnation changed")
			require.Equal(t, old, ep.desiredPolicyRevision)
		})
	}
}
func TestNativePolicyDrainFailureRetriesSameClosedOwner(t *testing.T) {
	ep, _ := nativeObservationEndpoint(t)
	first := &policyTestDrain{done: make(chan struct{})}
	adapter := &policyTestTransitioner{next: first}
	ep.ztunnelPolicyTransitions = []ZtunnelPolicyTransitioner{adapter}
	res := policyMutationResult(ep)
	require.ErrorIs(t, startPolicyMutation(t, ep, res), ErrZtunnelPolicyDrainPending)
	failure := errors.New("typed drain unavailable")
	first.finish(failure)
	next := &policyTestDrain{done: make(chan struct{})}
	next.finish(nil)
	adapter.next = next
	require.NoError(t, ep.prepareZtunnelPolicyChange(t.Context(), res, false))
	require.Equal(t, int32(2), adapter.calls.Load())
	require.NoError(t, startPolicyMutation(t, ep, res))
}
func TestNativePolicyWithoutTransitionAuthorityFailsRequiredOnly(t *testing.T) {
	ep, _ := nativeObservationEndpoint(t)
	res := policyMutationResult(ep)
	ep.ztunnelMembership.Store(&ZtunnelMembership{Version: 1, State: ZtunnelMembershipRequired})
	require.ErrorContains(t, startPolicyMutation(t, ep, res), "no native policy transition authority")
	ep.ztunnelMembership.Store(nil)
	require.NoError(t, startPolicyMutation(t, ep, res))
}
func TestNativeUnchangedPolicyPreparationDoesNotDrain(t *testing.T) {
	ep, _ := nativeObservationEndpoint(t)
	adapter := &policyTestTransitioner{next: &policyTestDrain{done: make(chan struct{})}}
	ep.ztunnelPolicyTransitions = []ZtunnelPolicyTransitioner{adapter}
	require.NoError(t, ep.prepareZtunnelPolicyChange(t.Context(), &policyGenerateResult{endpointPolicy: ep.desiredPolicy, policyRevision: ep.desiredPolicyRevision}, false))
	require.Zero(t, adapter.calls.Load())
}

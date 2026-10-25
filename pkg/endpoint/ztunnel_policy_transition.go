// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"errors"
	"fmt"
)

var ErrZtunnelPolicyDrainPending = errors.New("native workload policy drain is incomplete")

// ZtunnelPolicyBinding is captured under the endpoint lock. It is correlation
// for a native registry/ZDS join, never authority supplied by a workload.
type ZtunnelPolicyBinding struct {
	// RequiredObserved is a sticky local restriction, not proof of capture,
	// authorization or an ADD. It must never make an unsafe state eligible.
	RequiredObserved                             bool
	EndpointID                                   uint16
	NamespaceUID, PodUID, NetNSPath, ContainerID string
	NetNSCookie                                  uint64
}

// ZtunnelPolicyDrain is completed only by the native typed original-ADD task
// drain path. An Envoy/ADS/ZDS generic ACK is not an implementation.
type ZtunnelPolicyDrain interface {
	Done() <-chan struct{}
	Err() error // Only read after Done closes.
}

// ZtunnelPolicyTransitioner is a trusted Hive dependency. Begin runs with the
// endpoint lock (and possibly incremental queue lock) held: it must synchronously
// revoke registry eligibility, then start bounded owned work, without I/O/waits,
// endpoint method calls or policy callbacks. Its worker runs without those locks.
// Nil means the native authority positively checked that there is no retained
// or in-flight ADD for this exact transition. Required pre-ADD also needs an
// exact current registry entry. A missing registry/configuration is not proof.
type ZtunnelPolicyTransitioner interface {
	BeginPolicyTransition(*Endpoint, ZtunnelPolicyBinding) (ZtunnelPolicyDrain, error)
}

type ztunnelPolicyDrainState struct {
	binding ZtunnelPolicyBinding
	drain   ZtunnelPolicyDrain
}

func (e *Endpoint) ztunnelPolicyBindingLocked() ZtunnelPolicyBinding {
	return ZtunnelPolicyBinding{RequiredObserved: e.ztunnelRequiresSourceIPLocked(), EndpointID: e.ID, NamespaceUID: e.GetK8sNamespaceUID(),
		PodUID: e.K8sUID, NetNSPath: e.containerNetnsPath, ContainerID: e.GetContainerID(), NetNSCookie: e.NetNsCookie}
}

// Caller holds the endpoint lock. No release of this terminal fence exists.
func (e *Endpoint) beginZtunnelPolicyDrainLocked() error {
	b := e.ztunnelPolicyBindingLocked()
	if old := e.ztunnelPolicyDrain; old != nil {
		if !sameZtunnelPolicyBinding(old.binding, b) {
			return fmt.Errorf("policy drain endpoint incarnation changed")
		}
		select {
		case <-old.drain.Done():
			if old.drain.Err() == nil {
				return nil
			}
			// The registry remains Draining. A fresh exact-owner retry may recover a
			// lost receipt; it cannot reopen this incarnation.
		default:
			return ErrZtunnelPolicyDrainPending
		}
	}
	if len(e.ztunnelPolicyTransitions) == 0 {
		if b.RequiredObserved {
			return fmt.Errorf("Required endpoint has no native policy transition authority")
		}
		return nil
	}
	if len(e.ztunnelPolicyTransitions) != 1 || e.ztunnelPolicyTransitions[0] == nil {
		return fmt.Errorf("native policy transition authority is ambiguous")
	}
	d, err := e.ztunnelPolicyTransitions[0].BeginPolicyTransition(e, b)
	if err != nil {
		return err
	}
	if d == nil {
		return nil
	}
	if d.Done() == nil {
		return fmt.Errorf("native policy drain has no completion")
	}
	e.ztunnelPolicyDrain = &ztunnelPolicyDrainState{binding: b, drain: d}
	select {
	case <-d.Done():
		return d.Err()
	default:
		return ErrZtunnelPolicyDrainPending
	}
}

func (e *Endpoint) requireZtunnelPolicyDrainLocked() error {
	return e.beginZtunnelPolicyDrainLocked()
}

// Called with endpoint mutex NOT held. buildMutex may be held; the ZDS worker
// never needs it. Both mutation entry points recheck under their existing lock.
func (e *Endpoint) prepareZtunnelPolicyChange(ctx context.Context, res *policyGenerateResult, incremental bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.lockAlive(); err != nil {
		return err
	}
	changed := (incremental || res != nil) && e.desiredPolicy != nil && e.desiredPolicy.HasPendingZtunnelMapChanges()
	if res != nil {
		changed = changed || res.endpointPolicy != e.desiredPolicy || res.policyRevision != e.desiredPolicyRevision
	}
	// An earlier race at the guarded consume may already have started a drain.
	changed = changed || e.ztunnelPolicyDrain != nil || e.desiredPolicy != e.realizedPolicy
	if !changed {
		e.unlock()
		return nil
	}
	err := e.beginZtunnelPolicyDrainLocked()
	state := e.ztunnelPolicyDrain
	e.unlock()
	if !errors.Is(err, ErrZtunnelPolicyDrainPending) {
		return err
	}
	if state == nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-state.drain.Done():
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := state.drain.Err(); err != nil {
		return err
	}
	if err := e.lockAlive(); err != nil {
		return err
	}
	defer e.unlock()
	if e.ztunnelPolicyDrain != state || !sameZtunnelPolicyBinding(state.binding, e.ztunnelPolicyBindingLocked()) {
		return fmt.Errorf("policy drain completion belongs to another endpoint incarnation")
	}
	return nil
}

// ObserveZtunnelRequired records restrictive process-local intent before strict
// ADD work can start. It provides no capture/ACK/TLS evidence and is never cleared.
// Atomic-only: safe for callers that already hold another subsystem's mutex.
func (e *Endpoint) ObserveZtunnelRequired() { e.ztunnelSourceIPRequired.Store(true) }

// Restrictive intent may strengthen during a first ADD attempt; it is not part
// of the immutable endpoint/sandbox identity. Weakening known intent is rejected.
func sameZtunnelPolicyBinding(old, current ZtunnelPolicyBinding) bool {
	if old.RequiredObserved && !current.RequiredObserved {
		return false
	}
	old.RequiredObserved = false
	current.RequiredObserved = false
	return old == current
}

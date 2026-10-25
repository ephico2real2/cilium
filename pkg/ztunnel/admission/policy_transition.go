// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package admission

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

type policyDrainResult struct {
	done chan struct{}
	err  error // Published by close(done); no reads before Done.
}

func (r *policyDrainResult) Done() <-chan struct{} { return r.done }
func (r *policyDrainResult) Err() error            { return r.err }

// BeginPolicyTransition is called only through native Endpoint mutation hooks.
// It performs no endpoint calls or I/O while the caller holds the endpoint
// lock. BeginDrain synchronously removes source eligibility before the worker
// can wait for the exact original-ADD proxy/task drain receipt.
func (g *gate) BeginPolicyTransition(ep *endpoint.Endpoint, b endpoint.ZtunnelPolicyBinding) (endpoint.ZtunnelPolicyDrain, error) {
	// This construction-time fact is distinct from a missing authority: this
	// process never constructed a ZDS owner. It is not historical/protected proof.
	if g.serverDisabledForExecution {
		if !g.enabled && !b.RequiredObserved && len(g.policyCandidates(b)) == 0 {
			return nil, nil
		}
		g.fencePolicyCandidates(b)
		return nil, fmt.Errorf("Required endpoint cannot use the no-ZDS execution mode")
	}
	if g.policyOwnership == nil {
		g.fencePolicyCandidates(b)
		return nil, fmt.Errorf("native ADD ownership inspector unavailable")
	}
	ownership, err := g.policyOwnership.ObservePolicyOwnership(b.EndpointID, b.PodUID, b.NetNSPath)
	if err != nil {
		g.fencePolicyCandidates(b)
		return nil, fmt.Errorf("native ADD ownership unavailable: %w", err)
	}
	if ownership != zds.PolicyOwnershipAbsent && ownership != zds.PolicyOwnershipRetained {
		g.fencePolicyCandidates(b)
		return nil, fmt.Errorf("native ADD ownership classification invalid")
	}
	relevant := g.policyCandidates(b)
	if !g.enabled {
		if b.RequiredObserved || len(relevant) != 0 || ownership == zds.PolicyOwnershipRetained {
			g.fencePolicyCandidates(b)
			return nil, fmt.Errorf("Required or retained ADD policy authority is disabled")
		}
		// Ordinary/platform endpoint, no known intent and positive current ZDS absence.
		return nil, nil
	}
	if g.membership == nil {
		return nil, fmt.Errorf("native membership registry unavailable for policy transition")
	}
	ref, state, found := g.membership.CurrentForPodUID(b.PodUID)
	if !found {
		if b.RequiredObserved || len(relevant) != 0 || ownership == zds.PolicyOwnershipRetained {
			g.fencePolicyCandidates(b)
			return nil, fmt.Errorf("Required or retained ADD has no exact current membership")
		}
		return nil, nil
	}
	if len(relevant) != 1 || relevant[0] != ref || ep == nil || b.EndpointID == 0 || state.EndpointID != b.EndpointID || state.NetnsPath != b.NetNSPath ||
		b.PodUID != ref.Key.PodUID || b.NamespaceUID != ref.Key.NamespaceUID || b.ContainerID == "" || b.NetNSCookie == 0 {
		g.fencePolicyCandidates(b)
		return nil, fmt.Errorf("Required policy update does not match the native endpoint/sandbox binding")
	}
	// Generation zero is safe only with this exact Required entry AND a positive
	// current ownership observation proving no retained replay/original ADD.
	if state.ZDSGeneration == 0 && !state.Draining {
		if ownership == zds.PolicyOwnershipAbsent {
			return nil, nil
		}
		g.membership.BeginDrain(ref)
		return nil, fmt.Errorf("pre-ADD registry conflicts with retained native ADD ownership")
	}
	generation, ok := g.membership.BeginDrain(ref)
	if !ok {
		return nil, fmt.Errorf("failed to terminally quarantine Required membership")
	}
	result := &policyDrainResult{done: make(chan struct{})}
	// Work owns a strict bounded deadline independently of request cancellation;
	// canceling a CNP update must never undo an already-started restrictive drain.
	go func() {
		defer close(result.done)
		ctx, cancel := context.WithTimeout(context.Background(), g.attemptTimeout)
		defer cancel()
		started := time.Now()
		deadline, _ := ctx.Deadline()
		if g.policyDrainer == nil {
			result.err = fmt.Errorf("typed original-ADD live policy drainer unavailable")
		} else {
			receipt, err := g.policyDrainer.DrainLiveEndpointForPolicyContext(ctx, ep, ref, generation)
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				err = receipt.ConfirmPolicyQuarantine(g.membership, ref, generation)
			}
			result.err = err
		}
		// Never turn terminal quarantine into Required/Captured on error or retry.
		if !g.publishMembership(ep, ref, "", "") {
			result.err = errors.Join(result.err, fmt.Errorf("terminal policy source publication was superseded"))
		}
		attrs := []any{logStage, "native-policy-live-drain", logfields.Attempt, 1,
			logfields.ElapsedDuration, time.Since(started), logDeadline, deadline,
			logfields.Backoff, time.Duration(0), logfields.EndpointID, b.EndpointID,
			logfields.K8sUID, b.PodUID, logNamespaceUID, b.NamespaceUID}
		if result.err != nil {
			g.logger.Error("Native workload policy quarantine drain failed", append(attrs, logfields.Error, result.err)...)
		} else {
			g.logger.Info("Native workload policy quarantine drain completed; incarnation remains closed", attrs...)
		}
	}()
	return result, nil
}

// Use all native slot/Pod/sandbox correlations so a stale or changed Pod UID
// cannot disguise retained ownership as an unrelated ordinary endpoint.
func (g *gate) policyCandidates(b endpoint.ZtunnelPolicyBinding) []membership.Reference {
	if g.membership == nil {
		return nil
	}
	refs := []membership.Reference{}
	for _, entry := range g.membership.SourceSnapshot().Entries {
		if (b.EndpointID != 0 && entry.EndpointID == b.EndpointID) ||
			(b.PodUID != "" && entry.Reference.Key.PodUID == b.PodUID) ||
			(b.NetNSPath != "" && entry.NetnsPath == b.NetNSPath) {
			refs = append(refs, entry.Reference)
		}
	}
	return refs
}
func (g *gate) fencePolicyCandidates(b endpoint.ZtunnelPolicyBinding) {
	for _, ref := range g.policyCandidates(b) {
		g.membership.BeginDrain(ref)
	}
}

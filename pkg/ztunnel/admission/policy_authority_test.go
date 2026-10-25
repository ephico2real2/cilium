// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package admission

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

func TestPolicyAuthorityAbsenceAndDisabledNeverDowngradeRequired(t *testing.T) {
	for _, name := range []string{"disabled-required", "disabled-ref", "disabled-retained", "missing-registry", "missing-ref", "retired-ref", "busy-owner", "missing-inspector", "unknown-observation", "stale-pod-uid", "stale-endpoint"} {
		t.Run(name, func(t *testing.T) {
			registry := membership.NewRegistry(1)
			b := endpoint.ZtunnelPolicyBinding{EndpointID: 9, NamespaceUID: "namespace", PodUID: "pod", NetNSPath: "/ns", ContainerID: "container", NetNSCookie: 5, RequiredObserved: true}
			g := &gate{enabled: true, membership: registry, policyOwnership: policyOwnershipFixture{state: zds.PolicyOwnershipAbsent}}
			var ref membership.Reference
			if name == "disabled-ref" || name == "retired-ref" || name == "stale-pod-uid" || name == "stale-endpoint" {
				var err error
				ref, err = registry.Require("namespace", "pod", 9, "/ns")
				require.NoError(t, err)
			}
			switch name {
			case "disabled-required":
				g.enabled = false
			case "disabled-ref":
				g.enabled = false
				b.RequiredObserved = false
			case "disabled-retained":
				g.enabled = false
				b.RequiredObserved = false
				g.policyOwnership = policyOwnershipFixture{state: zds.PolicyOwnershipRetained}
			case "missing-registry":
				g.membership = nil
			case "missing-ref": // Required marker survives missing registry association.
			case "retired-ref":
				generation, ok := registry.BeginDrain(ref)
				require.True(t, ok)
				require.True(t, registry.CompleteDrain(ref, generation))
				require.True(t, registry.Retire(ref))
			case "busy-owner":
				g.policyOwnership = policyOwnershipFixture{err: errors.New("ownership busy")}
			case "missing-inspector":
				g.policyOwnership = nil
			case "unknown-observation":
				g.policyOwnership = policyOwnershipFixture{}
			case "stale-pod-uid":
				b.PodUID = "replacement-pod"
				b.RequiredObserved = false
				g.policyOwnership = policyOwnershipFixture{state: zds.PolicyOwnershipRetained}
			case "stale-endpoint":
				b.EndpointID++
				g.policyOwnership = policyOwnershipFixture{state: zds.PolicyOwnershipRetained}
			}
			result, err := g.BeginPolicyTransition(&endpoint.Endpoint{}, b)
			require.Error(t, err)
			require.Nil(t, result)
			if state, ok := registry.Get(ref); ok {
				require.True(t, state.Draining, "known conflicting membership must close synchronously")
			}
		})
	}
}
func TestPolicyAuthorityExactPreADDAndOrdinaryRecovery(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled-unmanaged", true: "enabled-unmanaged"}[enabled], func(t *testing.T) {
			g := &gate{enabled: enabled, membership: membership.NewRegistry(1), policyOwnership: policyOwnershipFixture{state: zds.PolicyOwnershipAbsent}}
			result, err := g.BeginPolicyTransition(&endpoint.Endpoint{}, endpoint.ZtunnelPolicyBinding{EndpointID: 100})
			require.NoError(t, err)
			require.Nil(t, result)
		})
	}
	r := membership.NewRegistry(1)
	g := &gate{enabled: true, membership: r, policyOwnership: policyOwnershipFixture{state: zds.PolicyOwnershipAbsent}}
	b := endpoint.ZtunnelPolicyBinding{EndpointID: 9, NamespaceUID: "namespace", PodUID: "pod", NetNSPath: "/ns", ContainerID: "container", NetNSCookie: 5, RequiredObserved: true}
	_, err := g.BeginPolicyTransition(&endpoint.Endpoint{}, b)
	require.Error(t, err)
	ref, err := r.Require("namespace", "pod", 9, "/ns")
	require.NoError(t, err)
	result, err := g.BeginPolicyTransition(&endpoint.Endpoint{}, b)
	require.NoError(t, err)
	require.Nil(t, result)
	state, ok := r.Get(ref)
	require.True(t, ok)
	require.False(t, state.Draining)
	// Restoring metadata does not fabricate or cache a drained receipt/activation.
	require.Zero(t, state.ZDSGeneration)
	require.False(t, state.ReadyForAddress())
	require.False(t, state.Active())
}

func TestPolicyAuthorityNoZDSExecutionModeDoesNotExcuseRequired(t *testing.T) {
	r := membership.NewRegistry(1)
	g := &gate{serverDisabledForExecution: true, membership: r}
	// Constructor-owned default Observe mode has no ZDS instance at all.
	result, err := g.BeginPolicyTransition(&endpoint.Endpoint{}, endpoint.ZtunnelPolicyBinding{EndpointID: 100})
	require.NoError(t, err)
	require.Nil(t, result)
	b := endpoint.ZtunnelPolicyBinding{EndpointID: 9, PodUID: "pod", NamespaceUID: "ns", NetNSPath: "/ns", ContainerID: "container", NetNSCookie: 5, RequiredObserved: true}
	result, err = g.BeginPolicyTransition(&endpoint.Endpoint{}, b)
	require.Error(t, err)
	require.Nil(t, result)
	ref, err := r.Require("ns", "pod", 9, "/ns")
	require.NoError(t, err)
	b.RequiredObserved = false
	result, err = g.BeginPolicyTransition(&endpoint.Endpoint{}, b)
	require.Error(t, err)
	require.Nil(t, result)
	state, ok := r.Get(ref)
	require.True(t, ok)
	require.True(t, state.Draining)
	// Merely having !enabled with an unexpectedly missing owner is not this mode.
	g = &gate{membership: membership.NewRegistry(1)}
	result, err = g.BeginPolicyTransition(&endpoint.Endpoint{}, endpoint.ZtunnelPolicyBinding{EndpointID: 100})
	require.Error(t, err)
	require.Nil(t, result)
}

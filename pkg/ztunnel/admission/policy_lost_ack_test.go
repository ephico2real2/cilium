// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package admission

import (
	"errors"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

func TestNativePolicyZeroedRegistryWithRetainedADDStartsTerminalDrain(t *testing.T) {
	registry := membership.NewRegistry(1)
	ref, err := registry.Require("ns-uid", "pod-uid", 9, "/fixture/ns/net")
	require.NoError(t, err)
	generation, ok := registry.BeginZDS(ref)
	require.True(t, ok)
	require.True(t, registry.InvalidateCaptureGeneration(ref, generation))
	require.Zero(t, mustPolicyState(t, registry, ref).ZDSGeneration)
	d := &failedPolicyDrainer{entered: make(chan struct{}), release: make(chan struct{}), fail: errors.New("native original owner still unavailable")}
	g := &gate{enabled: true, membership: registry, policyOwnership: policyOwnershipFixture{state: zds.PolicyOwnershipRetained}, logger: hivetest.Logger(t), policyDrainer: d, attemptTimeout: time.Second}
	ep := &endpoint.Endpoint{ID: 9, K8sUID: "pod-uid"}
	binding := endpoint.ZtunnelPolicyBinding{EndpointID: 9, NamespaceUID: "ns-uid", PodUID: "pod-uid", NetNSPath: "/fixture/ns/net", ContainerID: "container-uid", NetNSCookie: 12, RequiredObserved: true}
	result, err := g.BeginPolicyTransition(ep, binding)
	require.NoError(t, err)
	require.NotNil(t, result, "lost ADD ACK is not pre-ADD absence")
	require.True(t, mustPolicyState(t, registry, ref).Draining)
	select {
	case <-d.entered:
	case <-time.After(time.Second):
		t.Fatal("terminal drain worker was not invoked")
	}
	close(d.release)
	select {
	case <-result.Done():
	case <-time.After(time.Second):
		t.Fatal("terminal drain did not finish")
	}
	require.ErrorIs(t, result.Err(), d.fail)
	state := mustPolicyState(t, registry, ref)
	require.True(t, state.Draining)
	require.False(t, state.DrainCompleted)
	require.False(t, state.ReadyForAddress())
	_, ok = registry.BeginZDS(ref)
	require.False(t, ok, "failed recovery cannot re-enroll the same incarnation")
}

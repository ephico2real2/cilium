// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package admission

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

type failedPolicyDrainer struct {
	entered chan struct{}
	release chan struct{}
	fail    error
}

func (d *failedPolicyDrainer) DrainLiveEndpointForPolicyContext(ctx context.Context, _ *endpoint.Endpoint, _ membership.Reference, _ uint64) (*zds.DrainReceipt, error) {
	close(d.entered)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.release:
		return nil, d.fail
	}
}
func TestNativePolicyTransitionFencesBeforeWaitingAndFailureCannotReenroll(t *testing.T) {
	registry := membership.NewRegistry(1)
	ref, err := registry.Require("ns-uid", "pod-uid", 9, "/fixture/ns/net")
	require.NoError(t, err)
	generation, ok := registry.BeginZDS(ref)
	require.True(t, ok)
	require.True(t, registry.MarkCaptured(ref, generation))
	require.True(t, registry.AcknowledgeZDS(ref, generation))
	require.True(t, mustPolicyState(t, registry, ref).ReadyForAddress())
	d := &failedPolicyDrainer{entered: make(chan struct{}), release: make(chan struct{}), fail: errors.New("underlying typed drain unavailable")}
	g := &gate{enabled: true, membership: registry, policyOwnership: policyOwnershipFixture{state: zds.PolicyOwnershipRetained}, logger: hivetest.Logger(t), policyDrainer: d, attemptTimeout: time.Second}
	ep := &endpoint.Endpoint{ID: 9, K8sUID: "pod-uid"}
	b := endpoint.ZtunnelPolicyBinding{EndpointID: 9, NamespaceUID: "ns-uid", PodUID: "pod-uid", NetNSPath: "/fixture/ns/net", ContainerID: "container-uid", NetNSCookie: 12}
	result, err := g.BeginPolicyTransition(ep, b)
	require.NoError(t, err)
	require.NotNil(t, result)
	state := mustPolicyState(t, registry, ref)
	require.True(t, state.Draining, "closed synchronously before returning a waiter")
	require.False(t, state.ReadyForAddress())
	require.False(t, state.Active())
	select {
	case <-d.entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not reach real drainer boundary")
	}
	close(d.release)
	select {
	case <-result.Done():
	case <-time.After(time.Second):
		t.Fatal("worker did not finish")
	}
	require.ErrorIs(t, result.Err(), d.fail)
	require.True(t, mustPolicyState(t, registry, ref).Draining)
	_, err = registry.Require("ns-uid", "pod-uid", 9, "/fixture/ns/net")
	require.Error(t, err)
	_, ok = registry.BeginZDS(ref)
	require.False(t, ok)
}
func mustPolicyState(t *testing.T, r *membership.Registry, ref membership.Reference) membership.State {
	t.Helper()
	state, ok := r.Get(ref)
	require.True(t, ok)
	return state
}
func TestNativePolicyTransitionMetadataMismatchFencesWithoutIssuingDrain(t *testing.T) {
	for _, name := range []string{"namespace", "endpoint", "sandbox", "cookie", "container"} {
		t.Run(name, func(t *testing.T) {
			r := membership.NewRegistry(1)
			ref, err := r.Require("ns", "pod", 9, "/ns")
			require.NoError(t, err)
			g := &gate{enabled: true, membership: r, policyOwnership: policyOwnershipFixture{state: zds.PolicyOwnershipAbsent}}
			b := endpoint.ZtunnelPolicyBinding{EndpointID: 9, NamespaceUID: "ns", PodUID: "pod", NetNSPath: "/ns", ContainerID: "runtime-id", NetNSCookie: 5}
			switch name {
			case "namespace":
				b.NamespaceUID = "reused-name-new-uid"
			case "endpoint":
				b.EndpointID++
			case "sandbox":
				b.NetNSPath = "/replaced"
			case "cookie":
				b.NetNSCookie = 0
			case "container":
				b.ContainerID = ""
			}
			result, err := g.BeginPolicyTransition(&endpoint.Endpoint{}, b)
			require.Error(t, err)
			require.Nil(t, result)
			require.True(t, mustPolicyState(t, r, ref).Draining)
		})
	}
}
func TestNativePolicyTransitionUnmanagedAndNeverAddedKeepNativeLifecycle(t *testing.T) {
	r := membership.NewRegistry(1)
	g := &gate{enabled: true, membership: r, policyOwnership: policyOwnershipFixture{state: zds.PolicyOwnershipAbsent}}
	result, err := g.BeginPolicyTransition(&endpoint.Endpoint{}, endpoint.ZtunnelPolicyBinding{})
	require.NoError(t, err)
	require.Nil(t, result)
	ref, err := r.Require("ns", "pod", 9, "/ns")
	require.NoError(t, err)
	result, err = g.BeginPolicyTransition(&endpoint.Endpoint{}, endpoint.ZtunnelPolicyBinding{EndpointID: 9, NamespaceUID: "ns", PodUID: "pod", NetNSPath: "/ns", ContainerID: "runtime-id", NetNSCookie: 5})
	require.NoError(t, err)
	require.Nil(t, result)
	require.False(t, mustPolicyState(t, r, ref).Draining)
}

type policyOwnershipFixture struct {
	state zds.PolicyOwnership
	err   error
}

func (p policyOwnershipFixture) ObservePolicyOwnership(uint16, string, string) (zds.PolicyOwnership, error) {
	return p.state, p.err
}

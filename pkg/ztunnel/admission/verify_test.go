// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
)

func admittedVerifyFixture(t *testing.T) (*gate, *endpoint.Endpoint, *atomic.Int32, *error) {
	t.Helper()
	g, _, ep := cniGateFixture(t)
	var enrolled atomic.Int32
	g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error {
		enrolled.Add(1)
		return nil
	}
	captureErr := new(error)
	g.verifyCapture = func(*endpoint.Endpoint, membership.Reference, uint64) error { return *captureErr }
	require.NoError(t, g.WaitForEndpoint(t.Context(), ep))
	require.EqualValues(t, 1, enrolled.Load())
	return g, ep, &enrolled, captureErr
}

// Verification confirms the admitted incarnation without changing anything:
// no ZDS ADD, no new capture generation, no publication change.
func TestVerifyEndpointConfirmsCurrentAdmissionWithoutSideEffects(t *testing.T) {
	g, ep, enrolled, _ := admittedVerifyFixture(t)
	ref, before, ok := g.membership.CurrentForPodUID(ep.K8sUID)
	require.True(t, ok)
	publication, _ := g.membership.Publication(ref)
	published, _ := ep.GetZtunnelMembership()

	require.NoError(t, g.VerifyEndpoint(t.Context(), ep))
	require.NoError(t, g.VerifyEndpoint(t.Context(), ep))

	require.EqualValues(t, 1, enrolled.Load(), "verification never sends a ZDS ADD")
	_, after, _ := g.membership.CurrentForPodUID(ep.K8sUID)
	require.Equal(t, before, after, "verification never starts a capture generation")
	again, _ := g.membership.Publication(ref)
	require.Equal(t, publication, again)
	republished, _ := ep.GetZtunnelMembership()
	require.Equal(t, published, republished)
}

// Each kind of stale evidence fails verification, so the caller re-admits.
func TestVerifyEndpointRejectsStaleEvidence(t *testing.T) {
	t.Run("capture not held by the live ztunnel execution", func(t *testing.T) {
		g, ep, _, captureErr := admittedVerifyFixture(t)
		*captureErr = errors.New("retained ADD belongs to an earlier ztunnel execution")
		require.ErrorContains(t, g.VerifyEndpoint(t.Context(), ep), "earlier ztunnel execution")
	})
	t.Run("namespace enrollment removed", func(t *testing.T) {
		g, ep, _, _ := admittedVerifyFixture(t)
		ns, err := g.core.Namespaces().Get(t.Context(), "apps", metav1.GetOptions{})
		require.NoError(t, err)
		delete(ns.Labels, "io.cilium/mtls-enabled")
		_, err = g.core.Namespaces().Update(t.Context(), ns, metav1.UpdateOptions{})
		require.NoError(t, err)
		require.ErrorContains(t, g.VerifyEndpoint(t.Context(), ep), "enrollment intent")
	})
	t.Run("Pod recreated under the same name", func(t *testing.T) {
		g, ep, _, _ := admittedVerifyFixture(t)
		pod, err := g.core.Pods("apps").Get(t.Context(), "server", metav1.GetOptions{})
		require.NoError(t, err)
		pod.UID = "recreated-pod"
		_, err = g.core.Pods("apps").Update(t.Context(), pod, metav1.UpdateOptions{})
		require.NoError(t, err)
		require.ErrorContains(t, g.VerifyEndpoint(t.Context(), ep), "admitted incarnation")
	})
	t.Run("capture generation advanced", func(t *testing.T) {
		g, ep, _, _ := admittedVerifyFixture(t)
		ref, _, ok := g.membership.CurrentForPodUID(ep.K8sUID)
		require.True(t, ok)
		_, ok = g.membership.BeginZDS(ref)
		require.True(t, ok)
		require.Error(t, g.VerifyEndpoint(t.Context(), ep))
	})
	t.Run("verifier unavailable", func(t *testing.T) {
		g, ep, _, _ := admittedVerifyFixture(t)
		g.verifyCapture = nil
		require.ErrorContains(t, g.VerifyEndpoint(t.Context(), ep), "unavailable")
	})
}

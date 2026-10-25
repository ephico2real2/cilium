// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
)

type restoreRevalidator struct {
	restrict   bool
	failures   int32
	readmitted atomic.Int32
	attempts   atomic.Int32
}

func (r *restoreRevalidator) ShouldRevalidate(context.Context, *endpoint.Endpoint, bool) (bool, error) {
	return r.restrict, nil
}
func (r *restoreRevalidator) RestrictRestoredEndpoint(context.Context, *endpoint.Endpoint, bool) (bool, error) {
	return r.restrict, nil
}
func (r *restoreRevalidator) EnsureEndpoint(_ context.Context, _ *endpoint.Endpoint, stage string) error {
	if stage != membership.StageRestoredReadmission {
		return errors.New("restored re-admission named the wrong stage: " + stage)
	}
	if r.attempts.Add(1) <= r.failures {
		return errors.New("ZDS cannot carry an ADD yet")
	}
	r.readmitted.Add(1)
	return nil
}

// Restriction runs before the ZDS snapshot is seeded and needs no ZDS; it
// reports re-admission when any revalidator requires it.
func TestRestoredEndpointRestrictionAggregatesRevalidators(t *testing.T) {
	ops := &EnrollmentReconciler{logger: hivetest.Logger(t), endpointRevalidators: []membership.EndpointRevalidator{
		&restoreRevalidator{}, &restoreRevalidator{restrict: true}}}
	needed, err := ops.restrictRestoredEndpoint(t.Context(), &endpoint.Endpoint{ID: 9}, true)
	require.NoError(t, err)
	require.True(t, needed)
	ops.endpointRevalidators = []membership.EndpointRevalidator{nil}
	_, err = ops.restrictRestoredEndpoint(t.Context(), &endpoint.Endpoint{ID: 9}, true)
	require.Error(t, err)
}

// Re-admission after an agent restart runs after seeding, retries while ZDS
// cannot yet carry an ADD, and never fails or blocks reconciler start.
func TestRestoredRequiredEndpointsAreReadmittedAsynchronouslyWithRetry(t *testing.T) {
	r := &restoreRevalidator{failures: 2}
	ops := &EnrollmentReconciler{logger: hivetest.Logger(t), endpointRevalidators: []membership.EndpointRevalidator{r},
		restoreBackoff: time.Millisecond}
	ops.readmitRestoredRequired([]*endpoint.Endpoint{{ID: 9, K8sNamespace: "apps", K8sPodName: "server"}})
	require.Eventually(t, func() bool { return r.readmitted.Load() == 1 }, 5*time.Second, time.Millisecond)
	require.Equal(t, int32(3), r.attempts.Load(), "two failed attempts, then success, then no further attempts")
	ops.restoreWG.Wait()
}

// Stop cancels a re-admission that cannot succeed and joins it.
func TestReconcilerStopCancelsRestoredReadmission(t *testing.T) {
	r := &restoreRevalidator{failures: 1 << 30}
	ops := &EnrollmentReconciler{logger: hivetest.Logger(t), endpointRevalidators: []membership.EndpointRevalidator{r},
		restoreBackoff: time.Millisecond}
	ops.readmitRestoredRequired([]*endpoint.Endpoint{{ID: 9}})
	require.Eventually(t, func() bool { return r.attempts.Load() >= 2 }, 5*time.Second, time.Millisecond)
	ops.restoreCancel()
	done := make(chan struct{})
	go func() { ops.restoreWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("restored re-admission did not stop")
	}
	require.Zero(t, r.readmitted.Load())
}

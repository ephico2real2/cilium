// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package membership

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
)

func capturedTestMembership(t *testing.T) (*Registry, Reference) {
	t.Helper()
	r := NewRegistry(1)
	ref, err := r.Require("ns-uid", "pod-uid", 9, "/ns")
	require.NoError(t, err)
	generation, ok := r.BeginZDS(ref)
	require.True(t, ok)
	require.True(t, r.MarkCaptured(ref, generation))
	require.True(t, r.AcknowledgeZDS(ref, generation))
	return r, ref
}

// Address and effective-policy bookkeeping is not part of a Publication or a
// SourceSnapshot. If it advanced their revisions, every ADS acknowledgment
// would make the endpoint's published membership and the source record stale.
func TestADSEvidenceDoesNotAdvancePublicationOrSourceRevision(t *testing.T) {
	r, ref := capturedTestMembership(t)
	publication, ok := r.Publication(ref)
	require.True(t, ok)
	snapshot := r.SourceSnapshot()

	ads := r.BeginADSGeneration()
	address, ok := r.PublishAddress(ref, ads)
	require.True(t, ok)
	require.True(t, r.AcknowledgeAddress(ref, ads, address))
	version, ok := r.PublishPolicy(ref, ads, PolicyEvidence{WorkloadUID: "pod-uid", AddressVersion: address,
		Revision: "sha256:policy", BoundToWorkload: true, RequiresAuthenticatedPeer: true, DenyByDefault: true})
	require.True(t, ok)
	require.True(t, r.AcknowledgePolicy(ref, ads, version))
	state, _ := r.Get(ref)
	require.True(t, state.Active())

	after, ok := r.Publication(ref)
	require.True(t, ok)
	require.Equal(t, publication, after)
	require.Equal(t, snapshot.Revision, r.SourceSnapshot().Revision)
	require.NoError(t, r.PublishIfSourceSnapshotCurrent(snapshot, func() error { return nil }),
		"a source write fenced by the earlier snapshot stays valid across ADS bookkeeping")

	// A real capture change still advances both.
	_, ok = r.BeginZDS(ref)
	require.True(t, ok)
	changed, ok := r.Publication(ref)
	require.True(t, ok)
	require.Greater(t, changed.Revision, publication.Revision)
	require.ErrorIs(t, r.PublishIfSourceSnapshotCurrent(snapshot, func() error { return nil }), ErrSourcePublicationStale)
}

type ensuringRevalidator struct {
	stages    []string
	ensureErr error
}

func (r *ensuringRevalidator) ShouldRevalidate(context.Context, *endpoint.Endpoint, bool) (bool, error) {
	return true, nil
}
func (r *ensuringRevalidator) RestrictRestoredEndpoint(context.Context, *endpoint.Endpoint, bool) (bool, error) {
	return true, nil
}
func (r *ensuringRevalidator) EnsureEndpoint(_ context.Context, _ *endpoint.Endpoint, stage string) error {
	r.stages = append(r.stages, stage)
	return r.ensureErr
}

// A lease refresh asks every revalidator to ensure the endpoint is admitted,
// which re-admits only stale evidence (the gate's EnsureEndpoint tests cover
// that), and reports the first failure. No revalidator is never success.
func TestSourceRefreshEnsuresAdmissionThroughEveryRevalidator(t *testing.T) {
	ep := &endpoint.Endpoint{ID: 9}
	first, second := &ensuringRevalidator{}, &ensuringRevalidator{}
	require.NoError(t, ensureAdmitted(t.Context(), ep, []EndpointRevalidator{first, second}))
	require.Equal(t, []string{StageSourceVerification}, first.stages)
	require.Equal(t, []string{StageSourceVerification}, second.stages)

	failed := &ensuringRevalidator{ensureErr: errors.New("admission failed")}
	require.ErrorContains(t, ensureAdmitted(t.Context(), ep, []EndpointRevalidator{failed}), "admission failed")
	require.Error(t, ensureAdmitted(t.Context(), ep, nil), "no revalidator is never success")
	require.Error(t, ensureAdmitted(t.Context(), ep, []EndpointRevalidator{nil}), "a nil revalidator is never success")
}

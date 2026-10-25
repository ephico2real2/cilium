// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package membership

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/hive/hivetest"
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

type verifyFirstRevalidator struct {
	verifyErr   error
	verified    int
	readmitted  int
	readmitErr  error
	restricted  int
	shouldCheck int
}

func (r *verifyFirstRevalidator) ShouldRevalidate(context.Context, *endpoint.Endpoint, bool) (bool, error) {
	r.shouldCheck++
	return true, nil
}
func (r *verifyFirstRevalidator) RestrictRestoredEndpoint(context.Context, *endpoint.Endpoint, bool) (bool, error) {
	r.restricted++
	return true, nil
}
func (r *verifyFirstRevalidator) VerifyEndpoint(context.Context, *endpoint.Endpoint) error {
	r.verified++
	return r.verifyErr
}
func (r *verifyFirstRevalidator) RevalidateEndpoint(context.Context, *endpoint.Endpoint) error {
	r.readmitted++
	return r.readmitErr
}

// A lease refresh must not change a capture that still verifies; it re-admits
// only when verification fails, and reports the re-admission's own result.
func TestSourceRefreshVerifiesBeforeReadmitting(t *testing.T) {
	ep := &endpoint.Endpoint{ID: 9}
	current := &verifyFirstRevalidator{}
	require.NoError(t, verifyOrReadmit(t.Context(), ep, []EndpointRevalidator{current}, hivetest.Logger(t)))
	require.Equal(t, 1, current.verified)
	require.Zero(t, current.readmitted, "a current capture is never re-admitted by a refresh")

	stale := &verifyFirstRevalidator{verifyErr: errors.New("retained ADD belongs to an earlier ztunnel execution")}
	require.NoError(t, verifyOrReadmit(t.Context(), ep, []EndpointRevalidator{stale}, hivetest.Logger(t)))
	require.Equal(t, 1, stale.readmitted, "stale evidence is re-admitted")

	failed := &verifyFirstRevalidator{verifyErr: errors.New("stale"), readmitErr: errors.New("admission failed")}
	require.ErrorContains(t, verifyOrReadmit(t.Context(), ep, []EndpointRevalidator{failed}, hivetest.Logger(t)), "admission failed")
	require.Error(t, verifyOrReadmit(t.Context(), ep, nil, hivetest.Logger(t)), "no revalidator is never success")
}

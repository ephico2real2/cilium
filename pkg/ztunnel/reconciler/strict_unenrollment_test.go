// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ztunnel/table"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

func TestStrictNamespaceDeleteDefersLiveEndpointsWithoutDELOrXDSRemoval(t *testing.T) {
	db, _, manager, enroller, ops, events := setupTest(t)
	ops.strictCreationAdmission = true
	// No namespace intent table insertion: the desired record is already gone.
	// The guard must not depend on a stale name-only table entry or app labels.
	manager.Endpoints = []*endpoint.Endpoint{
		createTestEndpoint(91, "apps", "protected", "/owned/netns/protected"),
	}
	err := ops.Delete(context.Background(), db.ReadTxn(), 1, &table.EnrolledNamespace{Name: "apps"})
	require.ErrorIs(t, err, zds.ErrStrictLiveUnenrollment)
	require.Empty(t, enroller.disenrolledIDs)
	require.Empty(t, events, "no namespace-wide xDS REMOVED before active membership has drained")
}

func TestStrictNamespaceDeleteWithNoEndpointsCompletesWithoutNamespaceRemovalEvent(t *testing.T) {
	db, _, manager, enroller, ops, events := setupTest(t)
	ops.strictCreationAdmission = true
	manager.Endpoints = nil
	require.NoError(t, ops.Delete(context.Background(), db.ReadTxn(), 1, &table.EnrolledNamespace{Name: "apps"}))
	require.Empty(t, enroller.disenrolledIDs)
	require.Empty(t, events)
}

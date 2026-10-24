// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package table

import (
	"testing"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
)

func TestK8sNamespaceToEnrolledNamespacePreservesUID(t *testing.T) {
	tests := []struct {
		name       string
		namespace  k8sTables.Namespace
		deleted    bool
		wantResult statedb.DeriveResult
	}{
		{
			name: "enrolled namespace carries current UID",
			namespace: k8sTables.Namespace{
				Name: "orders", UID: "namespace-uid-a",
				Labels: map[string]string{"io.cilium/mtls-enabled": "true"},
			},
			wantResult: statedb.DeriveInsert,
		},
		{
			name: "empty UID is preserved as unknown",
			namespace: k8sTables.Namespace{
				Name:   "orders",
				Labels: map[string]string{"io.cilium/mtls-enabled": "true"},
			},
			wantResult: statedb.DeriveInsert,
		},
		{
			name: "delete preserves UID metadata",
			namespace: k8sTables.Namespace{
				Name: "orders", UID: "namespace-uid-a",
				Labels: map[string]string{"io.cilium/mtls-enabled": "true"},
			},
			deleted:    true,
			wantResult: statedb.DeriveDelete,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, result := K8sNamespaceToEnrolledNamespace(tt.namespace, tt.deleted)
			require.Equal(t, tt.wantResult, result)
			require.Equal(t, tt.namespace.Name, got.Name)
			require.Equal(t, tt.namespace.UID, got.UID)
			require.Equal(t, reconciler.StatusKindPending, got.Status.Kind,
				"namespace UID is metadata only and must not be presented as validation")
		})
	}
}

func TestEnrolledNamespaceClonePreservesUID(t *testing.T) {
	original := &EnrolledNamespace{
		Name: "orders", UID: "namespace-uid-a", Status: reconciler.StatusPending(),
	}

	clone := original.Clone()
	require.NotSame(t, original, clone)
	require.Equal(t, original.Name, clone.Name)
	require.Equal(t, original.UID, clone.UID)

	updated := clone.SetStatus(reconciler.StatusDone())
	require.Equal(t, original.UID, updated.UID,
		"reconciler status cloning must carry the namespace incarnation unchanged")
}

func TestEnrolledNamespaceNameIndexTracksRecreatedNamespace(t *testing.T) {
	db := statedb.New()
	tbl, err := NewEnrolledNamespacesTable(db)
	require.NoError(t, err)

	for _, uid := range []string{"namespace-uid-a", "namespace-uid-b"} {
		derived, result := K8sNamespaceToEnrolledNamespace(k8sTables.Namespace{
			Name: "orders", UID: uid,
			Labels: map[string]string{"io.cilium/mtls-enabled": "true"},
		}, false)
		require.Equal(t, statedb.DeriveInsert, result)

		txn := db.WriteTxn(tbl)
		_, _, err := tbl.Insert(txn, derived)
		require.NoError(t, err)
		txn.Commit()
	}

	got, _, found := tbl.Get(db.ReadTxn(), EnrolledNamespaceByName("orders"))
	require.True(t, found)
	require.Equal(t, "orders", got.Name)
	require.Equal(t, "namespace-uid-b", got.UID,
		"Name remains the lookup key while a same-name informer update replaces the UID")
}

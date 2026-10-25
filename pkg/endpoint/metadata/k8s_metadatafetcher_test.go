// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/option"
)

func nonPolicyConfig() *option.DaemonConfig {
	return &option.DaemonConfig{
		EnablePolicy:             option.NeverEnforce,
		DisableCiliumEndpointCRD: true,
		IdentityAllocationMode:   option.IdentityAllocationModeCRD,
	}
}

func TestIsPodStoreOutdatedForUID(t *testing.T) {
	storeUID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	otherUID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	tests := []struct {
		name string
		uid  string
		pod  *slim_corev1.Pod
		want bool
	}{
		{
			name: "empty uid never outdated",
			uid:  "",
			pod:  &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{UID: types.UID(storeUID)}},
			want: false,
		},
		{
			name: "uid match not outdated",
			uid:  storeUID,
			pod:  &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{UID: types.UID(storeUID)}},
			want: false,
		},
		{
			name: "uid mismatch without mirror annotation is outdated",
			uid:  otherUID,
			pod: &slim_corev1.Pod{
				ObjectMeta: slim_metav1.ObjectMeta{
					UID: types.UID(storeUID),
				},
			},
			want: true,
		},
		{
			name: "uid mismatch mirror pod not outdated",
			uid:  otherUID,
			pod: &slim_corev1.Pod{
				ObjectMeta: slim_metav1.ObjectMeta{
					UID: types.UID(storeUID),
					Annotations: map[string]string{
						corev1.MirrorPodAnnotationKey: otherUID,
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPodStoreOutdatedForUID(tt.uid, tt.pod)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFetchK8sMetadataCarriesNamespaceUID(t *testing.T) {
	require.NoError(t, labelsfilter.ParseLabelPrefixCfg(hivetest.Logger(t), nil, nil, ""))
	db := statedb.New()
	namespaces, err := k8sTables.NewNamespaceTable(db)
	require.NoError(t, err)
	txn := db.WriteTxn(namespaces)
	_, _, err = namespaces.Insert(txn, k8sTables.Namespace{Name: "orders", UID: "namespace-uid-a"})
	require.NoError(t, err)
	txn.Commit()

	fetcher := &cachedEndpointMetadataFetcher{
		logger:      hivetest.Logger(t),
		config:      &option.DaemonConfig{EnablePolicy: option.AlwaysEnforce},
		clusterInfo: cmtypes.DefaultClusterInfo,
		db:          db,
		namespaces:  namespaces,
	}
	metadata, err := fetcher.FetchK8sMetadataForEndpointFromPod(&slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{Namespace: "orders", Name: "api"},
	})
	require.NoError(t, err)
	require.Equal(t, "namespace-uid-a", metadata.NamespaceUID)

	txn = db.WriteTxn(namespaces)
	_, _, err = namespaces.Insert(txn, k8sTables.Namespace{Name: "orders", UID: "namespace-uid-b"})
	require.NoError(t, err)
	txn.Commit()
	metadata, err = fetcher.FetchK8sMetadataForEndpointFromPod(&slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{Namespace: "orders", Name: "api"},
	})
	require.NoError(t, err)
	require.Equal(t, "namespace-uid-b", metadata.NamespaceUID)

	// The non-policy path keeps the existing name-only identity labels while
	// reading the UID opportunistically from the initialized namespace table.
	fetcher.config = nonPolicyConfig()
	require.False(t, option.NetworkPolicyEnabled(fetcher.config), "fixture must exercise the non-policy path")
	metadata, err = fetcher.FetchK8sMetadataForEndpointFromPod(&slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{Namespace: "orders", Name: "api"},
	})
	require.NoError(t, err)
	require.Equal(t, "namespace-uid-b", metadata.NamespaceUID)
	require.Equal(t, []string{
		"k8s:io.cilium.k8s.policy.cluster=default",
		"k8s:io.kubernetes.pod.namespace=orders",
	}, metadata.IdentityLabels.GetModel())

	txn = db.WriteTxn(namespaces)
	_, _, err = namespaces.Delete(txn, k8sTables.Namespace{Name: "orders"})
	require.NoError(t, err)
	txn.Commit()
	metadata, err = fetcher.FetchK8sMetadataForEndpointFromPod(&slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{Namespace: "orders", Name: "api"},
	})
	require.NoError(t, err)
	require.Empty(t, metadata.NamespaceUID, "missing live namespace UID must not be synthesized")
}

func TestNonPolicyNamespaceUIDLookupDoesNotWaitForUninitializedTable(t *testing.T) {
	db := statedb.New()
	namespaces, err := k8sTables.NewNamespaceTable(db)
	require.NoError(t, err)
	txn := db.WriteTxn(namespaces)
	finishInitialization := namespaces.RegisterInitializer(txn, "test-pending-namespace-watch")
	txn.Commit()
	defer func() {
		txn := db.WriteTxn(namespaces)
		finishInitialization(txn)
		txn.Commit()
	}()

	fetcher := &cachedEndpointMetadataFetcher{
		logger:      hivetest.Logger(t),
		config:      nonPolicyConfig(),
		clusterInfo: cmtypes.DefaultClusterInfo,
		db:          db,
		namespaces:  namespaces,
	}
	require.False(t, option.NetworkPolicyEnabled(fetcher.config), "fixture must exercise the non-policy path")
	done := make(chan *endpoint.K8sMetadata, 1)
	go func() {
		metadata, _ := fetcher.FetchK8sMetadataForEndpointFromPod(&slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{Namespace: "orders", Name: "api"},
		})
		done <- metadata
	}()

	select {
	case metadata := <-done:
		require.Empty(t, metadata.NamespaceUID)
	case <-time.After(time.Second):
		t.Fatal("non-policy metadata lookup blocked waiting for a namespace watcher")
	}
}

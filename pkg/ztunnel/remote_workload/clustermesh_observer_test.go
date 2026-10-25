// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

type registeredWatchFunctions map[string]store.WSMFunc

func (m registeredWatchFunctions) Register(prefix string, fn store.WSMFunc) { m[prefix] = fn }
func (registeredWatchFunctions) Run(context.Context)                        {}

func TestClusterMeshObserverUsesPinnedOriginAlongsideCachedRouting(t *testing.T) {
	factory := &pairedWatchFactory{started: make(chan string, 1)}
	observer := &clusterMeshObserver{
		logger: slog.New(slog.DiscardHandler), cluster: "cluster-beta",
		storeFactory: factory,
		clusterInfo:  cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255},
		sink:         &recordingSink{}, enableZTunnel: true, enableSourceMembership: true,
		originConfigDirectory: t.TempDir(), originClientCommonName: "ztunnel-origin-reader",
		remoteClientFactory: common.RemoteClientFactoryFn(func(context.Context, *slog.Logger, string, kvstore.ExtraOptions) (kvstore.BackendOperations, chan error) {
			return nil, nil
		}),
	}
	manager := registeredWatchFunctions{}
	observer.Register(manager, nil, cmtypes.CiliumClusterConfig{
		ID: 17,
		Capabilities: cmtypes.CiliumClusterConfigCapabilities{
			Cached: true, WorkloadIdentityV1: true, ZtunnelMembershipV1: true,
		},
	})
	if _, ok := manager[ipcache.IPIdentitiesPath]; !ok {
		t.Fatal("observer did not register the independent direct-origin watch for a KVStoreMesh-routed peer")
	}
	if !observer.Status().Enabled {
		t.Fatal("observer should report that its direct-origin supervisor is registered")
	}
	if observer.originSession == nil || observer.originSession.Factory != factory || observer.joiner == nil {
		t.Fatal("observer did not retain its dedicated direct-origin session and source-join gate")
	}
	if observer.Status().Synced {
		t.Fatal("observer reported synchronization before either source watch completed")
	}
}

func TestClusterMeshObserverIsDisabledWithoutExplicitOptIn(t *testing.T) {
	manager := registeredWatchFunctions{}
	observer := &clusterMeshObserver{
		logger: slog.New(slog.DiscardHandler), cluster: "cluster-beta",
		storeFactory: &pairedWatchFactory{started: make(chan string, 1)},
		sink:         &recordingSink{}, enableZTunnel: true,
	}
	observer.Register(manager, nil, cmtypes.CiliumClusterConfig{ID: 17})
	if len(manager) != 0 {
		t.Fatalf("disabled-by-default observer registered %d source watches", len(manager))
	}
	if observer.Status().Enabled {
		t.Fatal("observer reported enabled without the explicit membership opt-in")
	}
}

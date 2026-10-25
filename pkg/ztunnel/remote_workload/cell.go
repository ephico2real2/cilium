// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/observer"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore/store"
	ztunnelconfig "github.com/cilium/cilium/pkg/ztunnel/config"
)

type cellParams struct {
	cell.In

	Logger              *slog.Logger
	StoreFactory        store.Factory
	ClusterInfo         cmtypes.ClusterInfo
	Config              ztunnelconfig.Config
	RemoteClientFactory common.RemoteClientFactoryFn `optional:"true"`
}

// Cell registers a native ClusterMesh observer factory. Each peer observer
// incarnation writes complete replacement snapshots into its own slot of the
// shared PeerSnapshotStore. Those snapshots are discovery state only; the xDS
// owner applies issuer-profile, deadline and collision authority before it
// projects any remote workload, and source membership alone does not
// authorize traffic. The same-cluster reader fills LocalSourceMailbox with
// the leased workloads of this cluster's other nodes, as sources only. This
// cell does not synthesize local APIWorkloads or modify endpoint/ipcache
// state.
var Cell = cell.Module(
	"ztunnel-remote-workloads",
	"Observe authenticated remote ClusterMesh workload identity snapshots",

	cell.Provide(NewPeerSnapshotStore),
	cell.Provide(newLocalSourceMailbox),
	cell.Invoke(registerLocalSourceReader),
	cell.Provide(func(params cellParams, store *PeerSnapshotStore) observer.FactoryOut {
		factory := NewClusterMeshObserverFactory(FactoryParams{
			Logger:                 params.Logger,
			StoreFactory:           params.StoreFactory,
			ClusterInfo:            params.ClusterInfo,
			SinkForCluster:         store.NewWriter,
			EnableZTunnel:          params.Config.EnableZTunnel,
			EnableSourceMembership: params.Config.EnableRemoteWorkloadMembership,
			OriginConfigDirectory:  params.Config.RemoteOriginConfigDirectory,
			OriginClientCommonName: params.Config.RemoteOriginClientCommonName,
			RemoteClientFactory:    params.RemoteClientFactory,
		})
		return observer.NewFactoryOut(factory)
	}),
)

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh/observer"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore/store"
	ztunnelconfig "github.com/cilium/cilium/pkg/ztunnel/config"
)

type cellParams struct {
	cell.In

	Logger       *slog.Logger
	StoreFactory store.Factory
	ClusterInfo  cmtypes.ClusterInfo
	Config       ztunnelconfig.Config
}

type sinkParams struct {
	cell.In

	Admission SnapshotAdmission `optional:"true"`
}

// Cell registers a native ClusterMesh observer factory. The only supplied
// sink is deny-by-default until a future integration provides authenticated
// remote enrollment, effective policy, and an xDS publisher. This cell does
// not synthesize local APIWorkloads or modify endpoint/ipcache state.
var Cell = cell.Module(
	"ztunnel-remote-workloads",
	"Observe authenticated remote ClusterMesh workload identity snapshots",

	cell.Provide(NewSnapshotMailbox),
	cell.Provide(func(mailbox *SnapshotMailbox, params sinkParams) SnapshotSink {
		return GatedSnapshotSink{Admission: params.Admission, Mailbox: mailbox}
	}),
	cell.Provide(func(params cellParams, sink SnapshotSink) observer.FactoryOut {
		factory := NewClusterMeshObserverFactory(FactoryParams{
			Logger:        params.Logger,
			StoreFactory:  params.StoreFactory,
			ClusterInfo:   params.ClusterInfo,
			Sink:          sink,
			EnableZTunnel: params.Config.EnableZTunnel,
		})
		return observer.NewFactoryOut(factory)
	}),
)

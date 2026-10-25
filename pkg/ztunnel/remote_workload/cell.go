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

type sinkParams struct {
	cell.In

	Admission SnapshotAdmission `optional:"true"`
}

// Cell registers a native ClusterMesh observer factory. The supplied sink
// remains deny-by-default until a later integration supplies remote policy
// admission and an xDS consumer. Source membership alone does not authorize or
// route a remote workload. This cell does not synthesize local APIWorkloads or
// modify endpoint/ipcache state.
var Cell = cell.Module(
	"ztunnel-remote-workloads",
	"Observe authenticated remote ClusterMesh workload identity snapshots",

	cell.Provide(NewSnapshotMailbox),
	cell.Provide(func(mailbox *SnapshotMailbox, params sinkParams) SnapshotSink {
		return GatedSnapshotSink{Admission: params.Admission, Mailbox: mailbox}
	}),
	cell.Provide(func(params cellParams, sink SnapshotSink) observer.FactoryOut {
		factory := NewClusterMeshObserverFactory(FactoryParams{
			Logger:                 params.Logger,
			StoreFactory:           params.StoreFactory,
			ClusterInfo:            params.ClusterInfo,
			Sink:                   sink,
			EnableZTunnel:          params.Config.EnableZTunnel,
			EnableSourceMembership: params.Config.EnableRemoteWorkloadMembership,
			OriginConfigDirectory:  params.Config.RemoteOriginConfigDirectory,
			OriginClientCommonName: params.Config.RemoteOriginClientCommonName,
			RemoteClientFactory:    params.RemoteClientFactory,
		})
		return observer.NewFactoryOut(factory)
	}),
)

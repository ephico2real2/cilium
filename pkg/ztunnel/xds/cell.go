// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	remote "github.com/cilium/cilium/pkg/ztunnel/remote_workload"
	"github.com/cilium/cilium/pkg/ztunnel/table"
)

var Cell = cell.Module(
	"ztunnel-xds",
	"ztunnel certificate authority and control plane",
	cell.Config(IssuerProfileProbeConfig{}),
	cell.Provide(newIssuerProfileSource),
	cell.Provide(NewServer),
	cell.Provide(func(x *Server) *AuthorizationPolicies {
		if x == nil {
			return nil
		}
		return x.authorizations
	}),
	cell.Provide(func(x *Server) chan *EndpointEvent {
		if x == nil {
			return nil
		}
		return x.endpointEventChan
	}),
	metrics.Metric(NewMetrics),
)

type xdsServerParams struct {
	cell.In

	Lifecycle  cell.Lifecycle
	DB         *statedb.DB
	Logger     *slog.Logger
	EPManager  endpointmanager.EndpointManager
	K8sWatcher *watchers.K8sWatcher
	Config     config.Config
	// ClusterInfo is Cilium's validated local identity. Name must match the
	// clusterId configured in ztunnel's workload inventory.
	ClusterInfo            cmtypes.ClusterInfo
	EnrolledNamespaceTable statedb.RWTable[*table.EnrolledNamespace]
	Metrics                *Metrics
	IssuerProfile          *issuerProfileSource
	// Nodes is Cilium's native node table (Kubernetes Node discovery).
	Nodes statedb.Table[*node.Node]
	// RemotePeers holds authenticated remote ClusterMesh workload snapshots.
	RemotePeers *remote.PeerSnapshotStore `optional:"true"`
}

func NewServer(params xdsServerParams) *Server {
	if !params.Config.EnableZTunnel {
		return nil
	}
	params.Metrics.Enable()

	server := newServer(
		params.Logger,
		params.DB,
		params.EPManager,
		params.K8sWatcher.GetK8sCiliumEndpointsWatcher(),
		params.EnrolledNamespaceTable,
		params.Config.EndpointEventChannelBufferSize,
		params.Metrics,
	)

	server.caType = params.Config.CAType
	server.trustDomain = params.Config.SpiffeTrustDomain
	server.clusterName = params.ClusterInfo.Name
	server.requireMTLS = params.Config.RequireMTLS
	server.effectivePolicyQuarantine = params.Config.EffectivePolicyQuarantine
	server.issuerProfile = params.IssuerProfile
	if names, err := newNativeNodeNames(params.DB, params.Nodes, params.ClusterInfo); err != nil {
		// Every Address response then fails closed; no IP fallback exists.
		params.Logger.Error("ztunnel xDS has no Kubernetes node discovery", logfields.Error, err)
	} else {
		server.nodeNames = names
	}

	// Remote workloads are projected only with explicit remote membership,
	// and only for peers whose trust domain the validated issuer profile
	// approves; without a profile every peer stays withdrawn.
	var stopTrust context.CancelFunc
	if params.Config.EnableRemoteWorkloadMembership && params.RemotePeers != nil {
		server.remotePeers = params.RemotePeers
		server.remoteTrust = newRemoteTrustAuthority(params.Logger, params.IssuerProfile, params.ClusterInfo.Name, params.Config.SpiffeTrustDomain)
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			if server.remoteTrust != nil {
				var ctx context.Context
				ctx, stopTrust = context.WithCancel(context.Background())
				go server.remoteTrust.run(ctx)
			}
			return server.Serve()
		},
		OnStop: func(_ cell.HookContext) error {
			if stopTrust != nil {
				stopTrust()
			}
			server.GracefulStop()
			return nil
		},
	})

	return server
}

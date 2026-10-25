// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/ztunnel/config"
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
	server.issuerProfile = params.IssuerProfile

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			return server.Serve()
		},
		OnStop: func(_ cell.HookContext) error {
			server.GracefulStop()
			return nil
		},
	})

	return server
}

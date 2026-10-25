// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/ztunnel/admission"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/reconciler"
	"github.com/cilium/cilium/pkg/ztunnel/remote_workload"
	"github.com/cilium/cilium/pkg/ztunnel/xds"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

// Cell starts ztunnel related control-plane components.
var Cell = cell.Module(
	"ztunnel",
	"ztunnel related control-plane components",
	cell.Config(config.DefaultConfig),
	cell.Invoke(validateConfig),

	// XDS control plane for ztunnel
	xds.Cell,
	remote_workload.Cell,

	// ZDS server for ztunnel
	zds.Cell,
	admission.Cell,
	reconciler.Cell,
)

type ztunnelParams struct {
	cell.In

	Config        config.Config
	IssuerProfile xds.IssuerProfileProbeConfig
	ClusterMesh   *clustermesh.ClusterMesh
}

func validateConfig(params ztunnelParams) error {
	if err := params.Config.Validate(); err != nil {
		return err
	}

	if !params.Config.EnableZTunnel {
		return nil
	}

	if params.ClusterMesh != nil {
		if err := clusterMeshCapability(params.Config, params.IssuerProfile); err != nil {
			return fmt.Errorf("ztunnel with clustermesh requires the native mesh runtime: %w", err)
		}
	}

	return nil
}

// clusterMeshCapability validates that every native owner a ClusterMesh
// deployment depends on is assembled. Remote workloads are reachable through
// ztunnel only when they are authenticated and projected (remote workload
// membership), bound to a trust domain approved by the issuer profile
// (issuer-profile pins), and verified as SPIRE identities; local workloads
// stay deny-by-default until their effective policy is compiled and
// acknowledged, which also gates their datapath release (effective policy
// quarantine with strict mTLS). Each owner fails closed at runtime: without
// a valid peer, profile or acknowledgment, remote workloads are withdrawn and
// local workloads stay quarantined.
func clusterMeshCapability(c config.Config, issuer xds.IssuerProfileProbeConfig) error {
	switch {
	case !c.RequireMTLS:
		return fmt.Errorf("ztunnel-require-mtls is required")
	case c.CAType != config.CATypeSpire:
		return fmt.Errorf("ztunnel-ca-type=spire is required")
	case !c.EffectivePolicyQuarantine:
		return fmt.Errorf("ztunnel-effective-policy-quarantine is required")
	case !c.EnableRemoteWorkloadMembership || c.RemoteOriginConfigDirectory == "" || c.RemoteOriginClientCommonName == "":
		return fmt.Errorf("authenticated remote workload membership with a direct-origin configuration directory is required")
	case issuer.IssuerProfileProbePins == "":
		return fmt.Errorf("ztunnel-issuer-profile-probe-pins is required")
	}
	return nil
}

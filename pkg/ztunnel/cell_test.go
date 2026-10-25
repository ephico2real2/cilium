// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/xds"
)

func assembledConfig() (config.Config, xds.IssuerProfileProbeConfig) {
	return config.Config{EnableZTunnel: true, RequireMTLS: true, CAType: config.CATypeSpire, EffectivePolicyQuarantine: true,
			EnableRemoteWorkloadMembership: true, RemoteOriginConfigDirectory: "/var/lib/cilium/ztunnel-origin",
			RemoteOriginClientCommonName: "ztunnel-origin-reader", SpiffeTrustDomain: "cmtc-a.mesh.example"},
		xds.IssuerProfileProbeConfig{IssuerProfileProbePins: "/var/lib/cilium/issuer-profile/pins.json"}
}

func TestClusterMeshRequiresTheAssembledNativeRuntime(t *testing.T) {
	mesh := &clustermesh.ClusterMesh{}
	c, pins := assembledConfig()
	require.NoError(t, validateConfig(ztunnelParams{Config: c, IssuerProfile: pins, ClusterMesh: mesh}))
	require.NoError(t, validateConfig(ztunnelParams{Config: c, IssuerProfile: pins}), "no ClusterMesh: unchanged")

	for name, mutate := range map[string]func(*config.Config, *xds.IssuerProfileProbeConfig){
		"no strict mTLS": func(c *config.Config, _ *xds.IssuerProfileProbeConfig) {
			c.RequireMTLS, c.EffectivePolicyQuarantine, c.EnableRemoteWorkloadMembership = false, false, false
		},
		"internal CA":         func(c *config.Config, _ *xds.IssuerProfileProbeConfig) { c.CAType = config.CATypeInternal },
		"no effective policy": func(c *config.Config, _ *xds.IssuerProfileProbeConfig) { c.EffectivePolicyQuarantine = false },
		"no remote membership": func(c *config.Config, _ *xds.IssuerProfileProbeConfig) {
			c.EnableRemoteWorkloadMembership, c.RemoteOriginConfigDirectory = false, ""
		},
		"no issuer profile": func(_ *config.Config, p *xds.IssuerProfileProbeConfig) { p.IssuerProfileProbePins = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c, pins := assembledConfig()
			mutate(&c, &pins)
			err := validateConfig(ztunnelParams{Config: c, IssuerProfile: pins, ClusterMesh: mesh})
			require.Error(t, err, "a missing native owner keeps ztunnel and ClusterMesh incompatible")
		})
	}

	disabled := config.Config{CAType: config.CATypeInternal, SpiffeTrustDomain: "cluster.local"}
	require.NoError(t, validateConfig(ztunnelParams{Config: disabled, ClusterMesh: mesh}), "ztunnel disabled: ClusterMesh unaffected")
}

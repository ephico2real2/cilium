// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func TestCABackendConfiguration(t *testing.T) {
	for _, backend := range []string{CATypeInternal, CATypeSpire} {
		t.Run(backend, func(t *testing.T) {
			cfg := DefaultConfig
			cfg.EnableZTunnel = true
			cfg.CAType = backend
			require.NoError(t, cfg.Validate())
		})
	}
	cfg := DefaultConfig
	cfg.EnableZTunnel = true
	cfg.CAType = "unrecognized"
	require.ErrorContains(t, cfg.Validate(), "unsupported ztunnel-ca-type")
	cfg.CAType = CATypeSpire
	cfg.EndpointEventChannelBufferSize = -1
	require.ErrorContains(t, cfg.Validate(), "must be non-negative")

	flags := pflag.NewFlagSet("ztunnel", pflag.ContinueOnError)
	DefaultConfig.Flags(flags)
	require.NoError(t, flags.Parse([]string{"--enable-ztunnel", "--ztunnel-ca-type=spire"}))
	backend, err := flags.GetString("ztunnel-ca-type")
	require.NoError(t, err)
	require.Equal(t, CATypeSpire, backend)
}

func TestRejectInvalidWorkloadTrustDomain(t *testing.T) {
	for _, domain := range []string{"", "https://example.test", "spiffe://example.test", "example.test/path"} {
		t.Run(domain, func(t *testing.T) {
			cfg := DefaultConfig
			cfg.EnableZTunnel = true
			cfg.SpiffeTrustDomain = domain
			require.ErrorContains(t, cfg.Validate(), "invalid mesh-auth-spiffe-trust-domain")
		})
	}
}

func TestRequireMTLSConfiguration(t *testing.T) {
	cfg := DefaultConfig
	require.False(t, cfg.RequireMTLS)
	cfg.RequireMTLS = true
	require.ErrorContains(t, cfg.Validate(), "requires enable-ztunnel")
	cfg.EnableZTunnel = true
	require.NoError(t, cfg.Validate())

	flags := pflag.NewFlagSet("ztunnel", pflag.ContinueOnError)
	DefaultConfig.Flags(flags)
	require.NoError(t, flags.Parse([]string{"--ztunnel-require-mtls"}))
	enabled, err := flags.GetBool("ztunnel-require-mtls")
	require.NoError(t, err)
	require.True(t, enabled)
}

func TestRemoteWorkloadMembershipIsOptInAndRequiresStrictMTLS(t *testing.T) {
	cfg := DefaultConfig
	require.Equal(t, "ztunnel-origin-reader", cfg.RemoteOriginClientCommonName)
	require.False(t, cfg.EnableRemoteWorkloadMembership)
	cfg.EnableRemoteWorkloadMembership = true
	require.ErrorContains(t, cfg.Validate(), "requires enabled ztunnel and strict mTLS")
	cfg.EnableZTunnel = true
	require.ErrorContains(t, cfg.Validate(), "requires enabled ztunnel and strict mTLS")
	cfg.RequireMTLS = true
	require.ErrorContains(t, cfg.Validate(), "requires ztunnel-remote-origin-config-dir")
	cfg.RemoteOriginConfigDirectory = t.TempDir()
	require.NoError(t, cfg.Validate())

	flags := pflag.NewFlagSet("ztunnel", pflag.ContinueOnError)
	DefaultConfig.Flags(flags)
	require.NoError(t, flags.Parse(nil))
	enabled, err := flags.GetBool("ztunnel-enable-remote-workload-membership")
	require.NoError(t, err)
	require.False(t, enabled)
}

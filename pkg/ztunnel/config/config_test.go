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

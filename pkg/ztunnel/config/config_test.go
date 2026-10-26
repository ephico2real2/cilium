// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/labels"
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
	cfg.SourceMembershipEtcdConfig = "relative/etcd.yaml"
	require.ErrorContains(t, cfg.Validate(), "requires remote workload membership and an absolute path")
	cfg.SourceMembershipEtcdConfig = "/var/lib/cilium/ztunnel-membership/etcd.yaml"
	require.NoError(t, cfg.Validate())
	cfg.EnableRemoteWorkloadMembership = false
	require.ErrorContains(t, cfg.Validate(), "requires remote workload membership and an absolute path")
	cfg.EnableRemoteWorkloadMembership = true

	flags := pflag.NewFlagSet("ztunnel", pflag.ContinueOnError)
	DefaultConfig.Flags(flags)
	require.NoError(t, flags.Parse(nil))
	enabled, err := flags.GetBool("ztunnel-enable-remote-workload-membership")
	require.NoError(t, err)
	require.False(t, enabled)
}

func TestDNSResolverLabels(t *testing.T) {
	cfg := DefaultConfig
	require.Empty(t, cfg.DNSResolverLabels, "no resolver is approved by default")
	sel, err := cfg.DNSResolverSelector()
	require.NoError(t, err)
	require.Empty(t, sel)

	cfg.DNSResolverLabels = []string{"k8s:io.kubernetes.pod.namespace=kube-system"}
	require.ErrorContains(t, cfg.Validate(), "requires enable-ztunnel")
	cfg.EnableZTunnel = true
	require.NoError(t, cfg.Validate())

	for name, entries := range map[string][]string{
		"no source":           {"io.kubernetes.pod.namespace=kube-system"},
		"other source":        {"any:io.kubernetes.pod.namespace=kube-system"},
		"no value":            {"k8s:io.kubernetes.pod.namespace", "k8s:k8s-app=kube-dns"},
		"empty value":         {"k8s:io.kubernetes.pod.namespace=", "k8s:k8s-app=kube-dns"},
		"no namespace":        {"k8s:k8s-app=kube-dns"},
		"duplicate key":       {"k8s:io.kubernetes.pod.namespace=kube-system", "k8s:io.kubernetes.pod.namespace=default"},
		"cluster label":       {"k8s:io.kubernetes.pod.namespace=kube-system", "k8s:io.cilium.k8s.policy.cluster=cmtc-a"},
		"empty entry":         {"k8s:io.kubernetes.pod.namespace=kube-system", ""},
		"reserved identity":   {"reserved:host"},
		"namespace via other": {"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=kube-system"},
	} {
		t.Run(name, func(t *testing.T) {
			c := cfg
			c.DNSResolverLabels = entries
			require.Error(t, c.Validate())
		})
	}

	// The ConfigMap form: one comma-separated string.
	var parsed Config
	h := hive.New(
		cell.Config(DefaultConfig),
		cell.Invoke(func(c Config) { parsed = c }),
	)
	h.Viper().Set("enable-ztunnel", true)
	h.Viper().Set("ztunnel-dns-resolver-labels",
		"k8s:io.kubernetes.pod.namespace=kube-system,k8s:k8s-app=kube-dns,k8s:io.cilium.k8s.policy.serviceaccount=coredns")
	require.NoError(t, h.Populate(hivetest.Logger(t)))
	require.NoError(t, parsed.Validate())
	sel, err = parsed.DNSResolverSelector()
	require.NoError(t, err)
	require.Equal(t, []labels.Label{
		labels.NewLabel("io.kubernetes.pod.namespace", "kube-system", labels.LabelSourceK8s),
		labels.NewLabel("k8s-app", "kube-dns", labels.LabelSourceK8s),
		labels.NewLabel("io.cilium.k8s.policy.serviceaccount", "coredns", labels.LabelSourceK8s),
	}, sel)
}

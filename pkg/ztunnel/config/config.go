// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

const (
	CATypeInternal = "internal"
	CATypeSpire    = "spire"
)

var DefaultConfig = Config{
	EnableZTunnel:                  false,
	CAType:                         CATypeInternal,
	SpiffeTrustDomain:              "cluster.local",
	RemoteOriginClientCommonName:   "ztunnel-origin-reader",
	EndpointEventChannelBufferSize: 1,
}

// Config is a shared config for all ZTunnel module's cells.
// Note: The operator reads EnableZTunnel directly from the ConfigMap,
// while the agent uses this Config struct for dependency injection.
type Config struct {
	EnableZTunnel                  bool
	RequireMTLS                    bool   `mapstructure:"ztunnel-require-mtls"`
	EffectivePolicyQuarantine      bool   `mapstructure:"ztunnel-effective-policy-quarantine"`
	EnableRemoteWorkloadMembership bool   `mapstructure:"ztunnel-enable-remote-workload-membership"`
	RemoteOriginConfigDirectory    string `mapstructure:"ztunnel-remote-origin-config-dir"`
	RemoteOriginClientCommonName   string `mapstructure:"ztunnel-remote-origin-client-common-name"`
	SourceMembershipEtcdConfig     string `mapstructure:"ztunnel-source-membership-etcd-config"`
	CAType                         string `mapstructure:"ztunnel-ca-type"`
	SpiffeTrustDomain              string `mapstructure:"mesh-auth-spiffe-trust-domain"`
	EndpointEventChannelBufferSize int    `mapstructure:"ztunnel-endpoint-event-channel-buffer-size"`
	// DNSResolverLabels approves the DNS resolvers that HBONE-only endpoints
	// may query in plaintext (UDP/TCP 53): every cluster-wide identity of the
	// local cluster that carries all of these labels. Empty approves none.
	DNSResolverLabels []string `mapstructure:"ztunnel-dns-resolver-labels"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
	flags.Bool("ztunnel-effective-policy-quarantine", false, "Experimental: bind explicit deny-by-default policy quarantine to every native workload; no effective policy activation")
	flags.Bool("ztunnel-require-mtls", false, "Experimental: require an authenticated peer for inbound ztunnel workload TCP connections")
	flags.Bool("ztunnel-enable-remote-workload-membership", false, "Experimental: publish and consume short-lived, directly authenticated remote workload membership; does not enable remote authorization or traffic")
	flags.String("ztunnel-remote-origin-config-dir", "", "Read-only directory containing per-peer direct ClusterMesh origin etcd configs for remote workload membership")
	flags.String("ztunnel-remote-origin-client-common-name", "ztunnel-origin-reader", "Expected common name of the dedicated read-only direct-origin etcd client certificate")
	flags.String("ztunnel-source-membership-etcd-config", "", "etcd client config of the dedicated connection that publishes this node's source membership; the global kvstore stays disabled")
	flags.String("mesh-auth-spiffe-trust-domain", "cluster.local", "SPIFFE trust domain for ztunnel workloads")
	flags.String("ztunnel-ca-type", CATypeInternal, "Workload CA backend: internal or spire")
	flags.Int("ztunnel-endpoint-event-channel-buffer-size", 1, "Buffer size for the ztunnel endpoint event channel")
	flags.MarkHidden("ztunnel-endpoint-event-channel-buffer-size")
	flags.StringSlice("ztunnel-dns-resolver-labels", nil, "Labels (k8s:key=value, one of them the Pod namespace) of the approved DNS resolver identities that HBONE-only endpoints may query on UDP/TCP 53; empty approves none")
}

func (c Config) Validate() error {
	if c.EffectivePolicyQuarantine && (!c.EnableZTunnel || !c.RequireMTLS) {
		return fmt.Errorf("native effective policy quarantine requires enabled ztunnel and strict mTLS")
	}
	if c.EnableRemoteWorkloadMembership && (!c.EnableZTunnel || !c.RequireMTLS) {
		return fmt.Errorf("remote workload membership requires enabled ztunnel and strict mTLS")
	}
	if c.EnableRemoteWorkloadMembership && c.RemoteOriginConfigDirectory == "" {
		return fmt.Errorf("remote workload membership requires ztunnel-remote-origin-config-dir")
	}
	if c.EnableRemoteWorkloadMembership && c.RemoteOriginClientCommonName == "" {
		return fmt.Errorf("remote workload membership requires ztunnel-remote-origin-client-common-name")
	}
	if c.SourceMembershipEtcdConfig != "" && (!c.EnableRemoteWorkloadMembership || !filepath.IsAbs(c.SourceMembershipEtcdConfig)) {
		return fmt.Errorf("ztunnel-source-membership-etcd-config requires remote workload membership and an absolute path")
	}
	if c.RequireMTLS && !c.EnableZTunnel {
		return fmt.Errorf("ztunnel-require-mtls requires enable-ztunnel")
	}
	if c.EnableZTunnel && c.CAType != CATypeInternal && c.CAType != CATypeSpire {
		return fmt.Errorf("unsupported ztunnel-ca-type %q: expected internal or spire", c.CAType)
	}
	if c.EnableZTunnel {
		td, err := spiffeid.TrustDomainFromString(c.SpiffeTrustDomain)
		if err != nil || td.String() != c.SpiffeTrustDomain {
			return fmt.Errorf("invalid mesh-auth-spiffe-trust-domain %q", c.SpiffeTrustDomain)
		}
	}
	if c.EndpointEventChannelBufferSize < 0 {
		return fmt.Errorf("ztunnel-endpoint-event-channel-buffer-size must be non-negative, got %d", c.EndpointEventChannelBufferSize)
	}
	if len(c.DNSResolverLabels) > 0 && !c.EnableZTunnel {
		return fmt.Errorf("ztunnel-dns-resolver-labels requires enable-ztunnel")
	}
	if _, err := c.DNSResolverSelector(); err != nil {
		return err
	}
	return nil
}

// DNSResolverSelector parses DNSResolverLabels. Every label is an exact
// "k8s:key=value"; one of them must name the Pod namespace, so a label common
// to many namespaces cannot approve resolvers everywhere. The cluster label is
// rejected: resolvers are always identities of the local cluster.
func (c Config) DNSResolverSelector() ([]labels.Label, error) {
	selector := make([]labels.Label, 0, len(c.DNSResolverLabels))
	keys := make(map[string]struct{}, len(c.DNSResolverLabels))
	for _, raw := range c.DNSResolverLabels {
		raw = strings.TrimSpace(raw)
		lbl := labels.ParseLabel(raw)
		if !strings.HasPrefix(raw, labels.LabelSourceK8sKeyPrefix) || lbl.Key == "" || lbl.Value == "" {
			return nil, fmt.Errorf("invalid ztunnel-dns-resolver-labels entry %q: expected k8s:key=value", raw)
		}
		if lbl.Key == k8sConst.PolicyLabelCluster {
			return nil, fmt.Errorf("ztunnel-dns-resolver-labels must not name a cluster: resolvers are local-cluster identities")
		}
		if _, dup := keys[lbl.Key]; dup {
			return nil, fmt.Errorf("ztunnel-dns-resolver-labels names key %q twice", lbl.Key)
		}
		keys[lbl.Key] = struct{}{}
		selector = append(selector, lbl)
	}
	if _, ok := keys[k8sConst.PodNamespaceLabel]; len(selector) > 0 && !ok {
		return nil, fmt.Errorf("ztunnel-dns-resolver-labels must include k8s:%s=<namespace>", k8sConst.PodNamespaceLabel)
	}
	return selector, nil
}

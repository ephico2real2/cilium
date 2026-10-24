// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"fmt"

	"github.com/spf13/pflag"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	CATypeInternal = "internal"
	CATypeSpire    = "spire"
)

var DefaultConfig = Config{
	EnableZTunnel:                  false,
	CAType:                         CATypeInternal,
	SpiffeTrustDomain:              "cluster.local",
	EndpointEventChannelBufferSize: 1,
}

// Config is a shared config for all ZTunnel module's cells.
// Note: The operator reads EnableZTunnel directly from the ConfigMap,
// while the agent uses this Config struct for dependency injection.
type Config struct {
	EnableZTunnel                  bool
	CAType                         string `mapstructure:"ztunnel-ca-type"`
	SpiffeTrustDomain              string `mapstructure:"mesh-auth-spiffe-trust-domain"`
	EndpointEventChannelBufferSize int    `mapstructure:"ztunnel-endpoint-event-channel-buffer-size"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
	flags.String("mesh-auth-spiffe-trust-domain", "cluster.local", "SPIFFE trust domain for ztunnel workloads")
	flags.String("ztunnel-ca-type", CATypeInternal, "Workload CA backend: internal or spire")
	flags.Int("ztunnel-endpoint-event-channel-buffer-size", 1, "Buffer size for the ztunnel endpoint event channel")
	flags.MarkHidden("ztunnel-endpoint-event-channel-buffer-size")
}

func (c Config) Validate() error {
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
	return nil
}

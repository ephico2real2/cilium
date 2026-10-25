// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

// CAType identifies the CA backend ztunnel uses to issue workload identities.
type CAType string

const (
	// CATypeSpire indicates ztunnel uses an external SPIRE server as its CA.
	// In this mode the operator manages SPIRE entries for enrolled namespaces.
	CATypeSpire CAType = "spire"
	// CATypeInternal indicates ztunnel uses Cilium's built-in CA, with no SPIRE
	// dependency. The operator does not run the SPIRE enrollment reconciler.
	CATypeInternal CAType = "internal"
)

var DefaultConfig = Config{
	EnableZTunnel: false,
	CAType:        CATypeInternal,
}

type Config struct {
	EnableZTunnel          bool
	ExternalExactRegistrar bool   `mapstructure:"ztunnel-spire-external-exact-registrar"`
	CAType                 CAType `mapstructure:"ztunnel-ca-type"`
}

// UseSpireCA reports whether ztunnel is enabled and configured to use an
// external SPIRE server as its CA.
func (c Config) UseSpireCA() bool {
	return c.EnableZTunnel && c.CAType == CATypeSpire
}

// Validate rejects a registrar selection without the corresponding external CA.
func (c Config) Validate() error {
	if c.ExternalExactRegistrar && !c.UseSpireCA() {
		return fmt.Errorf("external exact SPIRE registrar requires enabled ztunnel with SPIRE CA")
	}
	return nil
}

// UseLegacySpireEnrollment is false when exact server-local registration owns
// entries. Cilium then receives no SPIRE management identity or client.
func (c Config) UseLegacySpireEnrollment() bool {
	return c.UseSpireCA() && !c.ExternalExactRegistrar
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("ztunnel-spire-external-exact-registrar", false, "Use an independently qualified exact server-local registrar; disable operator SPIRE management and broad namespace registration")
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
	flags.String("ztunnel-ca-type", string(CATypeInternal),
		"CA backend used by ztunnel: 'spire' (external SPIRE server) or 'internal' (Cilium-managed CA)")
}

// SpiffeIDPathFunc returns the SPIFFE ID path in the form of /ns/{namespace}/sa/{serviceaccount}
func SpiffeIDPathFunc(namespacedname string) string {
	parts := strings.Split(namespacedname, "/")
	if len(parts) != 2 {
		return ""
	}
	return fmt.Sprintf("/ns/%s/sa/%s", parts[0], parts[1])
}

// SpiffeIDSelectorsFunc returns the SPIFFE ID selectors for a given service account's namespaced name.
// The selectors are in the form of:
//
//	{Type: "k8s", Value: "ns:<namespace>"}
//	{Type: "k8s", Value: "sa:<serviceaccount>"}
func SpiffeIDSelectorsFunc(namespacedname string) []*types.Selector {
	parts := strings.Split(namespacedname, "/")
	if len(parts) != 2 {
		return nil
	}
	return []*types.Selector{
		{
			Type:  "k8s",
			Value: "ns:" + parts[0],
		},
		{
			Type:  "k8s",
			Value: "sa:" + parts[1],
		},
	}
}

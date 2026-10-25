// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package spire

import (
	"testing"

	ztunnel "github.com/cilium/cilium/operator/pkg/ztunnel/config"
)

func TestExternalRegistrarDoesNotCreateSPIREManagementClient(t *testing.T) {
	// Every other dependency is deliberately nil: returning a client or creating
	// the management job would attempt the old bootstrap or panic.
	if client := NewClient(params{ZtunnelConfig: ztunnel.Config{EnableZTunnel: true, CAType: ztunnel.CATypeSpire, ExternalExactRegistrar: true}}); client != nil {
		t.Fatal("external registrar started a SPIRE management client")
	}
}

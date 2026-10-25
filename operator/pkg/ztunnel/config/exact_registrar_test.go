// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package config

import "testing"

func TestExternalExactRegistrarDisablesLegacySPIREManagement(t *testing.T) {
	for _, tc := range []struct {
		enabled  bool
		ca       CAType
		external bool
		want     bool
	}{
		{false, CATypeSpire, false, false}, {true, CATypeInternal, false, false}, {true, CATypeSpire, false, true}, {true, CATypeSpire, true, false},
	} {
		c := Config{EnableZTunnel: tc.enabled, CAType: tc.ca, ExternalExactRegistrar: tc.external}
		if c.UseLegacySpireEnrollment() != tc.want {
			t.Fatalf("unexpected legacy registration mode: %+v", c)
		}
		if tc.external && !c.UseSpireCA() {
			t.Fatal("external registration must not change CA selection")
		}
	}
}

func TestExternalExactRegistrarRequiresSPIRECA(t *testing.T) {
	for _, c := range []Config{{ExternalExactRegistrar: true}, {EnableZTunnel: true, CAType: CATypeInternal, ExternalExactRegistrar: true}} {
		if c.Validate() == nil {
			t.Fatal("unsupported external registrar mode accepted")
		}
	}
	if err := (Config{EnableZTunnel: true, CAType: CATypeSpire, ExternalExactRegistrar: true}).Validate(); err != nil {
		t.Fatal(err)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"strings"
	"testing"

	client "go.etcd.io/etcd/client/v3"

	"github.com/cilium/cilium/pkg/time"
)

type testLeaseTTLWriter struct{}

func (testLeaseTTLWriter) UpdateWithLeaseTTLIfLocked(context.Context, string, []byte, time.Duration, KVLocker) error {
	return nil
}

func TestLeaseTTLWriterForChecksSelectedBackendCapability(t *testing.T) {
	unsupported := &clientImpl{BackendOperations: &inMemoryClient{}}
	if writer, ok := LeaseTTLWriterFor(unsupported); ok || writer != nil {
		t.Fatal("wrapper exposed a short-lease capability unsupported by its backend")
	}

	supportedBackend := struct {
		BackendOperations
		LeaseTTLWriter
	}{BackendOperations: &inMemoryClient{}, LeaseTTLWriter: testLeaseTTLWriter{}}
	supported := &clientImpl{BackendOperations: supportedBackend}
	if writer, ok := LeaseTTLWriterFor(supported); !ok || writer == nil {
		t.Fatal("selected backend with explicit short leases was not detected")
	}
	if writer, ok := LeaseTTLWriterFor(nil); ok || writer != nil {
		t.Fatal("nil client exposed short-lease capability")
	}
}

func TestStandaloneClientReportsOnlyItsBackendCapability(t *testing.T) {
	if StandaloneClient(nil).IsEnabled() {
		t.Fatal("standalone client without a backend is enabled")
	}
	plain := StandaloneClient(&inMemoryClient{})
	if !plain.IsEnabled() {
		t.Fatal("standalone client with a backend is disabled")
	}
	if writer, ok := LeaseTTLWriterFor(plain); ok || writer != nil {
		t.Fatal("standalone wrapper exposed a short-lease capability its backend lacks")
	}
	capable := StandaloneClient(struct {
		BackendOperations
		LeaseTTLWriter
	}{BackendOperations: &inMemoryClient{}, LeaseTTLWriter: testLeaseTTLWriter{}})
	if writer, ok := LeaseTTLWriterFor(capable); !ok || writer == nil {
		t.Fatal("standalone wrapper hid the short-lease capability of its backend")
	}
}

func TestLeaseTTLWriteHeadHasSeparateStableNamespace(t *testing.T) {
	key := "cilium/state/ztunnel/membership/v1/agents/node-a"
	head := leaseTTLWriteHead(key)
	if head != leaseTTLWriteHead(key) || head == leaseTTLWriteHead(key+"-other") {
		t.Fatal("server write head is not stable and key-specific")
	}
	if strings.HasPrefix(head, "cilium/state/ztunnel/membership/v1/agents/") ||
		!strings.HasPrefix(head, StatePrefix+"/lease-ttl-write-heads/v1/") {
		t.Fatal("persistent write head overlaps the source record watch prefix")
	}
}

func TestLeaseTTLGrantRequiresExactBound(t *testing.T) {
	for _, tc := range []struct {
		name  string
		grant *client.LeaseGrantResponse
		valid bool
	}{
		{name: "missing"},
		{name: "missing-id", grant: &client.LeaseGrantResponse{TTL: 30}},
		{name: "shorter", grant: &client.LeaseGrantResponse{ID: 1, TTL: 29}},
		{name: "longer", grant: &client.LeaseGrantResponse{ID: 1, TTL: 31}},
		{name: "exact", grant: &client.LeaseGrantResponse{ID: 1, TTL: 30}, valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateLeaseTTLGrant(tc.grant, 30*time.Second); (err == nil) != tc.valid {
				t.Fatalf("grant validation result %v, expected valid=%v", err, tc.valid)
			}
		})
	}
}

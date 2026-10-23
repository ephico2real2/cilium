// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package security_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	workloadpb "github.com/cilium/cilium/pkg/ztunnel/pb"
	securitypb "github.com/cilium/cilium/pkg/ztunnel/pb/security"
)

func TestSchemaMatchesPinnedProxySource(t *testing.T) {
	source, err := os.ReadFile("authorization_ztunnel.proto")
	if err != nil {
		t.Fatal(err)
	}
	var pin struct {
		SHA256 string `json:"sha256"`
	}
	pinned, err := os.ReadFile("testdata/proxy-source.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(pinned, &pin); err != nil {
		t.Fatal(err)
	}
	// These are the only allowed changes from the proxy's source schema.
	normalized := strings.ReplaceAll(string(source), "option go_package=\"github.com/cilium/cilium/pkg/ztunnel/pb/security\";", "option go_package=\"pkg/workloadapi/security\";")
	normalized = strings.ReplaceAll(normalized, "// Cilium changes only go_package. Pinned source and wire contract: SOURCE.md.\n", "")
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(normalized))); got != pin.SHA256 {
		t.Fatalf("authorization schema differs from the selected proxy source: %s != %s", got, pin.SHA256)
	}
}

func TestAuthorizationDescriptorShape(t *testing.T) {
	if got := (&securitypb.Authorization{}).ProtoReflect().Descriptor().FullName(); got != "istio.security.Authorization" {
		t.Fatalf("unexpected authorization message: %s", got)
	}
	for _, tc := range []struct {
		message proto.Message
		field   protoreflect.Name
		number  protoreflect.FieldNumber
	}{
		{&securitypb.Authorization{}, "rules", 5},
		{&securitypb.Authorization{}, "dry_run", 6},
		{&securitypb.Rule{}, "clauses", 1},
		{&securitypb.Clause{}, "matches", 2},
		{&securitypb.Match{}, "principals", 3},
		{&securitypb.Match{}, "destination_ports", 9},
		{&securitypb.Match{}, "service_accounts", 11},
		{&securitypb.Match{}, "not_service_accounts", 12},
		{&securitypb.StringMatch{}, "presence", 4},
	} {
		desc := tc.message.ProtoReflect().Descriptor()
		field := desc.Fields().ByName(tc.field)
		if field == nil || field.Number() != tc.number {
			t.Errorf("%s.%s does not use field %d", desc.FullName(), tc.field, tc.number)
		}
	}
	if (&securitypb.Authorization{}).ProtoReflect().Descriptor().Fields().ByName("groups") != nil {
		t.Fatal("newer Istio groups schema must not replace the pinned rules schema")
	}
}

func TestIndependentAllowPolicyFixture(t *testing.T) {
	fixture, err := os.ReadFile("testdata/allow-pos-v1.hex")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := hex.DecodeString(strings.TrimSpace(string(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	var policy securitypb.Authorization
	if err := proto.Unmarshal(wire, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Name != "allow-pos" || policy.Namespace != "shop" || policy.Scope != securitypb.Scope_WORKLOAD_SELECTOR || policy.Action != securitypb.Action_ALLOW {
		t.Fatalf("incorrect decoded authorization: %v", &policy)
	}
	if len(policy.Rules) != 1 || len(policy.Rules[0].Clauses) != 1 || len(policy.Rules[0].Clauses[0].Matches) != 1 {
		t.Fatalf("incorrect rule/clause/match shape: %v", &policy)
	}
	match := policy.Rules[0].Clauses[0].Matches[0]
	if len(match.Principals) != 1 || match.Principals[0].GetExact() != "cluster-a.example/ns/shop/sa/pos" {
		t.Fatalf("incorrect exact principal: %v", match.Principals)
	}
	if len(match.DestinationPorts) != 1 || match.DestinationPorts[0] != 80 {
		t.Fatalf("expected application port 80, not the tunnel port: %v", match.DestinationPorts)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&policy)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encoded) != hex.EncodeToString(wire) {
		t.Fatal("generated serializer changed the independent fixture encoding")
	}
	envelope, err := anypb.New(&policy)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.TypeUrl != "type.googleapis.com/istio.security.Authorization" {
		t.Fatalf("incorrect xDS type URL: %s", envelope.TypeUrl)
	}
	resolved, err := envelope.UnmarshalNew()
	if err != nil || !proto.Equal(resolved, &policy) {
		t.Fatalf("registered Any round trip failed: %v", err)
	}
}

func TestDenyPresenceAndJSONRoundTrip(t *testing.T) {
	policy := &securitypb.Authorization{
		Name: "require-authenticated-principal", Scope: securitypb.Scope_GLOBAL, Action: securitypb.Action_DENY,
		Rules: []*securitypb.Rule{{Clauses: []*securitypb.Clause{{Matches: []*securitypb.Match{{
			NotPrincipals: []*securitypb.StringMatch{{MatchType: &securitypb.StringMatch_Presence{Presence: &emptypb.Empty{}}}},
		}}}}}},
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var decoded securitypb.Authorization
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(policy, &decoded) {
		t.Fatal("JSON binding lost DENY, presence oneof or rule nesting")
	}
}

func TestWorkloadAndSecurityAddressesRemainDistinct(t *testing.T) {
	workload := (&workloadpb.Address{}).ProtoReflect().Descriptor().FullName()
	network := (&securitypb.Address{}).ProtoReflect().Descriptor().FullName()
	if workload != "istio.workload.Address" || network != "istio.security.Address" || workload == network {
		t.Fatalf("address descriptors collided: workload=%s security=%s", workload, network)
	}
}

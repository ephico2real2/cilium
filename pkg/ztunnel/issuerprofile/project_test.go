// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package issuerprofile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type publicFixture struct {
	NowUnix         string     `json:"nowUnix"`
	ApprovalJSON    string     `json:"approvalJSON"`
	PublicationJSON string     `json:"publicationJSON"`
	Wire            DERProfile `json:"wire"`
}

func fixture(t *testing.T) (publicFixture, Install, *corev1.ConfigMap, *corev1.ConfigMap, time.Time) {
	t.Helper()
	raw, err := os.ReadFile("testdata/issuer-profile-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f publicFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	seconds, err := strconv.ParseInt(f.NowUnix, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(seconds, 0)
	e := Install{Expected: Expected{OutputUID: f.Wire.OutputUID, SourceUID: f.Wire.SourceUID, SourceNamespace: f.Wire.SourceNamespace, SourceName: f.Wire.SourceName, Cluster: f.Wire.Cluster, MinimumGeneration: 7, MinimumSequence: 10, RootPins: []string{f.Wire.RootSHA256}}, OutputNamespace: f.Wire.OutputNamespace, OutputName: f.Wire.OutputName, Node: f.Wire.Node}
	immutable := true
	source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: e.SourceNamespace, Name: e.SourceName, UID: types.UID(e.SourceUID), ResourceVersion: "17"}, Immutable: &immutable, Data: map[string]string{ApprovalKey: f.ApprovalJSON}}
	output := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: e.OutputNamespace, Name: e.OutputName, UID: types.UID(e.OutputUID), ResourceVersion: "23", Labels: map[string]string{OutputLabel: "true"}, Annotations: map[string]string{InitializedAnnotation: "true"}}, Data: map[string]string{DataKey: f.PublicationJSON}}
	return f, e, source, output, now
}
func TestAuthorizedAPIProjectionMatchesSharedDERFixture(t *testing.T) {
	f, e, source, output, now := fixture(t)
	client := fake.NewClientset(source, output)
	body, err := ReadAndProject(context.Background(), client.CoreV1(), e, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	var wire DERProfile
	if err = json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, f.Wire, wire, "Go projection must match the shared Rust DER fixture")
}
func TestRejectInvalidAPIBindingsAndLease(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Install, *corev1.ConfigMap, *corev1.ConfigMap, *time.Time)
	}{
		{"output-uid", func(_ *Install, _ *corev1.ConfigMap, o *corev1.ConfigMap, _ *time.Time) { o.UID = "replacement" }},
		{"source-uid", func(_ *Install, s *corev1.ConfigMap, _ *corev1.ConfigMap, _ *time.Time) { s.UID = "replacement" }},
		{"source-not-immutable", func(_ *Install, s *corev1.ConfigMap, _ *corev1.ConfigMap, _ *time.Time) { s.Immutable = nil }},
		{"source-rv", func(_ *Install, s *corev1.ConfigMap, _ *corev1.ConfigMap, _ *time.Time) { s.ResourceVersion = "18" }},
		{"output-label", func(_ *Install, _ *corev1.ConfigMap, o *corev1.ConfigMap, _ *time.Time) { o.Labels = nil }},
		{"output-not-initialized", func(_ *Install, _ *corev1.ConfigMap, o *corev1.ConfigMap, _ *time.Time) { o.Annotations = nil }},
		{"lease-expiry", func(_ *Install, _ *corev1.ConfigMap, _ *corev1.ConfigMap, n *time.Time) { *n = n.Add(30 * time.Second) }},
		{"future", func(_ *Install, _ *corev1.ConfigMap, _ *corev1.ConfigMap, n *time.Time) { *n = n.Add(-2 * time.Second) }},
		{"sequence-floor", func(e *Install, _ *corev1.ConfigMap, _ *corev1.ConfigMap, _ *time.Time) { e.MinimumSequence = 11 }},
		{"generation-floor", func(e *Install, _ *corev1.ConfigMap, _ *corev1.ConfigMap, _ *time.Time) { e.MinimumGeneration = 8 }},
		{"independent-root-pin", func(e *Install, _ *corev1.ConfigMap, _ *corev1.ConfigMap, _ *time.Time) {
			e.RootPins = []string{SHA([]byte("unapproved"))}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, e, s, o, n := fixture(t)
			tc.mutate(&e, s, o, &n)
			client := fake.NewClientset(s, o)
			body, err := ReadAndProject(context.Background(), client.CoreV1(), e, func() time.Time { return n })
			if err == nil || body != nil {
				t.Fatal("invalid source returned a usable profile")
			}
		})
	}
}
func TestAPIUnavailableNeverReturnsLastGoodProjection(t *testing.T) {
	_, e, s, o, n := fixture(t)
	client := fake.NewClientset(s, o)
	client.PrependReactor("get", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("API unavailable") })
	if body, err := ReadAndProject(context.Background(), client.CoreV1(), e, func() time.Time { return n }); err == nil || body != nil {
		t.Fatal("API failure did not fence projection")
	}
}
func TestSourceAndOutputReadRacesRejected(t *testing.T) {
	for _, name := range []string{"issuer-approval", "issuer-publication"} {
		t.Run(name, func(t *testing.T) {
			_, e, s, o, n := fixture(t)
			client := fake.NewClientset(s, o)
			gets := 0
			client.PrependReactor("get", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
				if a.(ktesting.GetAction).GetName() != name {
					return false, nil, nil
				}
				gets++
				if gets < 2 {
					return false, nil, nil
				}
				copy := s.DeepCopy()
				if name == e.OutputName {
					copy = o.DeepCopy()
				}
				copy.ResourceVersion = "changed"
				return true, copy, nil
			})
			if body, err := ReadAndProject(context.Background(), client.CoreV1(), e, func() time.Time { return n }); err == nil || body != nil {
				t.Fatal("racing object accepted")
			}
		})
	}
}
func TestTombstoneProjectsWithoutMissingSource(t *testing.T) {
	_, e, _, o, n := fixture(t)
	p, err := DecodePublication([]byte(o.Data[DataKey]))
	if err != nil {
		t.Fatal(err)
	}
	p.State = "withdrawn"
	p.Reason = "SourceDeleted"
	p.Sequence++
	p.Approval = nil
	p.ApprovalDigest = ""
	p.PublishedAt = Stamp(n)
	p.ValidUntil = Stamp(n)
	body, err := Encode(*p)
	if err != nil {
		t.Fatal(err)
	}
	o.Data[DataKey] = string(body)
	client := fake.NewClientset(o)
	wire, err := ReadAndProject(context.Background(), client.CoreV1(), e, func() time.Time { return n })
	if err != nil {
		t.Fatal(err)
	}
	var result DERProfile
	if err = json.Unmarshal(wire, &result); err != nil {
		t.Fatal(err)
	}
	if result.State != "withdrawn" || result.RootDER != nil || len(result.Clusters) != 0 {
		t.Fatal("withdrawal retained anchors")
	}
}

func TestCheckpointDigestsNamespacesAndWithdrawnHistory(t *testing.T) {
	for _, name := range []string{"approval-digest", "publication-digest", "malformed-digest", "dotted-namespace", "withdrawn-generation", "withdrawn-source", "withdrawn-digest"} {
		t.Run(name, func(t *testing.T) {
			f, e, s, o, n := fixture(t)
			e.ApprovalDigestAtMinimum = f.Wire.ApprovalDigest
			e.PublicationDigestAtMinimum = f.Wire.PublicationDigest
			switch name {
			case "approval-digest":
				e.ApprovalDigestAtMinimum = SHA([]byte("other authority"))
			case "publication-digest":
				e.PublicationDigestAtMinimum = SHA([]byte("other publication"))
			case "malformed-digest":
				e.PublicationDigestAtMinimum = "bad"
			case "dotted-namespace":
				e.SourceNamespace = "not.namespace"
				e.OutputNamespace = e.SourceNamespace
			default:
				p, err := DecodePublication([]byte(o.Data[DataKey]))
				if err != nil {
					t.Fatal(err)
				}
				p.State = "withdrawn"
				p.Reason = "SourceDeleted"
				p.Sequence++
				p.Approval = nil
				p.ApprovalDigest = ""
				p.ValidUntil = p.PublishedAt
				switch name {
				case "withdrawn-generation":
					p.AcceptedGeneration = 6
				case "withdrawn-source":
					p.AcceptedSourceUID = "replacement"
				case "withdrawn-digest":
					p.AcceptedApprovalDigest = SHA([]byte("other authority"))
				}
				body, err := Encode(*p)
				if err != nil {
					t.Fatal(err)
				}
				o.Data[DataKey] = string(body)
			}
			client := fake.NewClientset(s, o)
			if body, err := ReadAndProject(context.Background(), client.CoreV1(), e, func() time.Time { return n }); err == nil || body != nil {
				t.Fatal("invalid checkpoint produced usable material")
			}
		})
	}
}

func TestAPIOutageThenRecoveryRequiresCurrentRevalidation(t *testing.T) {
	_, e, s, o, n := fixture(t)
	client := fake.NewClientset(s, o)
	unavailable := false
	client.PrependReactor("get", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
		if unavailable {
			return true, nil, errors.New("API unavailable")
		}
		return false, nil, nil
	})
	read := func() ([]byte, error) {
		return ReadAndProject(context.Background(), client.CoreV1(), e, func() time.Time { return n })
	}
	if body, err := read(); err != nil || body == nil {
		t.Fatalf("initial projection: %v", err)
	}
	unavailable = true
	if body, err := read(); err == nil || body != nil {
		t.Fatal("API outage retained usable projection")
	}
	unavailable = false
	if body, err := read(); err != nil || body == nil {
		t.Fatalf("verified API recovery: %v", err)
	}
}

func TestWithdrawalAndRenewalCannotLowerCheckpoint(t *testing.T) {
	f, e, s, o, n := fixture(t)
	client := fake.NewClientset(s, o)
	e.ApprovalDigestAtMinimum = f.Wire.ApprovalDigest
	original, err := DecodePublication([]byte(o.Data[DataKey]))
	if err != nil {
		t.Fatal(err)
	}
	withdrawn := *original
	withdrawn.State = "withdrawn"
	withdrawn.Reason = "SourceDeleted"
	withdrawn.Sequence = 11
	withdrawn.Approval = nil
	withdrawn.ApprovalDigest = ""
	withdrawn.ValidUntil = withdrawn.PublishedAt
	update := func(p Publication, rv string) {
		t.Helper()
		body, err := Encode(p)
		if err != nil {
			t.Fatal(err)
		}
		o = o.DeepCopy()
		o.ResourceVersion = rv
		o.Data[DataKey] = string(body)
		if _, err = client.CoreV1().ConfigMaps(e.OutputNamespace).Update(context.Background(), o, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	read := func() ([]byte, error) {
		return ReadAndProject(context.Background(), client.CoreV1(), e, func() time.Time { return n })
	}
	update(withdrawn, "24")
	body, err := read()
	if err != nil {
		t.Fatal(err)
	}
	var wire DERProfile
	if err = json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.State != "withdrawn" || wire.Generation != "7" || wire.ApprovalDigest != f.Wire.ApprovalDigest || wire.RootDER != nil || len(wire.Clusters) != 0 {
		t.Fatal("withdrawal erased history or retained anchors")
	}
	// This assignment models an independently persisted checkpoint. This function
	// does not implement persistence or make a runtime-fencing claim.
	e.MinimumSequence = 11
	e.PublicationDigestAtMinimum = wire.PublicationDigest
	update(*original, "25")
	if body, err = read(); err == nil || body != nil {
		t.Fatal("pre-withdrawal replay accepted")
	}
	renewal := *original
	renewal.Sequence = 12
	update(renewal, "26")
	body, err = read()
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Sequence != "12" || wire.Generation != "7" || len(wire.Clusters) != 2 {
		t.Fatal("new same-approval renewal failed")
	}
}

func TestApprovalAndEnvelopeHaveSeparateByteBounds(t *testing.T) {
	if MaxBytes != 64*1024 || MaxPublicationBytes != 256*1024 {
		t.Fatal("producer byte-bound contract drift")
	}
	_, e, s, o, n := fixture(t)
	// Whitespace does not change the digest. Approval bytes remain independently
	// bounded even when a larger envelope is otherwise allowed.
	o.Data[DataKey] = string(append([]byte(o.Data[DataKey]), makeSpaces(MaxBytes)...))
	client := fake.NewClientset(s, o)
	if body, err := ReadAndProject(context.Background(), client.CoreV1(), e, func() time.Time { return n }); err != nil || body == nil {
		t.Fatalf("bounded larger publication: %v", err)
	}
	s.Data[ApprovalKey] = string(append([]byte(s.Data[ApprovalKey]), makeSpaces(MaxBytes)...))
	client = fake.NewClientset(s, o)
	if body, err := ReadAndProject(context.Background(), client.CoreV1(), e, func() time.Time { return n }); err == nil || body != nil {
		t.Fatal("oversized approval accepted inside larger envelope budget")
	}
}
func makeSpaces(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return b
}

func TestDeliveryReasonsDoNotInventPermanentRevocation(t *testing.T) {
	_, e, _, o, _ := fixture(t)
	p, err := DecodePublication([]byte(o.Data[DataKey]))
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"SourceUnavailable", "Unknown"} {
		copy := *p
		copy.Reason = reason
		if body, err := project(&copy, e); err == nil || body != nil {
			t.Fatal("invalid published reason produced material")
		}
	}
	for _, reason := range []string{"SourceUnavailable", "SourceChanged", "SourceDeleted", "SourceUIDMismatch", "SourceInvalid", "SourceExpired", "GenerationRollback"} {
		copy := *p
		copy.State = "withdrawn"
		copy.Reason = reason
		copy.ValidUntil = copy.PublishedAt
		copy.Approval = nil
		body, err := project(&copy, e)
		if err != nil {
			t.Fatal(err)
		}
		var wire DERProfile
		if err = json.Unmarshal(body, &wire); err != nil {
			t.Fatal(err)
		}
		if wire.Reason != reason || wire.RootDER != nil || len(wire.Clusters) != 0 {
			t.Fatal("unavailability reason or anchor-free state lost")
		}
	}
	for _, reason := range []string{"Validated", "Unknown", "AuthoritativeWithdrawal"} {
		copy := *p
		copy.State = "withdrawn"
		copy.Reason = reason
		copy.ValidUntil = copy.PublishedAt
		copy.Approval = nil
		if body, err := project(&copy, e); err == nil || body != nil {
			t.Fatal("invalid withdrawal reason accepted")
		}
	}
}

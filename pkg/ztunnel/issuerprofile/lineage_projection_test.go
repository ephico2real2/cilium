// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package issuerprofile

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cilium/cilium/pkg/time"
)

func TestApprovedLineageAPIProjectionMatchesSharedRustFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/issuer-profile-lineage-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f publicFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	_, e, s, o, _ := fixture(t)
	e.OutputUID = f.Wire.OutputUID
	e.RootPins = []string{f.Wire.RootSHA256}
	e.ApprovalDigestAtMinimum = f.Wire.ApprovalDigest
	e.PublicationDigestAtMinimum = f.Wire.PublicationDigest
	s.Data[ApprovalKey] = f.ApprovalJSON
	o.Data[DataKey] = f.PublicationJSON
	o.UID = types.UID(f.Wire.OutputUID)
	seconds, err := strconv.ParseInt(f.NowUnix, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(seconds, 0)
	client := fake.NewClientset(s, o)
	body, err := ReadAndProject(context.Background(), client.CoreV1(), e, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	var result DERProfile
	if err = json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, f.Wire, result, "approved parent DER must match shared Rust contract")
	for _, cluster := range result.Clusters {
		if len(cluster.Issuers) != 1 || len(cluster.Issuers[0].LineageDER) != 1 {
			t.Fatal("missing bounded explicit cluster CA lineage")
		}
	}
}

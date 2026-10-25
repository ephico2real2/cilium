// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/issuerprofile"
)

func testProfile(state string, sequence string, clusters ...issuerprofile.DERCluster) issuerprofile.DERProfile {
	return issuerprofile.DERProfile{WireVersion: 1, Cluster: "cmtc-a", Node: "worker-a", State: state, Sequence: sequence, Clusters: clusters}
}

func approvedCluster(name, domain string) issuerprofile.DERCluster {
	return issuerprofile.DERCluster{ClusterID: name, TrustDomain: domain, Issuers: []issuerprofile.DERIssuer{{SPKISHA256: "00"}}}
}

func profileSnapshot(t testing.TB, p issuerprofile.DERProfile, until time.Time) issuerProfileSnapshot {
	body, err := json.Marshal(p)
	require.NoError(t, err)
	return issuerProfileSnapshot{body: body, version: p.Sequence + "/d", state: p.State, until: until}
}

func TestRemoteTrustDecodeBindsOnlyApprovedPeerDomains(t *testing.T) {
	now := time.Now()
	until := now.Add(30 * time.Second)
	view, err := decodeRemoteTrust(profileSnapshot(t, testProfile("published", "7",
		approvedCluster("cmtc-a", "cmtc-a.mesh.example"), approvedCluster("cmtc-b", "cmtc-b.mesh.example"),
		issuerprofile.DERCluster{ClusterID: "cmtc-c", TrustDomain: "cmtc-c.mesh.example"}), until), "cmtc-a", "cmtc-a.mesh.example", now)
	require.NoError(t, err)
	require.True(t, view.valid)
	require.Equal(t, uint64(7), view.sequence)
	require.Equal(t, map[string]string{"cmtc-b": "cmtc-b.mesh.example"}, view.peers, "the local cluster and a peer without approved issuers are not remote domains")
	domain, err := view.domain("cmtc-b", now)
	require.NoError(t, err)
	require.Equal(t, "cmtc-b.mesh.example", domain)
	_, err = view.domain("cmtc-c", now)
	require.Error(t, err)
	_, err = view.domain("cmtc-b", until)
	require.ErrorContains(t, err, "expired")

	for name, tc := range map[string]struct {
		profile issuerprofile.DERProfile
		until   time.Time
	}{
		"tombstone":            {testProfile("withdrawn", "8", approvedCluster("cmtc-a", "cmtc-a.mesh.example")), until},
		"expired":              {testProfile("published", "8", approvedCluster("cmtc-a", "cmtc-a.mesh.example")), now},
		"local domain differs": {testProfile("published", "8", approvedCluster("cmtc-a", "other.example")), until},
		"local cluster absent": {testProfile("published", "8", approvedCluster("cmtc-b", "cmtc-b.mesh.example")), until},
		"duplicate domain": {testProfile("published", "8", approvedCluster("cmtc-a", "cmtc-a.mesh.example"),
			approvedCluster("cmtc-b", "cmtc-a.mesh.example")), until},
		"duplicate cluster": {testProfile("published", "8", approvedCluster("cmtc-a", "cmtc-a.mesh.example"),
			approvedCluster("cmtc-b", "cmtc-b.mesh.example"), approvedCluster("cmtc-b", "cmtc-x.mesh.example")), until},
		"noncanonical domain": {testProfile("published", "8", approvedCluster("cmtc-a", "cmtc-a.mesh.example"),
			approvedCluster("cmtc-b", "CMTC-B.mesh.example")), until},
		"zero sequence": {testProfile("published", "0", approvedCluster("cmtc-a", "cmtc-a.mesh.example")), until},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeRemoteTrust(profileSnapshot(t, tc.profile, tc.until), "cmtc-a", "cmtc-a.mesh.example", now)
			require.Error(t, err)
		})
	}
}

// The accepted profile survives a failed refresh only until its own expiry; a
// validated withdrawal applies at once; a later valid read recovers.
func TestRemoteTrustAuthorityHonoursProfileValidity(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var result struct {
		snapshot issuerProfileSnapshot
		err      error
	}
	a := &remoteTrustAuthority{log: slog.New(slog.DiscardHandler), localCluster: "cmtc-a", localDomain: "cmtc-a.mesh.example",
		clock: func() time.Time { return now }, interval: 2 * time.Second, changed: make(chan struct{})}
	a.read = func(context.Context) (issuerProfileSnapshot, error) { return result.snapshot, result.err }

	view, watch := a.View()
	require.False(t, view.valid)
	result.snapshot = profileSnapshot(t, testProfile("published", "7",
		approvedCluster("cmtc-a", "cmtc-a.mesh.example"), approvedCluster("cmtc-b", "cmtc-b.mesh.example")), now.Add(30*time.Second))
	require.Equal(t, 2*time.Second, a.refresh(context.Background()))
	require.True(t, closed(watch))
	view, watch = a.View()
	require.True(t, view.valid)

	// API failure: keep the accepted profile, re-check no later than expiry.
	result.err = errors.New("apiserver unavailable")
	now = now.Add(29 * time.Second)
	require.Equal(t, time.Second, a.refresh(context.Background()))
	view, _ = a.View()
	require.True(t, view.valid)
	require.False(t, closed(watch), "an unchanged view does not notify")

	// At expiry the failure withdraws trust.
	now = now.Add(time.Second)
	a.refresh(context.Background())
	view, watch = a.View()
	require.False(t, view.valid)
	require.Contains(t, view.reason, "apiserver unavailable")

	// Recovery with a new publication.
	result.err = nil
	result.snapshot = profileSnapshot(t, testProfile("published", "8",
		approvedCluster("cmtc-a", "cmtc-a.mesh.example"), approvedCluster("cmtc-b", "cmtc-b.mesh.example")), now.Add(30*time.Second))
	a.refresh(context.Background())
	require.True(t, closed(watch))
	view, watch = a.View()
	require.True(t, view.valid)
	require.Equal(t, uint64(8), view.sequence)

	// A validated tombstone withdraws immediately, before expiry.
	result.snapshot = profileSnapshot(t, testProfile("withdrawn", "9", approvedCluster("cmtc-a", "cmtc-a.mesh.example")), now.Add(30*time.Second))
	a.refresh(context.Background())
	require.True(t, closed(watch))
	view, _ = a.View()
	require.False(t, view.valid)

	var unconfigured *remoteTrustAuthority
	view, watch = unconfigured.View()
	require.False(t, view.valid)
	require.Nil(t, watch)
}

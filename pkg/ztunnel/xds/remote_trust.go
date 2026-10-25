// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/issuerprofile"
)

// remoteTrustView is the current trust-domain binding of ClusterMesh peers,
// taken only from the validated issuer profile that is also delivered to the
// local ztunnel. A peer's trust domain is never derived from its cluster
// name, the local domain or remote discovery data.
type remoteTrustView struct {
	valid    bool
	reason   string
	sequence uint64
	until    time.Time
	// peers maps a peer cluster name to its approved trust domain. Only
	// clusters with at least one approved issuer are present.
	peers map[string]string
}

func (v remoteTrustView) domain(cluster string, now time.Time) (string, error) {
	if !v.valid {
		return "", fmt.Errorf("remote trust is unavailable: %s", v.reason)
	}
	if !now.Before(v.until) {
		return "", errors.New("issuer profile expired")
	}
	domain, ok := v.peers[cluster]
	if !ok {
		return "", fmt.Errorf("issuer profile approves no trust domain for cluster %q", cluster)
	}
	return domain, nil
}

func (v remoteTrustView) equal(o remoteTrustView) bool {
	return v.valid == o.valid && v.reason == o.reason && v.sequence == o.sequence && v.until.Equal(o.until) && maps.Equal(v.peers, o.peers)
}

// decodeRemoteTrust validates one projected issuer profile. The local cluster
// must be approved with exactly the configured local trust domain; cluster
// names and trust domains must be unique.
func decodeRemoteTrust(snapshot issuerProfileSnapshot, localCluster, localDomain string, now time.Time) (remoteTrustView, error) {
	var profile issuerprofile.DERProfile
	if err := json.Unmarshal(snapshot.body, &profile); err != nil {
		return remoteTrustView{}, fmt.Errorf("decode issuer profile: %w", err)
	}
	if profile.State != "published" || snapshot.state != "published" {
		return remoteTrustView{}, fmt.Errorf("issuer profile is not published (state %q)", profile.State)
	}
	if profile.Cluster != localCluster {
		return remoteTrustView{}, fmt.Errorf("issuer profile belongs to cluster %q", profile.Cluster)
	}
	sequence, err := canonicalPositive(profile.Sequence)
	if err != nil {
		return remoteTrustView{}, err
	}
	if !now.Before(snapshot.until) {
		return remoteTrustView{}, errors.New("issuer profile expired")
	}
	view := remoteTrustView{valid: true, sequence: sequence, until: snapshot.until, peers: make(map[string]string)}
	clusters := make(map[string]bool, len(profile.Clusters))
	domains := make(map[string]bool, len(profile.Clusters))
	localSeen := false
	for _, cluster := range profile.Clusters {
		if !issuerprofile.ClusterValid(cluster.ClusterID) || clusters[cluster.ClusterID] {
			return remoteTrustView{}, fmt.Errorf("invalid or duplicate cluster %q in issuer profile", cluster.ClusterID)
		}
		clusters[cluster.ClusterID] = true
		td, err := spiffeid.TrustDomainFromString(cluster.TrustDomain)
		if err != nil || td.String() != cluster.TrustDomain || domains[cluster.TrustDomain] {
			return remoteTrustView{}, fmt.Errorf("invalid or duplicate trust domain %q in issuer profile", cluster.TrustDomain)
		}
		domains[cluster.TrustDomain] = true
		if cluster.ClusterID == localCluster {
			if cluster.TrustDomain != localDomain {
				return remoteTrustView{}, fmt.Errorf("issuer profile approves trust domain %q for the local cluster, configured %q", cluster.TrustDomain, localDomain)
			}
			localSeen = true
			continue
		}
		if len(cluster.Issuers) == 0 {
			continue // no approved signer: the peer's identities cannot verify
		}
		view.peers[cluster.ClusterID] = cluster.TrustDomain
	}
	if !localSeen {
		return remoteTrustView{}, errors.New("issuer profile does not approve the local cluster")
	}
	return view, nil
}

// remoteTrustAuthority keeps the current remoteTrustView. It reads the
// profile through the same validated, pinned API client and process-local
// floors as the ztunnel issuer-profile delivery. A failed refresh keeps the
// last accepted profile only until that profile's own validity ends; a
// tombstone or invalid profile withdraws it at once.
type remoteTrustAuthority struct {
	log          *slog.Logger
	read         func(context.Context) (issuerProfileSnapshot, error)
	localCluster string
	localDomain  string
	clock        func() time.Time
	interval     time.Duration

	mu      lock.Mutex
	view    remoteTrustView
	changed chan struct{}
}

func newRemoteTrustAuthority(log *slog.Logger, source *issuerProfileSource, localCluster, localDomain string) *remoteTrustAuthority {
	a := &remoteTrustAuthority{log: log, localCluster: localCluster, localDomain: localDomain, clock: time.Now,
		interval: 2 * time.Second, changed: make(chan struct{}),
		view: remoteTrustView{reason: "issuer profile has not been read"}}
	if source != nil {
		a.read = source.snapshot
	}
	return a
}

// View returns the current view and the channel closed on its next change.
func (a *remoteTrustAuthority) View() (remoteTrustView, <-chan struct{}) {
	if a == nil {
		return remoteTrustView{reason: "issuer profile authority is not configured"}, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.view, a.changed
}

func (a *remoteTrustAuthority) publish(view remoteTrustView) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.view.equal(view) {
		return
	}
	a.view = view
	close(a.changed)
	a.changed = make(chan struct{})
}

// refresh performs one read and returns when the view must be re-evaluated
// next (its expiry or the poll interval).
func (a *remoteTrustAuthority) refresh(ctx context.Context) time.Duration {
	now := a.clock()
	if a.read == nil {
		a.publish(remoteTrustView{reason: "issuer profile delivery is not configured"})
		return a.interval
	}
	snapshot, err := a.read(ctx)
	if err == nil {
		var view remoteTrustView
		view, err = decodeRemoteTrust(snapshot, a.localCluster, a.localDomain, now)
		if err == nil {
			a.publish(view)
			return min(a.interval, view.until.Sub(now))
		}
		// A validated profile that withdraws or misbinds trust takes
		// effect immediately.
		a.publish(remoteTrustView{reason: err.Error()})
		a.log.Warn("Withdrawing remote workload trust", logStage, "remote-trust", logfields.Error, err)
		return a.interval
	}
	current, _ := a.View()
	if current.valid && now.Before(current.until) {
		a.log.Warn("Issuer profile refresh failed; keeping the accepted profile until it expires",
			logStage, "remote-trust", logfields.Error, err, "validUntil", current.until)
		return min(a.interval, current.until.Sub(now))
	}
	a.publish(remoteTrustView{reason: "issuer profile unavailable: " + err.Error()})
	return a.interval
}

func (a *remoteTrustAuthority) run(ctx context.Context) {
	for {
		wait := max(a.refresh(ctx), 10*time.Millisecond)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

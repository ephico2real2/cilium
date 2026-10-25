// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/google/uuid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	validation "k8s.io/apimachinery/pkg/util/validation"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
	remote "github.com/cilium/cilium/pkg/ztunnel/remote_workload"
)

// Remote workload resources are disjoint from local ones: local Address
// resources are named by their Pod UID alone.
const remoteResourcePrefix = "cilium/remote/"

// errRemoteRecovery ends a stream on which a peer was withdrawn and is now
// admissible again. Recovery is delivered only on a fresh stream, which
// starts from a complete merged snapshot; an invalidated view is never
// carried across the invalidation on the same stream.
var errRemoteRecovery = errors.New("remote peer recovered after withdrawal; a fresh xDS stream is required")

func remoteResourceName(key remote.WorkloadKey) string {
	return fmt.Sprintf("%s%d/%s/%s", remoteResourcePrefix, key.ClusterID, key.NamespaceUID, key.PodUID)
}

func canonicalUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// remotePeerProjection is one peer's projected complete replacement set.
type remotePeerProjection struct {
	resources map[string][]byte // name -> encoded pb.Address
	addresses map[netip.Addr]string
	until     time.Time
	err       error
}

// projectRemoteSnapshot converts one authenticated peer snapshot into exact
// Address resources. trustDomain comes from the validated issuer profile;
// trustUntil is that profile's validity. localNodes are the local cluster's
// Kubernetes Node names: ztunnel locality compares node names only, so a
// remote workload on a node name that also exists locally is refused.
// Every error withdraws the whole peer.
func projectRemoteSnapshot(s remote.Snapshot, trustDomain string, trustUntil time.Time, localNodes map[string]bool, now time.Time) remotePeerProjection {
	fail := func(format string, args ...any) remotePeerProjection {
		return remotePeerProjection{err: fmt.Errorf(format, args...)}
	}
	if !s.Valid {
		reason := s.Reason
		if reason == "" {
			reason = "no valid snapshot"
		}
		return fail("remote snapshot invalid: %s", reason)
	}
	if err := cmtypes.ValidateClusterName(s.ClusterName); err != nil || s.ClusterID == 0 {
		return fail("remote snapshot lacks an authenticated cluster name and ID")
	}
	if s.Generation == 0 || s.SessionEpoch == 0 || s.SourceMembershipSessionEpoch == 0 || s.PeerIdentityEpoch == 0 {
		return fail("remote snapshot lacks its authenticated session epochs")
	}
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil || td.String() != trustDomain {
		return fail("invalid approved remote trust domain")
	}
	if s.SourceMembershipLeaseValidUntil.IsZero() || s.PeerCertificateNotAfter.IsZero() || s.PeerHeartbeatAt.IsZero() || trustUntil.IsZero() {
		return fail("remote snapshot lacks a lease, certificate or heartbeat deadline")
	}
	until := slices.MinFunc([]time.Time{trustUntil, s.SourceMembershipLeaseValidUntil, s.PeerCertificateNotAfter,
		s.PeerHeartbeatAt.Add(2 * kvstore.HeartbeatWriteInterval)}, func(a, b time.Time) int { return a.Compare(b) })
	if !now.Before(until) {
		return fail("remote snapshot authority expired")
	}
	if len(s.Workloads) > remote.MaxRemoteWorkloadsPerPeer {
		return fail("remote snapshot exceeds the workload bound")
	}
	out := remotePeerProjection{resources: make(map[string][]byte, len(s.Workloads)), addresses: make(map[netip.Addr]string), until: until}
	for _, w := range s.Workloads {
		if w.Key.ClusterID != s.ClusterID || !canonicalUUID(w.Key.NamespaceUID) || !canonicalUUID(w.Key.PodUID) {
			return fail("remote workload key is not an exact incarnation of the peer")
		}
		if len(validation.IsDNS1123Label(w.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(w.ServiceAccount)) != 0 ||
			len(validation.IsDNS1123Subdomain(w.PodName)) != 0 || len(validation.IsDNS1123Subdomain(w.NodeName)) != 0 {
			return fail("remote workload identity is not canonical")
		}
		if w.MembershipState != "captured" || w.MembershipEpoch == "" || w.MembershipGeneration == 0 {
			return fail("remote workload is not captured by its source")
		}
		if localNodes[w.NodeName] {
			return fail("remote workload node name %q also names a local node", w.NodeName)
		}
		if len(w.Addresses) == 0 || len(w.Addresses) > 2 {
			return fail("remote workload needs one or two addresses")
		}
		name := remoteResourceName(w.Key)
		if _, dup := out.resources[name]; dup {
			return fail("duplicate remote workload incarnation")
		}
		wire := &pb.Workload{Uid: name, Name: w.PodName, Namespace: w.Namespace, Node: w.NodeName,
			ClusterId: s.ClusterName, TrustDomain: trustDomain, ServiceAccount: w.ServiceAccount,
			TunnelProtocol: pb.TunnelProtocol_HBONE}
		families := map[bool]bool{}
		for _, ip := range w.Addresses {
			if !strictUnicastAddress(ip) || families[ip.Is4()] {
				return fail("invalid or ambiguous remote workload address")
			}
			families[ip.Is4()] = true
			if owner, exists := out.addresses[ip]; exists && owner != name {
				return fail("remote address has two workload owners")
			}
			out.addresses[ip] = name
			wire.Addresses = append(wire.Addresses, ip.AsSlice())
		}
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&pb.Address{Type: &pb.Address_Workload{Workload: wire}})
		if err != nil {
			return fail("encode remote workload: %v", err)
		}
		out.resources[name] = encoded
	}
	return out
}

// projectRemotePeers projects every peer, then withdraws every peer whose
// addresses collide with a local workload or with another peer: when two
// owners claim one address, neither is trusted.
func projectRemotePeers(views map[string]remote.PeerSnapshotView, trust remoteTrustView, localNodes map[string]bool, local map[netip.Addr]string, now time.Time) map[string]remotePeerProjection {
	out := make(map[string]remotePeerProjection, len(views))
	owners := make(map[netip.Addr][]string)
	for name, view := range views {
		domain, err := trust.domain(name, now)
		if err != nil {
			out[name] = remotePeerProjection{err: err}
			continue
		}
		projection := projectRemoteSnapshot(view.Snapshot, domain, trust.until, localNodes, now)
		if projection.err == nil && view.Snapshot.ClusterName != name {
			projection = remotePeerProjection{err: errors.New("remote snapshot names another peer")}
		}
		out[name] = projection
		for ip := range projection.addresses {
			owners[ip] = append(owners[ip], name)
		}
	}
	for ip, peers := range owners {
		_, localOwner := local[ip]
		if len(peers) < 2 && !localOwner {
			continue
		}
		for _, name := range peers {
			p := out[name]
			if p.err == nil {
				p = remotePeerProjection{err: fmt.Errorf("remote address %s collides with another workload owner", ip)}
				out[name] = p
			}
		}
	}
	return out
}

// remotePeerState is what this stream has published for one peer.
type remotePeerState struct {
	fence, writerEpoch uint64
	published          map[string][]byte
	addresses          map[netip.Addr]string
	// withdrawn: this stream removed the peer's resources after an
	// invalidation; it never re-adds them.
	withdrawn bool
}

// remoteStreamState is the remote half of one ztunnel ADS stream.
type remoteStreamState struct {
	peers    map[string]*remotePeerState
	deadline time.Time
	timer    *time.Timer
	// watches of the inputs read for the last computation
	viewWatch, trustWatch, nodeWatch <-chan struct{}
}

func newRemoteStreamState() *remoteStreamState {
	return &remoteStreamState{peers: make(map[string]*remotePeerState)}
}

func (st *remoteStreamState) addressOwners() map[netip.Addr]string {
	out := make(map[netip.Addr]string)
	for _, peer := range st.peers {
		for ip, name := range peer.addresses {
			out[ip] = name
		}
	}
	return out
}

// remoteDelta is one computed change for the stream.
type remoteDelta struct {
	upserts  map[string][]byte
	removals []string
	next     map[string]*remotePeerState
	deadline time.Time
	events   map[string]string // peer -> event (for logs and metrics)
}

// planRemote computes the stream's next remote state against the current
// inputs. initial plans the first complete snapshot (no withdrawal state
// exists yet). It returns errRemoteRecovery when a withdrawn peer, or a peer
// whose view crossed an invalidation after publication, is admissible again.
func (st *remoteStreamState) planRemote(views map[string]remote.PeerSnapshotView, trust remoteTrustView, localNodes map[string]bool, local map[netip.Addr]string, now time.Time) (remoteDelta, error) {
	projections := projectRemotePeers(views, trust, localNodes, local, now)
	delta := remoteDelta{upserts: make(map[string][]byte), next: make(map[string]*remotePeerState), events: make(map[string]string)}
	names := make([]string, 0, len(projections)+len(st.peers))
	for name := range projections {
		names = append(names, name)
	}
	for name := range st.peers {
		if _, ok := projections[name]; !ok {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	for _, name := range names {
		prev := st.peers[name]
		view, haveView := views[name]
		projection, haveProjection := projections[name]
		if !haveProjection {
			projection = remotePeerProjection{err: errors.New("remote peer removed")}
		}
		next := &remotePeerState{published: map[string][]byte{}, addresses: map[netip.Addr]string{}}
		if haveView {
			next.fence, next.writerEpoch = view.Fence, view.WriterEpoch
		}
		var hadPublished, crossed bool
		if prev != nil {
			hadPublished = len(prev.published) > 0
			next.withdrawn = prev.withdrawn
			crossed = haveView && (view.Fence != prev.fence || view.WriterEpoch != prev.writerEpoch)
		}
		withdraw := func(event string) {
			if prev != nil {
				for resource := range prev.published {
					delta.removals = append(delta.removals, resource)
				}
			}
			if hadPublished {
				// Only a peer this stream published can be withdrawn.
				next.withdrawn = true
				delta.events[name] = event
			}
		}
		switch {
		case projection.err != nil:
			withdraw("withdrawn")
		case next.withdrawn:
			return remoteDelta{}, fmt.Errorf("%w: peer %q", errRemoteRecovery, name)
		case hadPublished && crossed:
			// The view crossed an invalidation after this stream published
			// it. Withdraw now; recovery needs a fresh stream.
			withdraw("withdrawn")
			return remoteDelta{removals: delta.removals, next: nil}, fmt.Errorf("%w: peer %q crossed an invalidation", errRemoteRecovery, name)
		default:
			for resource, encoded := range projection.resources {
				if prev == nil || !bytes.Equal(prev.published[resource], encoded) {
					delta.upserts[resource] = encoded
				}
				next.published[resource] = encoded
			}
			for ip, resource := range projection.addresses {
				next.addresses[ip] = resource
			}
			if prev != nil {
				for resource := range prev.published {
					if _, kept := projection.resources[resource]; !kept {
						delta.removals = append(delta.removals, resource)
					}
				}
			}
			if delta.deadline.IsZero() || projection.until.Before(delta.deadline) {
				delta.deadline = projection.until
			}
			if prev == nil || !hadPublished {
				delta.events[name] = "projected"
			}
		}
		delta.next[name] = next
	}
	slices.Sort(delta.removals)
	return delta, nil
}

func (d remoteDelta) empty() bool { return len(d.upserts) == 0 && len(d.removals) == 0 }

// resources encodes the upserts in name order.
func (d remoteDelta) resources() ([]*v3.Resource, error) {
	names := make([]string, 0, len(d.upserts))
	for name := range d.upserts {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]*v3.Resource, 0, len(names))
	for _, name := range names {
		out = append(out, &v3.Resource{Name: name, Resource: &anypb.Any{
			TypeUrl: xdsTypeURLAddress, Value: d.upserts[name]}})
	}
	return out, nil
}

// commit records a delta that was sent.
func (st *remoteStreamState) commit(d remoteDelta) {
	st.peers = d.next
	st.deadline = d.deadline
}

func isRemoteResource(name string) bool { return strings.HasPrefix(name, remoteResourcePrefix) }

// remoteInputs reads the current peer view, trust view and local node names.
func (sp *StreamProcessor) remoteInputs() (map[string]remote.PeerSnapshotView, <-chan struct{}, remoteTrustView, <-chan struct{}, map[string]bool, <-chan struct{}, error) {
	views, viewWatch := sp.remotePeers.View()
	trust, trustWatch := sp.remoteTrust.View()
	if sp.nodeNames == nil {
		return nil, nil, remoteTrustView{}, nil, nil, nil, errors.New("Kubernetes node discovery is not configured")
	}
	nodes, nodeWatch, err := sp.nodeNames.localNames()
	if err != nil {
		return nil, nil, remoteTrustView{}, nil, nil, nil, err
	}
	return views, viewWatch, trust, trustWatch, nodes, nodeWatch, nil
}

func (sp *StreamProcessor) remoteEnabled() bool { return sp.remotePeers != nil }

// addInitialRemote appends the current remote projection to the initial
// Address response, so ztunnel receives local and remote workloads in one
// complete snapshot. Strict initial removals then run once on the merge.
func (sp *StreamProcessor) addInitialRemote(response *v3.DeltaDiscoveryResponse, now time.Time) (remoteDelta, error) {
	views, viewWatch, trust, trustWatch, nodes, nodeWatch, err := sp.remoteInputs()
	if err != nil {
		return remoteDelta{}, err
	}
	local, err := localAddressOwners(response)
	if err != nil {
		return remoteDelta{}, err
	}
	st := newRemoteStreamState()
	delta, err := st.planRemote(views, trust, nodes, local, now)
	if err != nil {
		return remoteDelta{}, err
	}
	resources, err := delta.resources()
	if err != nil {
		return remoteDelta{}, err
	}
	response.Resources = append(response.Resources, resources...)
	sp.remote = st
	sp.remote.viewWatch, sp.remote.trustWatch, sp.remote.nodeWatch = viewWatch, trustWatch, nodeWatch
	sp.remoteInitial = &delta
	sp.remoteInitialTrust = trust
	return delta, nil
}

// commitInitialRemote records the remote half of the initial snapshot after
// it was sent.
func (sp *StreamProcessor) commitInitialRemote(now time.Time) {
	if sp.remote == nil || sp.remoteInitial == nil {
		return
	}
	sp.remote.commit(*sp.remoteInitial)
	sp.recordRemoteDelta(*sp.remoteInitial, sp.remoteInitialTrust)
	sp.remoteInitial = nil
	sp.armRemoteDeadline(now)
}

// localAddressOwners indexes the local workload addresses of a response.
func localAddressOwners(response *v3.DeltaDiscoveryResponse) (map[netip.Addr]string, error) {
	out := make(map[netip.Addr]string)
	for _, resource := range response.Resources {
		if resource == nil || resource.Resource == nil || isRemoteResource(resource.Name) {
			continue
		}
		address := new(pb.Address)
		if err := resource.Resource.UnmarshalTo(address); err != nil {
			return nil, fmt.Errorf("decode local workload: %w", err)
		}
		for _, raw := range address.GetWorkload().GetAddresses() {
			ip, ok := netip.AddrFromSlice(raw)
			if !ok {
				return nil, errors.New("invalid local workload address")
			}
			out[ip.Unmap()] = resource.Name
		}
	}
	return out, nil
}

// syncRemote publishes the remote changes since the last send on this stream.
func (sp *StreamProcessor) syncRemote(now time.Time) error {
	if !sp.remoteEnabled() || sp.remote == nil {
		return nil
	}
	views, viewWatch, trust, trustWatch, nodes, nodeWatch, err := sp.remoteInputs()
	if err != nil {
		return err
	}
	delta, planErr := sp.remote.planRemote(views, trust, nodes, sp.localAddresses, now)
	if planErr != nil && !errors.Is(planErr, errRemoteRecovery) {
		return planErr
	}
	if len(delta.removals) > 0 || len(delta.upserts) > 0 {
		resources, err := delta.resources()
		if err != nil {
			return err
		}
		response := &v3.DeltaDiscoveryResponse{TypeUrl: xdsTypeURLAddress, Resources: resources,
			RemovedResources: delta.removals, Nonce: uuid.New().String()}
		if err := sp.sendAddressMessage(response, "xds-remote-workloads"); err != nil {
			return err
		}
		sp.recordRemoteDelta(delta, trust)
	}
	if planErr != nil {
		// Removals of the withdrawn peer were sent above; now end the stream.
		sp.recordRemoteEvent("stream_reset_for_recovery")
		sp.log.Info("Closing ztunnel xDS stream so a recovered remote peer is delivered on a fresh stream",
			logStage, "xds-remote-workloads", logfields.Error, planErr)
		return planErr
	}
	if delta.next != nil {
		sp.remote.commit(delta)
	}
	sp.remote.viewWatch, sp.remote.trustWatch, sp.remote.nodeWatch = viewWatch, trustWatch, nodeWatch
	sp.armRemoteDeadline(now)
	return nil
}

func (sp *StreamProcessor) recordRemoteDelta(delta remoteDelta, trust remoteTrustView) {
	for peer, event := range delta.events {
		sp.recordRemoteEvent(event)
		if sp.log != nil {
			sp.log.Info("Remote workload projection changed",
				logStage, "xds-remote-workloads", logfields.ClusterName, peer,
				logfields.Event, event, "issuerProfileSequence", trust.sequence)
		}
	}
	if sp.metrics != nil && delta.next != nil {
		for peer, state := range delta.next {
			sp.metrics.RemoteWorkloads.WithLabelValues(peer).Set(float64(len(state.published)))
		}
	}
}

func (sp *StreamProcessor) recordRemoteEvent(event string) {
	if sp.metrics != nil {
		sp.metrics.RemoteProjectionEvents.WithLabelValues(event).Inc()
	}
}

// armRemoteDeadline schedules re-evaluation at the earliest projected
// authority deadline, so expiry withdraws without any watch event.
func (sp *StreamProcessor) armRemoteDeadline(now time.Time) {
	st := sp.remote
	if st.timer != nil {
		st.timer.Stop()
		st.timer = nil
	}
	if st.deadline.IsZero() {
		return
	}
	st.timer = time.NewTimer(max(st.deadline.Sub(now), time.Millisecond))
}

func (sp *StreamProcessor) remoteTimer() <-chan time.Time {
	if sp.remote == nil || sp.remote.timer == nil {
		return nil
	}
	return sp.remote.timer.C
}

func (sp *StreamProcessor) remoteViewWatch() <-chan struct{} {
	if sp.remote == nil {
		return nil
	}
	return sp.remote.viewWatch
}

func (sp *StreamProcessor) remoteTrustWatch() <-chan struct{} {
	if sp.remote == nil {
		return nil
	}
	return sp.remote.trustWatch
}

func (sp *StreamProcessor) remoteNodeWatch() <-chan struct{} {
	if sp.remote == nil {
		return nil
	}
	return sp.remote.nodeWatch
}

// withdrawCollidingRemote handles a local response: any remote peer whose
// published addresses collide with a newly published local workload is
// withdrawn in the same response.
func (sp *StreamProcessor) withdrawCollidingRemote(response *v3.DeltaDiscoveryResponse) error {
	if sp.remote == nil {
		return nil
	}
	added, err := localAddressOwners(response)
	if err != nil {
		return err
	}
	for name, peer := range sp.remote.peers {
		collides := false
		for ip := range peer.addresses {
			if _, ok := added[ip]; ok {
				collides = true
				break
			}
		}
		if !collides || len(peer.published) == 0 {
			continue
		}
		for resource := range peer.published {
			response.RemovedResources = append(response.RemovedResources, resource)
		}
		slices.Sort(response.RemovedResources)
		sp.remote.peers[name] = &remotePeerState{fence: peer.fence, writerEpoch: peer.writerEpoch,
			published: map[string][]byte{}, addresses: map[netip.Addr]string{}, withdrawn: true}
		sp.recordRemoteEvent("withdrawn_local_collision")
		if sp.log != nil {
			sp.log.Warn("Withdrawing a remote peer whose workload address collides with a local workload",
				logStage, "xds-remote-workloads", logfields.ClusterName, name)
		}
	}
	return nil
}

// updateLocalAddresses keeps the stream's index of published local
// addresses after a successful local send.
func (sp *StreamProcessor) updateLocalAddresses(response *v3.DeltaDiscoveryResponse) error {
	if !sp.remoteEnabled() {
		return nil
	}
	if sp.localAddresses == nil {
		sp.localAddresses = make(map[netip.Addr]string)
	}
	for _, name := range response.RemovedResources {
		if isRemoteResource(name) {
			continue
		}
		for ip, owner := range sp.localAddresses {
			if owner == name {
				delete(sp.localAddresses, ip)
			}
		}
	}
	added, err := localAddressOwners(response)
	if err != nil {
		return err
	}
	for ip, owner := range added {
		sp.localAddresses[ip] = owner
	}
	return nil
}

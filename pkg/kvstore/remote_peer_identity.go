// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	grpccredentials "google.golang.org/grpc/credentials"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

const maxRemotePeerSPKIPins = 64

var errRemotePeerEvidenceUnavailable = errors.New("remote peer evidence is unavailable")

// RemotePeerIdentityConfig is local administrator-owned configuration in the
// per-peer etcd-client YAML. The remote ClusterMesh value never supplies pins.
type RemotePeerIdentityConfig struct {
	ClusterID  uint32   `json:"cluster-id" yaml:"cluster-id"`
	SPKISHA256 []string `json:"spki-sha256" yaml:"spki-sha256"`
}

// Validate rejects ambiguous or unsafe pin profiles before a client is created.
func (c *RemotePeerIdentityConfig) Validate() error {
	if c == nil {
		return nil
	}
	if err := cmtypes.ValidateClusterID(c.ClusterID); err != nil {
		return err
	}
	if len(c.SPKISHA256) == 0 || len(c.SPKISHA256) > maxRemotePeerSPKIPins {
		return fmt.Errorf("remote peer requires 1..%d SHA-256 SPKI pins", maxRemotePeerSPKIPins)
	}
	seen := make(map[string]struct{}, len(c.SPKISHA256))
	for _, raw := range c.SPKISHA256 {
		if len(raw) != sha256.Size*2 || raw != strings.ToLower(raw) {
			return fmt.Errorf("SPKI pin must be 64 lowercase hexadecimal characters")
		}
		if _, err := hex.DecodeString(raw); err != nil {
			return fmt.Errorf("invalid SHA-256 SPKI pin: %w", err)
		}
		if _, ok := seen[raw]; ok {
			return fmt.Errorf("duplicate SHA-256 SPKI pin")
		}
		seen[raw] = struct{}{}
	}
	return nil
}

type remotePeerTLSBinding struct {
	clusterName string
	clusterID   uint32
	pins        [][sha256.Size]byte
	profileID   [sha256.Size]byte
	proofMu     lock.Mutex
	proofID     uint64
	nextConnID  uint64
	lastProof   remoteTLSProof
	hasProof    bool
	connections map[uint64]remotePeerActiveConn
	// refreshing is set only by refreshTransports, between closing this
	// client's sockets and the next recorded handshake. Until its deadline the
	// evidence of the closed transport stays usable, so that a refresh the
	// client started itself is not reported as a lost peer.
	refreshing *remotePeerRefresh
	// handshakes is closed and replaced by connectionOpened; refreshTransports
	// waits on it for the handshake that follows a refresh.
	handshakes chan struct{}
}

// remoteTLSProof is immutable evidence for one successful gRPC TLS connection.
// The identity epoch changes only when the pinned leaf's public key (its SPKI)
// changes; a leaf renewed for the same key is the same identity with a later
// NotAfter. Evidence is usable only while every active connection on this
// direct etcd client has the same identity, and its NotAfter is the earliest
// one among them. This conservative lease keeps a newly opened connection from
// extending an older connection's lifetime.
type remoteTLSProof struct {
	identityEpoch uint64
	notAfter      time.Time
	spki          [sha256.Size]byte
}

// remotePeerActiveConn is one authenticated transport: its proof and the
// socket, so that refreshTransports can close it.
type remotePeerActiveConn struct {
	proof remoteTLSProof
	conn  net.Conn
}

// remotePeerRefresh is the bounded grace between a refresh and its handshake.
type remotePeerRefresh struct {
	proof remoteTLSProof
	until time.Time
}

// errRemotePeerRefreshTimedOut reports a transport refresh that was not
// followed by a new TLS handshake before its deadline.
var errRemotePeerRefreshTimedOut = errors.New("remote peer transport refresh was not followed by a new TLS handshake")

// RemotePeerEvidence is a read-only view over one immutable local pin profile,
// one verified leaf-certificate identity epoch that agrees across every active
// client transport, and the latest etcd heartbeat. Callers must re-fetch it
// for each watch epoch and while the snapshot is served. Implementations
// cannot change the profile associated with a connection.
type RemotePeerEvidence interface {
	ClusterName() string
	ClusterID() uint32
	IdentityEpoch() uint64
	CertificateNotAfter() time.Time
	LastHeartbeat() time.Time
	SPKIHash() [sha256.Size]byte
	ProfileID() [sha256.Size]byte
	Validate(now time.Time) error
}

type remotePeerEvidence struct {
	name          string
	id            uint32
	identityEpoch uint64
	notAfter      time.Time
	heartbeatAt   time.Time
	spki          [sha256.Size]byte
	profileID     [sha256.Size]byte
}

func (e remotePeerEvidence) ClusterName() string            { return e.name }
func (e remotePeerEvidence) ClusterID() uint32              { return e.id }
func (e remotePeerEvidence) IdentityEpoch() uint64          { return e.identityEpoch }
func (e remotePeerEvidence) CertificateNotAfter() time.Time { return e.notAfter }
func (e remotePeerEvidence) LastHeartbeat() time.Time       { return e.heartbeatAt }
func (e remotePeerEvidence) SPKIHash() [sha256.Size]byte    { return e.spki }
func (e remotePeerEvidence) ProfileID() [sha256.Size]byte   { return e.profileID }

// Validate limits provenance to the verified certificate lifetime and to the
// same heartbeat freshness boundary used by direct ClusterMesh health checks.
func (e remotePeerEvidence) Validate(now time.Time) error {
	if e.name == "" || e.id == cmtypes.ClusterIDUnset || e.identityEpoch == 0 || e.notAfter.IsZero() || e.spki == [sha256.Size]byte{} || e.profileID == [sha256.Size]byte{} {
		return errRemotePeerEvidenceUnavailable
	}
	if !now.Before(e.notAfter) {
		return fmt.Errorf("pinned remote peer certificate expired at %s", e.notAfter.UTC().Format(time.RFC3339))
	}
	if e.heartbeatAt.IsZero() || e.heartbeatAt.After(now) || now.Sub(e.heartbeatAt) > 2*HeartbeatWriteInterval {
		return fmt.Errorf("remote peer heartbeat is stale or unavailable")
	}
	return nil
}

// RemotePeerEvidenceProvider returns fresh evidence on demand. The provider
// must observe the etcd client's live connection context and actual heartbeat,
// not a cached boolean set by an earlier TLS handshake.
type RemotePeerEvidenceProvider interface {
	CurrentRemotePeerEvidence() (RemotePeerEvidence, error)
}

// RemotePeerTransportRefresher is implemented by the direct etcd backend with
// a pinned peer profile. RefreshRemotePeerTransport closes every authenticated
// transport of the client, so that the next RPC performs a new TLS handshake
// with the credential files as they are on disk now, and returns once that
// handshake has been recorded, with the evidence of the new transport. The
// client, its watches and its leases stay open: the etcd watch client resumes
// each watch at its last revision on the new transport. The evidence of the
// closed transport stays usable until the new handshake or until grace ends,
// whichever comes first; after a refresh without a handshake the evidence is
// unavailable and the caller must fail closed.
type RemotePeerTransportRefresher interface {
	RefreshRemotePeerTransport(ctx context.Context, grace time.Duration) (RemotePeerEvidence, error)
}

// RemotePeerBindingInfo exposes the immutable admin-owned peer identity only
// on a backend returned by RemotePeerBackendBinder. It is used to verify the
// advertised Cilium ClusterID before watcher registration; it does not assert
// that a live TLS connection or heartbeat is currently fresh.
type RemotePeerBindingInfo interface {
	PinnedRemotePeer() (clusterName string, clusterID uint32, profileID [sha256.Size]byte)
}

// RemotePeerBackendBinder is implemented only by the direct etcd backend with
// a configured TLS pin verifier. BindRemotePeer is called after the remote
// CiliumClusterConfig was read; it compares its advertised ID with the
// administrator-owned local profile before ClusterMesh reserves the ID or
// invokes observer registration.
type RemotePeerBackendBinder interface {
	BindRemotePeer(expectedName string, advertisedClusterID uint32) (BackendOperations, error)
}

type authenticatedRemotePeerBackend struct {
	BackendOperations
	provider RemotePeerEvidenceProvider
	binding  *remotePeerTLSBinding
}

func (b *authenticatedRemotePeerBackend) PinnedRemotePeer() (string, uint32, [sha256.Size]byte) {
	if b == nil || b.binding == nil {
		return "", cmtypes.ClusterIDUnset, [sha256.Size]byte{}
	}
	return b.binding.clusterName, b.binding.clusterID, b.binding.profileID
}

func (b *authenticatedRemotePeerBackend) CurrentRemotePeerEvidence() (RemotePeerEvidence, error) {
	evidence, err := b.provider.CurrentRemotePeerEvidence()
	if err != nil {
		return nil, err
	}
	if err := evidence.Validate(time.Now()); err != nil {
		return nil, err
	}
	return evidence, nil
}

func (b *authenticatedRemotePeerBackend) RefreshRemotePeerTransport(ctx context.Context, grace time.Duration) (RemotePeerEvidence, error) {
	refresher, ok := b.BackendOperations.(RemotePeerTransportRefresher)
	if !ok {
		return nil, fmt.Errorf("remote etcd backend cannot refresh its TLS transport")
	}
	return refresher.RefreshRemotePeerTransport(ctx, grace)
}

func newRemotePeerTLSBinding(clusterName string, cfg *RemotePeerIdentityConfig) (*remotePeerTLSBinding, error) {
	if cfg == nil {
		return nil, nil
	}
	if err := cmtypes.ValidateClusterName(clusterName); err != nil {
		return nil, fmt.Errorf("invalid local ClusterMesh peer name: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	pins := make([][sha256.Size]byte, 0, len(cfg.SPKISHA256))
	for _, raw := range cfg.SPKISHA256 {
		decoded, _ := hex.DecodeString(raw) // Validate checked the exact representation.
		var pin [sha256.Size]byte
		copy(pin[:], decoded)
		pins = append(pins, pin)
	}
	profileHash := sha256.New()
	profileHash.Write([]byte(clusterName))
	profileHash.Write([]byte{0})
	profileHash.Write([]byte(fmt.Sprint(cfg.ClusterID)))
	for _, pin := range pins {
		profileHash.Write(pin[:])
	}
	var profileID [sha256.Size]byte
	copy(profileID[:], profileHash.Sum(nil))
	return &remotePeerTLSBinding{clusterName: clusterName, clusterID: cfg.ClusterID, pins: pins, profileID: profileID}, nil
}

func (b *remotePeerTLSBinding) verifyState(state tls.ConnectionState) (remoteTLSProof, error) {
	if b == nil || b.clusterName == "" || b.clusterID == cmtypes.ClusterIDUnset || len(b.pins) == 0 {
		return remoteTLSProof{}, errRemotePeerEvidenceUnavailable
	}
	if len(state.VerifiedChains) == 0 {
		return remoteTLSProof{}, fmt.Errorf("remote etcd TLS connection has no verified certificate chain")
	}
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return remoteTLSProof{}, fmt.Errorf("remote etcd TLS connection has no peer certificate")
	}
	leaf := state.PeerCertificates[0]
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	matched := false
	for _, pin := range b.pins {
		matched = matched || subtle.ConstantTimeCompare(pin[:], spki[:]) == 1
	}
	if !matched {
		return remoteTLSProof{}, fmt.Errorf("remote etcd leaf SPKI is not authorized for ClusterMesh peer %q", b.clusterName)
	}
	if !time.Now().Before(leaf.NotAfter) {
		return remoteTLSProof{}, fmt.Errorf("remote etcd leaf certificate is expired")
	}
	return remoteTLSProof{notAfter: leaf.NotAfter, spki: spki}, nil
}

// VerifyConnection is the TLS-layer pin check. It deliberately does not
// publish process-global evidence: the gRPC credential wrapper below records
// the identity together with the lifetime of the exact authenticated socket.
func (b *remotePeerTLSBinding) VerifyConnection(state tls.ConnectionState) error {
	_, err := b.verifyState(state)
	return err
}

func (b *remotePeerTLSBinding) connectionOpened(state tls.ConnectionState, conn net.Conn) (uint64, error) {
	proof, err := b.verifyState(state)
	if err != nil {
		return 0, err
	}
	b.proofMu.Lock()
	defer b.proofMu.Unlock()
	if !b.hasProof || b.lastProof.spki != proof.spki {
		b.proofID++
		b.hasProof = true
	}
	b.lastProof = proof
	b.lastProof.identityEpoch = b.proofID
	proof.identityEpoch = b.proofID
	b.nextConnID++
	if b.connections == nil {
		b.connections = make(map[uint64]remotePeerActiveConn)
	}
	b.connections[b.nextConnID] = remotePeerActiveConn{proof: proof, conn: conn}
	// A recorded handshake ends any refresh grace and wakes its waiter.
	b.refreshing = nil
	if b.handshakes != nil {
		close(b.handshakes)
		b.handshakes = nil
	}
	return b.nextConnID, nil
}

func (b *remotePeerTLSBinding) connectionClosed(id uint64) {
	b.proofMu.Lock()
	delete(b.connections, id)
	b.proofMu.Unlock()
}

func (b *remotePeerTLSBinding) clearConnections() {
	b.proofMu.Lock()
	b.connections = make(map[uint64]remotePeerActiveConn)
	b.refreshing = nil
	b.proofMu.Unlock()
}

// refreshTransports closes every active authenticated socket and waits, at
// most grace, for the handshake of the transport that replaces it. While it
// waits, evidenceAt reports the closed transport's proof so that a refresh the
// client started is not seen as a lost peer. It returns the proof of the new
// transport, or an error once grace or ctx ends without a handshake; the
// grace is cleared on that error, so the evidence is then unavailable.
func (b *remotePeerTLSBinding) refreshTransports(ctx context.Context, grace time.Duration, now func() time.Time) (remoteTLSProof, error) {
	if b == nil {
		return remoteTLSProof{}, errRemotePeerEvidenceUnavailable
	}
	b.proofMu.Lock()
	proof, err := b.currentProofLocked(now())
	if err != nil {
		b.proofMu.Unlock()
		return remoteTLSProof{}, fmt.Errorf("cannot refresh an unverified remote peer transport: %w", err)
	}
	sockets := make([]net.Conn, 0, len(b.connections))
	for _, active := range b.connections {
		sockets = append(sockets, active.conn)
	}
	b.connections = make(map[uint64]remotePeerActiveConn)
	b.refreshing = &remotePeerRefresh{proof: proof, until: now().Add(grace)}
	if b.handshakes == nil {
		b.handshakes = make(chan struct{})
	}
	handshake := b.handshakes
	b.proofMu.Unlock()

	// Close outside the lock: the tracked wrapper's Close takes it again when
	// gRPC notices the dead transport.
	for _, socket := range sockets {
		if socket != nil {
			_ = socket.Close()
		}
	}

	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-handshake:
	case <-timer.C:
		b.endRefresh()
		return remoteTLSProof{}, errRemotePeerRefreshTimedOut
	case <-ctx.Done():
		b.endRefresh()
		return remoteTLSProof{}, ctx.Err()
	}
	b.proofMu.Lock()
	defer b.proofMu.Unlock()
	return b.currentProofLocked(now())
}

func (b *remotePeerTLSBinding) endRefresh() {
	b.proofMu.Lock()
	b.refreshing = nil
	b.proofMu.Unlock()
}

// currentProofLocked is the lease over every active transport: one identity,
// the earliest NotAfter. During a refresh grace with no active transport it is
// the proof of the transport the refresh closed.
func (b *remotePeerTLSBinding) currentProofLocked(now time.Time) (remoteTLSProof, error) {
	if len(b.connections) == 0 {
		if b.refreshing != nil && now.Before(b.refreshing.until) && now.Before(b.refreshing.proof.notAfter) {
			return b.refreshing.proof, nil
		}
		return remoteTLSProof{}, errRemotePeerEvidenceUnavailable
	}
	var proof remoteTLSProof
	first := true
	for _, active := range b.connections {
		if !now.Before(active.proof.notAfter) {
			return remoteTLSProof{}, fmt.Errorf("pinned remote peer certificate expired at %s", active.proof.notAfter.UTC().Format(time.RFC3339))
		}
		if first {
			proof = active.proof
			first = false
			continue
		}
		if active.proof.spki != proof.spki || active.proof.identityEpoch != proof.identityEpoch {
			return remoteTLSProof{}, fmt.Errorf("multiple pinned TLS identities are active; remote peer lease is withdrawn until the old transport closes")
		}
		if active.proof.notAfter.Before(proof.notAfter) {
			proof.notAfter = active.proof.notAfter
		}
	}
	return proof, nil
}

func (b *remotePeerTLSBinding) evidence(lastHeartbeat time.Time) (RemotePeerEvidence, error) {
	return b.evidenceAt(lastHeartbeat, time.Now())
}

func (b *remotePeerTLSBinding) evidenceAt(lastHeartbeat, now time.Time) (RemotePeerEvidence, error) {
	if b == nil {
		return nil, errRemotePeerEvidenceUnavailable
	}
	b.proofMu.Lock()
	proof, err := b.currentProofLocked(now)
	b.proofMu.Unlock()
	if err != nil {
		return nil, err
	}
	e := remotePeerEvidence{
		name: b.clusterName, id: b.clusterID,
		identityEpoch: proof.identityEpoch, notAfter: proof.notAfter,
		heartbeatAt: lastHeartbeat, spki: proof.spki, profileID: b.profileID,
	}
	if err := e.Validate(now); err != nil {
		return nil, err
	}
	return e, nil
}

// remotePeerTransportCredentials wraps the native gRPC TLS credentials used
// by the etcd client. The returned connection's Close removes its exact proof
// from the active set; evidence cannot outlive the transport that established
// it.
type remotePeerTransportCredentials struct {
	base    grpccredentials.TransportCredentials
	binding *remotePeerTLSBinding
}

func (c *remotePeerTransportCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, grpccredentials.AuthInfo, error) {
	conn, authInfo, err := c.base.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		return nil, nil, err
	}
	tlsInfo, ok := authInfo.(grpccredentials.TLSInfo)
	if !ok {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("remote etcd transport did not return TLS connection state")
	}
	id, err := c.binding.connectionOpened(tlsInfo.State, conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return &remotePeerTrackedConn{Conn: conn, closeProof: func() { c.binding.connectionClosed(id) }}, authInfo, nil
}

func (c *remotePeerTransportCredentials) ServerHandshake(net.Conn) (net.Conn, grpccredentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("remote ClusterMesh peer credentials are client-only")
}

func (c *remotePeerTransportCredentials) Info() grpccredentials.ProtocolInfo { return c.base.Info() }

func (c *remotePeerTransportCredentials) Clone() grpccredentials.TransportCredentials {
	return &remotePeerTransportCredentials{base: c.base.Clone(), binding: c.binding}
}

func (c *remotePeerTransportCredentials) OverrideServerName(name string) error {
	return c.base.OverrideServerName(name)
}

type remotePeerTrackedConn struct {
	net.Conn
	closeOnce  sync.Once
	closeProof func()
}

func (c *remotePeerTrackedConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(c.closeProof)
	return err
}

func newRemotePeerTransportCredentials(config *tls.Config, binding *remotePeerTLSBinding) (grpccredentials.TransportCredentials, error) {
	configured, err := configureRemotePeerTLS(config, binding)
	if err != nil {
		return nil, err
	}
	if configured == nil || binding == nil {
		return nil, fmt.Errorf("remote peer transport credentials require TLS and a pinned peer profile")
	}
	return &remotePeerTransportCredentials{base: grpccredentials.NewTLS(configured), binding: binding}, nil
}

func configureRemotePeerTLS(config *tls.Config, binding *remotePeerTLSBinding) (*tls.Config, error) {
	if binding == nil {
		return config, nil
	}
	if config == nil {
		return nil, fmt.Errorf("remote peer pin profile requires etcd TLS")
	}
	if config.InsecureSkipVerify {
		return nil, fmt.Errorf("remote peer pin profile rejects InsecureSkipVerify")
	}
	configured := config.Clone()
	prior := configured.VerifyConnection
	configured.VerifyConnection = func(state tls.ConnectionState) error {
		if prior != nil {
			if err := prior(state); err != nil {
				return err
			}
		}
		return binding.VerifyConnection(state)
	}
	return configured, nil
}

func (e *etcdClient) CurrentRemotePeerEvidence() (RemotePeerEvidence, error) {
	if e.remotePeerTLS == nil {
		return nil, errRemotePeerEvidenceUnavailable
	}
	if err := e.client.Ctx().Err(); err != nil {
		return nil, fmt.Errorf("remote etcd client is closed: %w", err)
	}
	e.RWMutex.RLock()
	lastHeartbeat := e.lastObservedHeartbeat
	e.RWMutex.RUnlock()
	return e.remotePeerTLS.evidence(lastHeartbeat)
}

// RefreshRemotePeerTransport re-handshakes this client's pinned transports in
// place: the sockets are closed, gRPC redials at once and presents the client
// certificate that the per-handshake reloader reads from disk now, and the
// etcd watch client resumes each watch at its last revision. The evidence of
// the new transport is returned; its NotAfter is the renewed server leaf's.
func (e *etcdClient) RefreshRemotePeerTransport(ctx context.Context, grace time.Duration) (RemotePeerEvidence, error) {
	if e.remotePeerTLS == nil {
		return nil, errRemotePeerEvidenceUnavailable
	}
	if err := e.client.Ctx().Err(); err != nil {
		return nil, fmt.Errorf("remote etcd client is closed: %w", err)
	}
	if grace <= 0 {
		return nil, fmt.Errorf("remote peer transport refresh requires a positive grace")
	}
	if _, err := e.remotePeerTLS.refreshTransports(ctx, grace, time.Now); err != nil {
		return nil, err
	}
	return e.CurrentRemotePeerEvidence()
}

func (e *etcdClient) BindRemotePeer(expectedName string, advertisedClusterID uint32) (BackendOperations, error) {
	if e.remotePeerTLS == nil {
		return nil, fmt.Errorf("remote etcd client has no administrator-pinned peer profile")
	}
	if err := validateRemotePeerBinding(e.remotePeerTLS, expectedName, advertisedClusterID); err != nil {
		return nil, err
	}
	if err := e.remotePeerTLS.requireCurrentTLSProof(time.Now()); err != nil {
		return nil, fmt.Errorf("cannot bind an unverified TLS peer: %w", err)
	}
	return &authenticatedRemotePeerBackend{BackendOperations: e, provider: e, binding: e.remotePeerTLS}, nil
}

func (b *remotePeerTLSBinding) requireCurrentTLSProof(now time.Time) error {
	if b == nil || b.profileID == [sha256.Size]byte{} {
		return errRemotePeerEvidenceUnavailable
	}
	_, err := b.evidenceAt(now, now)
	return err
}

func validateRemotePeerBinding(binding *remotePeerTLSBinding, expectedName string, advertisedClusterID uint32) error {
	if binding == nil {
		return errRemotePeerEvidenceUnavailable
	}
	if expectedName != binding.clusterName {
		return fmt.Errorf("remote etcd peer name %q does not match configured name %q", expectedName, binding.clusterName)
	}
	if advertisedClusterID != binding.clusterID {
		return fmt.Errorf("remote CiliumClusterConfig ID %d does not match pinned ID %d for %q", advertisedClusterID, binding.clusterID, expectedName)
	}
	return nil
}

var _ RemotePeerBackendBinder = (*etcdClient)(nil)
var _ RemotePeerEvidenceProvider = (*etcdClient)(nil)
var _ RemotePeerTransportRefresher = (*etcdClient)(nil)
var _ RemotePeerTransportRefresher = (*authenticatedRemotePeerBackend)(nil)

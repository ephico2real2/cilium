// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/clustermesh/clustercfg"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	ztmembership "github.com/cilium/cilium/pkg/ztunnel/membership"
)

const (
	originConfigMaxBytes = 64 * 1024
	originPollInterval   = 2 * time.Second
	originRetryMin       = 250 * time.Millisecond
	originRetryMax       = 10 * time.Second
	originConnectTimeout = 30 * time.Second
	originStopGrace      = 2 * time.Second
	// originRefreshLead is how long before the session lease ends the
	// supervisor re-handshakes the transport. cert-manager must renew the
	// client certificate earlier than this (the chart's renewBefore is 1 h).
	originRefreshLead = 10 * time.Minute
	// originRefreshGrace bounds a transport refresh: the time the previous
	// transport's evidence stays usable while gRPC redials, and the time a
	// refresh may take before the session is withdrawn.
	originRefreshGrace = 5 * time.Second
	// originRefreshRetry is the least time between two refreshes of one
	// session, so that a lease that a refresh could not extend (the renewed
	// credential is not on disk yet) does not redial on every poll.
	originRefreshRetry = time.Minute
	logOriginStage     = "stage"
	logOriginLeaseEnd  = "leaseEnd"
)

var errOriginConfigChanged = errors.New("origin configuration changed")
var errOriginLeaseExpired = errors.New("origin session lease expired without a fresh TLS handshake")
var errOriginWatchDidNotStop = errors.New("direct-origin watch did not stop after backend close")
var errOriginFactoryDidNotStop = errors.New("direct-origin client factory did not stop after cancellation")

// OriginPeerConfig is an immutable, secret-safe view of one direct-origin
// ClusterMesh client profile. It intentionally omits all key and certificate
// bytes. Fingerprint covers the trust of the session: the peer name and
// ClusterID, the config file (endpoints, pin, host aliases, file names) and
// the trusted CA bundle; a change restarts the session with a withdrawal.
// CredentialFingerprint covers the client certificate and key only: a change
// is a renewal, which the session takes up with a transport refresh, not a
// restart (the etcd client reloads these files at every TLS handshake).
// ClientCertificateEnd is the end of the shortest verified chain of the
// credential on disk now.
type OriginPeerConfig struct {
	Name                  string
	ExpectedClusterID     uint32
	Path                  string
	Fingerprint           [sha256.Size]byte
	CredentialFingerprint [sha256.Size]byte
	ClientCertificateEnd  time.Time
	RemotePeer            *kvstore.RemotePeerIdentityConfig
	HostAliases           []common.HostAlias
}

// OriginPeerConfigLoader loads a direct-origin file from a separate, read-only
// mount. Implementations must reject missing pins, insecure endpoints, paths
// outside the mount, malformed certificates, and stale credentials.
type OriginPeerConfigLoader interface {
	Load(name string, expectedClusterID uint32) (OriginPeerConfig, error)
}

// FilesystemOriginPeerConfigLoader reads one etcd client YAML file named after
// the peer, for example /var/lib/cilium/clustermesh-origin/cluster-beta.
type FilesystemOriginPeerConfigLoader struct {
	Directory                string
	ExpectedClientCommonName string
	Now                      func() time.Time
}

type originEtcdConfig struct {
	Endpoints         []string                          `json:"endpoints" yaml:"endpoints"`
	TrustedCAFile     string                            `json:"trusted-ca-file" yaml:"trusted-ca-file"`
	CertFile          string                            `json:"cert-file" yaml:"cert-file"`
	KeyFile           string                            `json:"key-file" yaml:"key-file"`
	CiliumHostAliases []common.HostAlias                `json:"cilium-host-aliases" yaml:"cilium-host-aliases"`
	CiliumRemotePeer  *kvstore.RemotePeerIdentityConfig `json:"cilium-remote-peer" yaml:"cilium-remote-peer"`
}

func (l FilesystemOriginPeerConfigLoader) Load(name string, expectedClusterID uint32) (OriginPeerConfig, error) {
	if err := cmtypes.ValidateClusterName(name); err != nil {
		return OriginPeerConfig{}, fmt.Errorf("invalid origin peer name: %w", err)
	}
	if err := cmtypes.ValidateClusterID(expectedClusterID); err != nil {
		return OriginPeerConfig{}, fmt.Errorf("invalid expected origin ClusterID: %w", err)
	}
	root, err := filepath.EvalSymlinks(l.Directory)
	if err != nil {
		return OriginPeerConfig{}, fmt.Errorf("resolve origin config directory: %w", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return OriginPeerConfig{}, fmt.Errorf("resolve origin config directory: %w", err)
	}
	path := filepath.Join(root, name)
	resolvedPath, err := resolveWithin(root, path)
	if err != nil {
		return OriginPeerConfig{}, fmt.Errorf("resolve origin peer config: %w", err)
	}
	configBytes, configMode, err := readSecretFile(resolvedPath, originConfigMaxBytes)
	if err != nil {
		return OriginPeerConfig{}, fmt.Errorf("read origin peer config: %w", err)
	}
	if configMode.Perm()&0o077 != 0 {
		return OriginPeerConfig{}, fmt.Errorf("origin peer config must not be group- or world-readable")
	}
	if l.ExpectedClientCommonName == "" {
		return OriginPeerConfig{}, fmt.Errorf("expected origin client certificate common name is not configured")
	}

	var etcdConfig originEtcdConfig
	if err := yaml.Unmarshal(configBytes, &etcdConfig); err != nil {
		return OriginPeerConfig{}, fmt.Errorf("parse origin etcd client config: %w", err)
	}
	if etcdConfig.CiliumRemotePeer == nil {
		return OriginPeerConfig{}, fmt.Errorf("origin peer is missing the administrator-pinned cilium-remote-peer profile")
	}
	if etcdConfig.CiliumRemotePeer.ClusterID != expectedClusterID {
		return OriginPeerConfig{}, fmt.Errorf("origin peer pin ClusterID %d does not match expected ClusterID %d", etcdConfig.CiliumRemotePeer.ClusterID, expectedClusterID)
	}
	if err := etcdConfig.CiliumRemotePeer.Validate(); err != nil {
		return OriginPeerConfig{}, fmt.Errorf("invalid origin peer pin: %w", err)
	}
	if err := validateOriginHostAliases(etcdConfig.CiliumHostAliases); err != nil {
		return OriginPeerConfig{}, err
	}
	if len(etcdConfig.Endpoints) == 0 || len(etcdConfig.Endpoints) > 16 {
		return OriginPeerConfig{}, fmt.Errorf("origin config requires 1..16 endpoints")
	}
	for _, endpoint := range etcdConfig.Endpoints {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return OriginPeerConfig{}, fmt.Errorf("origin endpoint must be an https URL with an explicit host and port")
		}
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return OriginPeerConfig{}, fmt.Errorf("origin endpoint has an invalid TCP port")
		}
	}
	if etcdConfig.TrustedCAFile == "" || etcdConfig.CertFile == "" || etcdConfig.KeyFile == "" {
		return OriginPeerConfig{}, fmt.Errorf("origin etcd config requires a trusted CA, read-only client certificate, and client key")
	}

	var clientCertificateEnd time.Time
	trustedRoots := x509.NewCertPool()
	hash := sha256.New()
	writeOriginHashPart(hash, []byte(name))
	writeOriginHashPart(hash, []byte(strconv.FormatUint(uint64(expectedClusterID), 10)))
	writeOriginHashPart(hash, configBytes)
	credentialHash := sha256.New()
	tlsContents := make(map[string][]byte, 3)
	for _, filePath := range []string{etcdConfig.TrustedCAFile, etcdConfig.CertFile, etcdConfig.KeyFile} {
		if !filepath.IsAbs(filePath) {
			return OriginPeerConfig{}, fmt.Errorf("origin TLS file paths must be absolute paths inside the read-only mount")
		}
		resolved, err := resolveWithin(root, filePath)
		if err != nil {
			return OriginPeerConfig{}, fmt.Errorf("resolve origin TLS file: %w", err)
		}
		contents, mode, err := readSecretFile(resolved, originConfigMaxBytes)
		if err != nil {
			return OriginPeerConfig{}, fmt.Errorf("read origin TLS file: %w", err)
		}
		if mode.Perm()&0o077 != 0 {
			return OriginPeerConfig{}, fmt.Errorf("origin TLS files must not be group- or world-readable")
		}
		writeOriginHashPart(hash, []byte(filepath.Base(filePath)))
		tlsContents[filePath] = contents
		if filePath == etcdConfig.TrustedCAFile {
			writeOriginHashPart(hash, contents)
			if !trustedRoots.AppendCertsFromPEM(contents) {
				return OriginPeerConfig{}, fmt.Errorf("origin trusted CA file contains no valid PEM certificates")
			}
		} else {
			writeOriginHashPart(credentialHash, contents)
		}
	}
	pair, err := tls.X509KeyPair(tlsContents[etcdConfig.CertFile], tlsContents[etcdConfig.KeyFile])
	if err != nil {
		return OriginPeerConfig{}, fmt.Errorf("origin client certificate and private key do not form a valid pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return OriginPeerConfig{}, fmt.Errorf("parse origin client certificate: %w", err)
	}
	if leaf.IsCA || leaf.Subject.CommonName != l.ExpectedClientCommonName {
		return OriginPeerConfig{}, fmt.Errorf("origin client certificate common name does not match the configured dedicated reader identity")
	}
	now := time.Now()
	if l.Now != nil {
		now = l.Now()
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return OriginPeerConfig{}, fmt.Errorf("origin client certificate is not currently valid")
	}
	if len(leaf.ExtKeyUsage) != 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return OriginPeerConfig{}, fmt.Errorf("origin client certificate is not valid for client authentication")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return OriginPeerConfig{}, fmt.Errorf("origin client certificate lacks digital-signature usage")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(der)
		if err != nil {
			return OriginPeerConfig{}, fmt.Errorf("parse origin client certificate chain: %w", err)
		}
		intermediates.AddCert(intermediate)
	}
	verifiedChains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         trustedRoots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return OriginPeerConfig{}, fmt.Errorf("origin client certificate is not trusted for client authentication: %w", err)
	}
	clientCertificateEnd = leaf.NotAfter
	// Bound the reader lease to the shortest verified path. A leaf can outlive
	// an intermediate (or a trust anchor); using the leaf expiry alone would
	// keep the source watch trusted after its actual chain stops validating.
	for _, chain := range verifiedChains {
		for _, certificate := range chain {
			if certificate.NotAfter.Before(clientCertificateEnd) {
				clientCertificateEnd = certificate.NotAfter
			}
		}
	}
	if clientCertificateEnd.IsZero() {
		return OriginPeerConfig{}, fmt.Errorf("origin client certificate validity was not checked")
	}

	return OriginPeerConfig{
		Name:                  name,
		ExpectedClusterID:     expectedClusterID,
		Path:                  resolvedPath,
		Fingerprint:           hashOriginDigest(hash.Sum(nil)),
		CredentialFingerprint: hashOriginDigest(credentialHash.Sum(nil)),
		ClientCertificateEnd:  clientCertificateEnd,
		RemotePeer:            etcdConfig.CiliumRemotePeer,
		HostAliases:           etcdConfig.CiliumHostAliases,
	}, nil
}

func validateOriginHostAliases(aliases []common.HostAlias) error {
	seen := make(map[string]struct{}, len(aliases))
	for _, alias := range aliases {
		if alias.Hostname == "" || len(alias.IPs) == 0 {
			return fmt.Errorf("origin host aliases require a hostname and at least one address")
		}
		if _, ok := seen[alias.Hostname]; ok {
			return fmt.Errorf("origin host aliases contain duplicate hostname %q", alias.Hostname)
		}
		seen[alias.Hostname] = struct{}{}
	}
	return nil
}

func writeOriginHashPart(hash io.Writer, value []byte) {
	var length [8]byte
	for i := range length {
		length[len(length)-1-i] = byte(uint64(len(value)) >> (8 * i))
	}
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(value)
}

func resolveWithin(root, path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("origin config path escapes the read-only mount")
	}
	return resolved, nil
}

func readSecretFile(path string, maxBytes int64) ([]byte, os.FileMode, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("origin config inputs must be regular files")
	}
	if info.Size() == 0 || info.Size() > maxBytes {
		return nil, 0, fmt.Errorf("origin config input has invalid size")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err == nil && int64(len(contents)) > maxBytes {
		err = fmt.Errorf("origin config input exceeds size limit")
	}
	return contents, info.Mode(), err
}

// OriginPeerConnection is returned only after the direct server pin and live
// source ClusterID have both been verified. It owns the backend and its
// lifetime; callers must Close it before reconnecting.
type OriginPeerConnection struct {
	Backend       kvstore.BackendOperations
	Evidence      kvstore.RemotePeerEvidenceProvider
	RemoteConfig  cmtypes.CiliumClusterConfig
	ProfileID     [sha256.Size]byte
	IdentityEpoch uint64
	cancel        context.CancelFunc
	closeOnce     sync.Once
}

func (c *OriginPeerConnection) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		if c.Backend != nil {
			c.Backend.Close()
		}
	})
}

// OriginPeerConnectionOpener creates one direct-origin backend. Its production
// implementation uses the normal Cilium etcd factory and binds the peer pin.
type OriginPeerConnectionOpener interface {
	// Open must honor ctx during factory creation, initial readiness, and the
	// live ClusterConfig read. Any backend created on an error or cancellation
	// must be closed before returning; a successful connection owns its client
	// lifetime until Close.
	Open(ctx context.Context, logger *slog.Logger, profile OriginPeerConfig) (*OriginPeerConnection, error)
}

// PinnedEtcdOriginPeerOpener uses the same configured Cilium etcd client
// factory but a distinct origin config and read-only client certificate.
type PinnedEtcdOriginPeerOpener struct {
	Factory          common.RemoteClientFactoryFn
	Logger           *slog.Logger
	ConnectTimeout   time.Duration
	FactoryStopGrace time.Duration
}

func (o PinnedEtcdOriginPeerOpener) Open(ctx context.Context, logger *slog.Logger, profile OriginPeerConfig) (*OriginPeerConnection, error) {
	if o.Factory == nil {
		return nil, fmt.Errorf("direct-origin etcd client factory is unavailable")
	}
	if profile.RemotePeer == nil || profile.RemotePeer.ClusterID != profile.ExpectedClusterID {
		return nil, fmt.Errorf("direct-origin etcd client requires an administrator pin for the expected ClusterID")
	}
	if err := profile.RemotePeer.Validate(); err != nil {
		return nil, fmt.Errorf("invalid direct-origin etcd client pin: %w", err)
	}
	if logger == nil {
		logger = o.Logger
	}
	if logger == nil {
		return nil, fmt.Errorf("direct-origin logger is unavailable")
	}
	fallback := dial.NewContextDialer(logger)
	dialer := fallback
	if len(profile.HostAliases) > 0 {
		dialer = dial.NewStaticContextDialerWithFallback(logger, common.ConvertHostAliasesToPlainMap(profile.HostAliases), fallback)
	}
	extra := kvstore.ExtraOptions{
		NoEndpointStatusChecks: true,
		NoLockQuorumCheck:      true,
		ClusterName:            profile.Name,
		RemotePeerIdentity:     profile.RemotePeer,
		DialOption:             []grpc.DialOption{grpc.WithContextDialer(dialer)},
	}
	if ctx == nil {
		return nil, fmt.Errorf("direct-origin client context is unavailable")
	}
	clientCtx, cancelClient := context.WithCancel(ctx)
	connectTimeout := o.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = originConnectTimeout
	}
	factoryStopGrace := o.FactoryStopGrace
	if factoryStopGrace <= 0 {
		factoryStopGrace = originStopGrace
	}
	attemptCtx, cancelAttempt := context.WithTimeout(ctx, connectTimeout)
	defer cancelAttempt()
	type factoryResult struct {
		backend kvstore.BackendOperations
		ready   chan error
	}
	factoryResults := make(chan factoryResult)
	factoryDone := make(chan struct{})
	go func() {
		defer close(factoryDone)
		backend, ready := o.Factory(clientCtx, logger, profile.Path, extra)
		select {
		case factoryResults <- factoryResult{backend: backend, ready: ready}:
		case <-clientCtx.Done():
			if backend != nil {
				backend.Close()
			}
		}
	}()
	var result factoryResult
	select {
	case result = <-factoryResults:
	case <-attemptCtx.Done():
		cancelClient()
		if err := waitOriginFactoryStop(factoryDone, factoryStopGrace); err != nil {
			return nil, errors.Join(attemptCtx.Err(), err)
		}
		return nil, fmt.Errorf("open direct ClusterMesh origin client: %w", attemptCtx.Err())
	case <-ctx.Done():
		cancelClient()
		if err := waitOriginFactoryStop(factoryDone, factoryStopGrace); err != nil {
			return nil, errors.Join(ctx.Err(), err)
		}
		return nil, ctx.Err()
	}
	backend, ready := result.backend, result.ready
	if backend == nil {
		cancelClient()
		return nil, fmt.Errorf("direct-origin factory returned a nil backend")
	}
	closeBackend := func(candidate kvstore.BackendOperations) {
		cancelClient()
		if candidate != nil {
			candidate.Close()
		}
	}
	if err := waitRemoteClientReady(attemptCtx, ready); err != nil {
		closeBackend(backend)
		return nil, fmt.Errorf("connect to direct ClusterMesh origin: %w", err)
	}
	if err := attemptCtx.Err(); err != nil {
		closeBackend(backend)
		return nil, fmt.Errorf("connect to direct ClusterMesh origin: %w", err)
	}
	remoteConfig, err := clustercfg.Get(attemptCtx, profile.Name, backend)
	if err != nil {
		closeBackend(backend)
		return nil, fmt.Errorf("read direct ClusterMesh origin config: %w", err)
	}
	if remoteConfig.ID != profile.ExpectedClusterID {
		closeBackend(backend)
		return nil, fmt.Errorf("direct origin ClusterID %d does not match configured ClusterID %d", remoteConfig.ID, profile.ExpectedClusterID)
	}
	if remoteConfig.Capabilities.Cached || !remoteConfig.Capabilities.WorkloadIdentityV1 || !remoteConfig.Capabilities.ZtunnelMembershipV1 {
		closeBackend(backend)
		return nil, fmt.Errorf("direct origin does not advertise required workload identity and membership formats")
	}
	binder, ok := backend.(kvstore.RemotePeerBackendBinder)
	if !ok {
		closeBackend(backend)
		return nil, fmt.Errorf("direct-origin backend does not support administrator-pinned peer binding")
	}
	bound, err := binder.BindRemotePeer(profile.Name, remoteConfig.ID)
	if err != nil {
		closeBackend(backend)
		return nil, fmt.Errorf("bind direct origin peer: %w", err)
	}
	closeBound := func() {
		cancelClient()
		bound.Close()
	}
	binding, ok := bound.(kvstore.RemotePeerBindingInfo)
	if !ok {
		closeBound()
		return nil, fmt.Errorf("bound direct-origin backend does not expose peer identity")
	}
	name, id, profileID := binding.PinnedRemotePeer()
	if name != profile.Name || id != profile.ExpectedClusterID || profileID == [sha256.Size]byte{} {
		closeBound()
		return nil, fmt.Errorf("direct-origin peer binding does not match configured name and ClusterID")
	}
	provider, ok := bound.(kvstore.RemotePeerEvidenceProvider)
	if !ok {
		closeBound()
		return nil, fmt.Errorf("bound direct-origin backend has no live peer evidence")
	}
	evidence, err := provider.CurrentRemotePeerEvidence()
	if err != nil {
		closeBound()
		return nil, fmt.Errorf("read direct-origin TLS evidence: %w", err)
	}
	if evidence == nil || evidence.ClusterName() != name || evidence.ClusterID() != id || evidence.ProfileID() != profileID {
		closeBound()
		return nil, fmt.Errorf("direct-origin TLS evidence does not match the pinned peer profile")
	}
	if err := evidence.Validate(time.Now()); err != nil {
		closeBound()
		return nil, fmt.Errorf("validate direct-origin TLS evidence: %w", err)
	}
	if err := attemptCtx.Err(); err != nil {
		closeBound()
		return nil, fmt.Errorf("connect to direct ClusterMesh origin: %w", err)
	}
	return &OriginPeerConnection{
		Backend:       bound,
		Evidence:      provider,
		RemoteConfig:  remoteConfig,
		ProfileID:     profileID,
		IdentityEpoch: evidence.IdentityEpoch(),
		cancel:        cancelClient,
	}, nil
}

func waitOriginFactoryStop(done <-chan struct{}, grace time.Duration) error {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errOriginFactoryDidNotStop
	}
}

func waitRemoteClientReady(ctx context.Context, ready <-chan error) error {
	if ready == nil {
		return fmt.Errorf("direct-origin factory returned a nil readiness channel")
	}
	select {
	case err, open := <-ready:
		if open {
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// OriginPeerWatchSession is one exact-prefix source watch. It must return only
// when ctx is canceled or the underlying session has failed. Implementations
// must withdraw the full previous snapshot on every invalid/end transition.
// Listed reports whether the most recent Run delivered a complete initial
// list; the supervisor restarts its retry backoff after such a session.
type OriginPeerWatchSession interface {
	Run(ctx context.Context, profile OriginPeerConfig, connection *OriginPeerConnection) error
	Listed() bool
}

// IPIdentityOriginWatchSession reuses Inventory and WatchStore for one source
// connection. It never watches KVStoreMesh's cilium/cache prefix.
type IPIdentityOriginWatchSession struct {
	Factory     store.Factory
	ClusterInfo cmtypes.ClusterInfo
	Logger      *slog.Logger
	Joiner      *SourceMembershipJoiner
	OnInventory func(*Inventory, store.WatchStore, store.WatchStore)

	mu          lock.Mutex
	clusterName string
	clusterID   uint32
	listed      atomic.Bool
}

// Listed reports whether the most recent Run delivered a complete initial
// list of the peer's IP identities.
func (s *IPIdentityOriginWatchSession) Listed() bool {
	return s != nil && s.listed.Load()
}

func (s *IPIdentityOriginWatchSession) Run(ctx context.Context, profile OriginPeerConfig, connection *OriginPeerConnection) error {
	if s == nil || s.Factory == nil || s.Logger == nil || s.Joiner == nil || connection == nil || connection.Backend == nil || connection.Evidence == nil {
		return fmt.Errorf("direct-origin watch session dependencies are incomplete")
	}
	s.listed.Store(false)
	s.mu.Lock()
	if s.clusterName == "" {
		s.clusterName = profile.Name
		s.clusterID = profile.ExpectedClusterID
	} else if s.clusterName != profile.Name || s.clusterID != profile.ExpectedClusterID {
		s.mu.Unlock()
		return fmt.Errorf("direct-origin watch session cannot change its pinned cluster identity")
	}
	joiner := s.Joiner
	s.mu.Unlock()

	inventory, err := NewInventory(profile.Name, profile.ExpectedClusterID, s.ClusterInfo, connection.Evidence, joiner)
	if err != nil {
		return err
	}
	inventory.SetOnListDone(func() { s.listed.Store(true) })
	watch := s.Factory.NewWatchStore(
		profile.Name,
		func() store.Key { return &identity.IPIdentityPair{} },
		inventory,
		store.RWSWithSessionObserver(inventory),
	)
	sourceWatch := s.Factory.NewWatchStore(
		profile.Name,
		func() store.Key { return &SourceMembershipKey{} },
		joiner,
		store.RWSWithSessionObserver(joiner),
	)
	if s.OnInventory != nil {
		s.OnInventory(inventory, watch, sourceWatch)
	}
	prefix := kvstore.JoinKey(ipcache.IPIdentitiesPath, ipcache.AddressSpace)
	sourcePrefix := kvstore.JoinKey(ztmembership.SourceMembershipPrefix)
	err = runSourceMembershipWatchPair(ctx, connection.Backend, watch, prefix, sourceWatch, sourcePrefix,
		inventory, joiner, connection.Evidence, profile.Name, profile.ExpectedClusterID)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// OriginPeerInvalidator synchronously withdraws this peer's current security
// snapshot using the consumer's monotonic source revision. Implementations
// must be an atomic local state update; an adapter must not synthesize a
// generation-zero Snapshot or acknowledge invalidation before the consumer
// has stopped using the previous source epoch.
type OriginPeerInvalidator interface {
	InvalidateOriginPeer(name string, clusterID uint32, reason string)
}

// OriginPeerSupervisor gives one peer's direct security watch its own backend,
// config fingerprint, TLS evidence monitor, cancellation and bounded retry.
// It does not own or change the KVStoreMesh route backend.
//
// A session's lease ends at the earlier of the client credential's chain end
// and the peer's server leaf NotAfter, both as presented at the session's
// last TLS handshake. Before the lease ends (RefreshLead), and when the client
// credential files change, the supervisor refreshes the session's transport in
// place through kvstore.RemotePeerTransportRefresher: no withdrawal, no new
// list. A lease that ends without a fresh handshake, or a refresh that is not
// followed by one within RefreshGrace, withdraws the peer.
type OriginPeerSupervisor struct {
	Logger         *slog.Logger
	Loader         OriginPeerConfigLoader
	Opener         OriginPeerConnectionOpener
	Watch          OriginPeerWatchSession
	Invalidator    OriginPeerInvalidator
	PollEvery      time.Duration
	RetryMin       time.Duration
	RetryMax       time.Duration
	StopGrace      time.Duration
	ConnectTimeout time.Duration
	RefreshLead    time.Duration
	RefreshGrace   time.Duration
	RefreshRetry   time.Duration
	Now            func() time.Time
}

// originSessionLease is what the current TLS handshake of a session proves,
// and when the supervisor last refreshed it.
type originSessionLease struct {
	// credentialEnd is the chain end of the client credential on disk when
	// the session's transport last handshook. The presented certificate is
	// the one the etcd client read from disk at that handshake, so the
	// profile loaded at the same poll bounds it from below.
	credentialEnd         time.Time
	credentialFingerprint [sha256.Size]byte
	refreshedAt           time.Time
}

// end is the lease end: the earlier of the client credential's chain end and
// the peer's server leaf NotAfter as seen on the active transport.
func (l originSessionLease) end(evidence kvstore.RemotePeerEvidence) time.Time {
	end := l.credentialEnd
	if evidence != nil && !evidence.CertificateNotAfter().IsZero() && evidence.CertificateNotAfter().Before(end) {
		end = evidence.CertificateNotAfter()
	}
	return end
}

func (s *OriginPeerSupervisor) Run(ctx context.Context, peer string, expectedClusterID uint32) error {
	if s.Loader == nil || s.Opener == nil || s.Watch == nil || s.Invalidator == nil {
		return fmt.Errorf("direct-origin supervisor dependencies are incomplete")
	}
	if s.Logger == nil {
		return fmt.Errorf("direct-origin supervisor logger is unavailable")
	}
	poll := s.PollEvery
	if poll <= 0 {
		poll = originPollInterval
	}
	retryMin := s.RetryMin
	if retryMin <= 0 {
		retryMin = originRetryMin
	}
	retryMax := s.RetryMax
	if retryMax < retryMin {
		retryMax = originRetryMax
	}
	stopGrace := s.StopGrace
	if stopGrace <= 0 {
		stopGrace = originStopGrace
	}
	connectTimeout := s.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = originConnectTimeout
	}
	refresh := originRefreshPolicy{lead: s.RefreshLead, grace: s.RefreshGrace, retry: s.RefreshRetry}
	if refresh.lead <= 0 {
		refresh.lead = originRefreshLead
	}
	if refresh.grace <= 0 {
		refresh.grace = originRefreshGrace
	}
	if refresh.retry <= 0 {
		refresh.retry = originRefreshRetry
	}
	now := s.Now
	if now == nil {
		now = time.Now
	}

	backoff := retryMin
	attempt := uint64(0)
	for ctx.Err() == nil {
		attempt++
		started := now()
		profile, err := s.Loader.Load(peer, expectedClusterID)
		if err == nil {
			err = validateOriginPeerProfile(profile, peer, expectedClusterID, now())
		}
		if err != nil {
			s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "origin config invalid: "+err.Error())
			s.logRetry("load-config", peer, attempt, started, backoff, connectTimeout, err)
			if !waitForRemoteWatchRetry(ctx, backoff) {
				break
			}
			backoff = min(backoff*2, retryMax)
			continue
		}
		// Withdraw any previously served state before opening a new source
		// epoch. The opener may close a failed backend before returning.
		s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "direct-origin connection attempt started")
		connection, opened, cancelSession, err := s.openOriginSession(ctx, peer, expectedClusterID, profile, poll, connectTimeout, now)
		if err != nil {
			s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "origin connection rejected: "+err.Error())
			s.logRetry("connect-origin", peer, attempt, started, backoff, connectTimeout, err)
			if !waitForRemoteWatchRetry(ctx, backoff) {
				break
			}
			backoff = min(backoff*2, retryMax)
			continue
		}
		if connection == nil || connection.Backend == nil || connection.Evidence == nil || connection.ProfileID == [sha256.Size]byte{} || connection.IdentityEpoch == 0 {
			s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "origin opener returned incomplete authenticated connection")
			if cancelSession != nil {
				cancelSession()
			}
			if connection != nil {
				connection.Close()
			}
			err = fmt.Errorf("origin opener returned incomplete authenticated connection")
			s.logRetry("validate-origin", peer, attempt, started, backoff, connectTimeout, err)
			if !waitForRemoteWatchRetry(ctx, backoff) {
				break
			}
			backoff = min(backoff*2, retryMax)
			continue
		}
		if err := validateOriginPeerConnection(profile, connection, now()); err != nil {
			s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "origin connection evidence rejected: "+err.Error())
			cancelSession()
			connection.Close()
			s.logRetry("validate-origin", peer, attempt, started, backoff, connectTimeout, err)
			if !waitForRemoteWatchRetry(ctx, backoff) {
				break
			}
			backoff = min(backoff*2, retryMax)
			continue
		}

		// The credential files may have changed while the connection opened;
		// the handshake used one of the two, so the earlier end bounds it.
		lease := originSessionLease{credentialEnd: profile.ClientCertificateEnd, credentialFingerprint: opened.CredentialFingerprint, refreshedAt: now()}
		if opened.ClientCertificateEnd.Before(lease.credentialEnd) {
			lease.credentialEnd = opened.ClientCertificateEnd
		}
		watchCtx, cancel := context.WithCancel(ctx)
		watchDone := make(chan error, 1)
		go func() { watchDone <- s.Watch.Run(watchCtx, profile, connection) }()
		watchErr, watchReturned := s.monitorSession(ctx, cancel, peer, expectedClusterID, profile, lease, refresh, connection, watchDone, poll, now)
		// Withdraw before cancellation or backend cleanup: stopSession may wait
		// through both grace periods and Backend.Close can block on active I/O.
		s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "direct-origin watch invalidated: "+watchErr.Error())
		cancel()
		cancelSession()
		err = s.stopSession(connection, watchDone, watchReturned, watchErr, stopGrace)
		if errors.Is(err, errOriginWatchDidNotStop) {
			// Do not start another backend while a previous watcher may still be
			// using its connection. The caller must restart the agent after this
			// invariant failure; the denied snapshot remains withdrawn.
			return err
		}
		if ctx.Err() != nil {
			break
		}
		if s.Watch.Listed() {
			// The session listed and served: the peer was reachable. An earlier
			// outage must not make this restart wait its ratcheted delay.
			backoff = retryMin
		}
		s.logRetry("restart-origin-watch", peer, attempt, started, backoff, connectTimeout, err)
		if !waitForRemoteWatchRetry(ctx, backoff) {
			break
		}
		backoff = min(backoff*2, retryMax)
	}
	s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "direct-origin supervisor stopped")
	if ctx.Err() != nil {
		return nil
	}
	return nil
}

type originOpenResult struct {
	connection *OriginPeerConnection
	err        error
}

// openOriginSession bounds both initial connection and config validation while
// checking projected config rotation during the open. sessionCtx is retained
// on success and is canceled only when this watch epoch is withdrawn. On
// success it also returns the profile as loaded after the connection opened,
// so that the session lease can be bounded by the credential on disk then.
func (s *OriginPeerSupervisor) openOriginSession(
	ctx context.Context,
	peer string,
	expectedClusterID uint32,
	initial OriginPeerConfig,
	poll time.Duration,
	timeout time.Duration,
	now func() time.Time,
) (*OriginPeerConnection, OriginPeerConfig, context.CancelFunc, error) {
	sessionCtx, cancelSession := context.WithCancel(ctx)
	opened := make(chan originOpenResult)
	go func() {
		connection, err := s.Opener.Open(sessionCtx, s.Logger.With(logfields.ClusterName, peer), initial)
		select {
		case opened <- originOpenResult{connection: connection, err: err}:
		case <-sessionCtx.Done():
			if connection != nil {
				connection.Close()
			}
		}
	}()

	attemptCtx, cancelAttempt := context.WithTimeout(ctx, timeout)
	defer cancelAttempt()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case result := <-opened:
			if result.err != nil {
				cancelSession()
				return nil, OriginPeerConfig{}, nil, result.err
			}
			if err := attemptCtx.Err(); err != nil {
				cancelSession()
				if result.connection != nil {
					result.connection.Close()
				}
				return nil, OriginPeerConfig{}, nil, err
			}
			current, err := s.Loader.Load(peer, expectedClusterID)
			if err == nil {
				err = validateOriginPeerProfile(current, peer, expectedClusterID, now())
			}
			if err != nil || current.Fingerprint != initial.Fingerprint {
				if err == nil {
					err = errOriginConfigChanged
				}
				s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "origin config changed during connection: "+err.Error())
				cancelSession()
				if result.connection != nil {
					result.connection.Close()
				}
				return nil, OriginPeerConfig{}, nil, fmt.Errorf("origin config changed during connection: %w", err)
			}
			return result.connection, current, cancelSession, nil
		case <-ticker.C:
			current, err := s.Loader.Load(peer, expectedClusterID)
			if err == nil {
				err = validateOriginPeerProfile(current, peer, expectedClusterID, now())
			}
			if err != nil || current.Fingerprint != initial.Fingerprint {
				if err == nil {
					err = errOriginConfigChanged
				}
				s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "origin config changed during connection: "+err.Error())
				cancelSession()
				return nil, OriginPeerConfig{}, nil, fmt.Errorf("origin config changed during connection: %w", err)
			}
		case <-attemptCtx.Done():
			s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "direct-origin connection attempt deadline exceeded")
			cancelSession()
			return nil, OriginPeerConfig{}, nil, fmt.Errorf("direct-origin connection attempt exceeded its deadline: %w", attemptCtx.Err())
		case <-ctx.Done():
			s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "direct-origin connection attempt canceled")
			cancelSession()
			return nil, OriginPeerConfig{}, nil, ctx.Err()
		}
	}
}

// originRefreshPolicy is when and how a session's transport is refreshed.
type originRefreshPolicy struct {
	lead  time.Duration
	grace time.Duration
	retry time.Duration
}

// monitorSession polls the on-disk profile and the live TLS evidence of one
// session until the watch ends or the session must be withdrawn. A trust
// change (Fingerprint), an invalid profile, a changed TLS identity, expired
// evidence and an expired lease end the session. A credential-only change and
// an approaching lease end refresh the transport in place.
func (s *OriginPeerSupervisor) monitorSession(
	ctx context.Context,
	cancel context.CancelFunc,
	peer string,
	expectedClusterID uint32,
	initial OriginPeerConfig,
	lease originSessionLease,
	refresh originRefreshPolicy,
	connection *OriginPeerConnection,
	watchDone <-chan error,
	poll time.Duration,
	now func() time.Time,
) (error, bool) {
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	withdraw := func(reason string, err error) (error, bool) {
		s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, reason+": "+err.Error())
		cancel()
		return fmt.Errorf("%s: %w", reason, err), false
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err(), false
		case err := <-watchDone:
			if err == nil {
				return fmt.Errorf("direct-origin watch exited unexpectedly"), true
			}
			return fmt.Errorf("direct-origin watch failed: %w", err), true
		case <-ticker.C:
			currentProfile, err := s.Loader.Load(peer, expectedClusterID)
			if err == nil {
				err = validateOriginPeerProfile(currentProfile, peer, expectedClusterID, now())
			}
			if err != nil {
				return withdraw("origin config became invalid", err)
			}
			if currentProfile.Fingerprint != initial.Fingerprint {
				s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, errOriginConfigChanged.Error())
				cancel()
				return errOriginConfigChanged, false
			}
			evidence, err := s.currentSessionEvidence(peer, expectedClusterID, initial, connection, now())
			if err != nil {
				return withdraw("direct-origin peer evidence expired or changed", err)
			}
			at := now()
			leaseEnd := lease.end(evidence)
			if !at.Before(leaseEnd) {
				return withdraw("direct-origin session lease expired", fmt.Errorf("%w: lease ended %s", errOriginLeaseExpired, leaseEnd.UTC().Format(time.RFC3339)))
			}
			credentialChanged := currentProfile.CredentialFingerprint != lease.credentialFingerprint
			leaseEnding := !at.Before(leaseEnd.Add(-refresh.lead))
			if !credentialChanged && !leaseEnding {
				continue
			}
			if at.Sub(lease.refreshedAt) < refresh.retry {
				continue
			}
			refresher, ok := connection.Backend.(kvstore.RemotePeerTransportRefresher)
			if !ok {
				// The backend cannot re-handshake in place; the lease end above
				// withdraws the session and the restart presents the new files.
				s.Logger.Warn("Direct-origin backend cannot refresh its TLS transport; the session ends at its lease end",
					logfields.LogSubsys, "ztunnel-remote-workload-origin",
					logOriginStage, "refresh-origin-transport",
					logfields.ClusterName, peer,
					logOriginLeaseEnd, leaseEnd,
				)
				lease.refreshedAt = at
				continue
			}
			started := at
			refreshed, err := refresher.RefreshRemotePeerTransport(ctx, refresh.grace)
			if err == nil {
				// The new transport must prove the same pinned identity; a
				// changed epoch (a new server key) is caught on the next poll
				// and relisted as before.
				_, err = s.currentSessionEvidence(peer, expectedClusterID, initial, connection, now())
			}
			if err != nil {
				// The previous transport is closed and no new handshake proved
				// the peer: fail closed now rather than serve past the lease.
				return withdraw("direct-origin transport refresh failed", err)
			}
			lease.credentialEnd = currentProfile.ClientCertificateEnd
			lease.credentialFingerprint = currentProfile.CredentialFingerprint
			lease.refreshedAt = now()
			s.Logger.Info("Direct-origin transport refreshed in place; the session and its snapshot continue",
				logfields.LogSubsys, "ztunnel-remote-workload-origin",
				logOriginStage, "refresh-origin-transport",
				logfields.ClusterName, peer,
				logfields.Reason, originRefreshReason(credentialChanged, leaseEnding),
				logfields.ElapsedDuration, time.Since(started),
				logOriginLeaseEnd, lease.end(refreshed),
				logfields.Expiration, refreshed.CertificateNotAfter(),
			)
		}
	}
}

func originRefreshReason(credentialChanged, leaseEnding bool) string {
	switch {
	case credentialChanged && leaseEnding:
		return "client credential renewed and lease ending"
	case credentialChanged:
		return "client credential renewed"
	default:
		return "lease ending"
	}
}

// currentSessionEvidence is the live TLS evidence of the session's transport,
// checked against the pinned profile and the identity the session opened with.
func (s *OriginPeerSupervisor) currentSessionEvidence(peer string, expectedClusterID uint32, initial OriginPeerConfig, connection *OriginPeerConnection, now time.Time) (kvstore.RemotePeerEvidence, error) {
	evidence, err := connection.Evidence.CurrentRemotePeerEvidence()
	if err != nil {
		return nil, err
	}
	if evidence == nil {
		return nil, fmt.Errorf("remote peer evidence provider returned no evidence")
	}
	if evidence.ClusterName() != peer || evidence.ClusterID() != expectedClusterID || evidence.ProfileID() != connection.ProfileID || !originProfileAllowsSPKI(initial, evidence.SPKIHash()) {
		return nil, fmt.Errorf("direct-origin TLS identity no longer matches pinned cluster profile")
	}
	if evidence.IdentityEpoch() != connection.IdentityEpoch {
		return nil, fmt.Errorf("direct-origin TLS identity epoch changed; a new full list is required")
	}
	if err := evidence.Validate(now); err != nil {
		return nil, err
	}
	return evidence, nil
}

func validateOriginPeerProfile(profile OriginPeerConfig, expectedName string, expectedID uint32, now time.Time) error {
	if profile.Name != expectedName || profile.ExpectedClusterID != expectedID {
		return fmt.Errorf("origin config name or ClusterID does not match the ClusterMesh peer")
	}
	if profile.Fingerprint == [sha256.Size]byte{} || profile.ClientCertificateEnd.IsZero() || !now.Before(profile.ClientCertificateEnd) {
		return fmt.Errorf("origin config fingerprint or client certificate validity is unavailable")
	}
	if profile.RemotePeer == nil || profile.RemotePeer.ClusterID != expectedID {
		return fmt.Errorf("origin config has no matching administrator pin")
	}
	return profile.RemotePeer.Validate()
}

func validateOriginPeerConnection(profile OriginPeerConfig, connection *OriginPeerConnection, now time.Time) error {
	if connection.RemoteConfig.ID != profile.ExpectedClusterID ||
		connection.RemoteConfig.Capabilities.Cached ||
		!connection.RemoteConfig.Capabilities.WorkloadIdentityV1 ||
		!connection.RemoteConfig.Capabilities.ZtunnelMembershipV1 {
		return fmt.Errorf("direct-origin cluster configuration lacks the required authenticated workload identity and membership formats")
	}
	evidence, err := connection.Evidence.CurrentRemotePeerEvidence()
	if err != nil {
		return fmt.Errorf("read direct-origin TLS evidence: %w", err)
	}
	if evidence == nil {
		return fmt.Errorf("direct-origin TLS evidence is unavailable")
	}
	if evidence.ClusterName() != profile.Name || evidence.ClusterID() != profile.ExpectedClusterID || evidence.ProfileID() != connection.ProfileID || evidence.IdentityEpoch() != connection.IdentityEpoch || !originProfileAllowsSPKI(profile, evidence.SPKIHash()) {
		return fmt.Errorf("direct-origin TLS evidence does not match the configured pinned peer")
	}
	return evidence.Validate(now)
}

func originProfileAllowsSPKI(profile OriginPeerConfig, spki [sha256.Size]byte) bool {
	if profile.RemotePeer == nil || spki == [sha256.Size]byte{} {
		return false
	}
	want := hex.EncodeToString(spki[:])
	return slices.Contains(profile.RemotePeer.SPKISHA256, want)
}

func (s *OriginPeerSupervisor) stopSession(connection *OriginPeerConnection, watchDone <-chan error, watchReturned bool, reason error, grace time.Duration) error {
	if reason == nil {
		reason = fmt.Errorf("origin session stopped")
	}
	if watchReturned {
		connection.Close()
		return reason
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-watchDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			reason = errors.Join(reason, err)
		}
		connection.Close()
		return reason
	case <-timer.C:
		connection.Close()
	}
	second := time.NewTimer(grace)
	defer second.Stop()
	select {
	case err := <-watchDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			reason = errors.Join(reason, err)
		}
		return reason
	case <-second.C:
		return errors.Join(reason, errOriginWatchDidNotStop)
	}
}

func (s *OriginPeerSupervisor) logRetry(stage, peer string, attempt uint64, started time.Time, delay, connectTimeout time.Duration, err error) {
	s.Logger.Warn("Direct-origin membership watch will retry",
		logfields.LogSubsys, "ztunnel-remote-workload-origin",
		logOriginStage, stage,
		logfields.ClusterName, peer,
		logfields.Attempt, attempt,
		logfields.ElapsedDuration, time.Since(started),
		logfields.RetryDelay, delay,
		logfields.Timeout, connectTimeout,
		logfields.Error, err,
	)
}

func hashOriginDigest(digest []byte) [sha256.Size]byte {
	var result [sha256.Size]byte
	copy(result[:], digest)
	return result
}

var _ OriginPeerConfigLoader = FilesystemOriginPeerConfigLoader{}
var _ OriginPeerConnectionOpener = PinnedEtcdOriginPeerOpener{}
var _ OriginPeerWatchSession = (*IPIdentityOriginWatchSession)(nil)

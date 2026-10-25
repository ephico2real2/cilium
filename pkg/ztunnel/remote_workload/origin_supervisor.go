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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const (
	originConfigMaxBytes = 64 * 1024
	originPollInterval   = 2 * time.Second
	originRetryMin       = 250 * time.Millisecond
	originRetryMax       = 10 * time.Second
	originConnectTimeout = 30 * time.Second
	originStopGrace      = 2 * time.Second
	logOriginStage       = "stage"
)

var errOriginConfigChanged = errors.New("origin configuration changed")
var errOriginWatchDidNotStop = errors.New("direct-origin watch did not stop after backend close")
var errOriginFactoryDidNotStop = errors.New("direct-origin client factory did not stop after cancellation")

// OriginPeerConfig is an immutable, secret-safe view of one direct-origin
// ClusterMesh client profile. It intentionally omits all key and certificate
// bytes. Fingerprint covers the config and all referenced TLS files.
type OriginPeerConfig struct {
	Name                 string
	ExpectedClusterID    uint32
	Path                 string
	Fingerprint          [sha256.Size]byte
	ClientCertificateEnd time.Time
	RemotePeer           *kvstore.RemotePeerIdentityConfig
	HostAliases          []common.HostAlias
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
		writeOriginHashPart(hash, contents)
		tlsContents[filePath] = contents
		if filePath == etcdConfig.TrustedCAFile {
			if !trustedRoots.AppendCertsFromPEM(contents) {
				return OriginPeerConfig{}, fmt.Errorf("origin trusted CA file contains no valid PEM certificates")
			}
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
		Name:                 name,
		ExpectedClusterID:    expectedClusterID,
		Path:                 resolvedPath,
		Fingerprint:          hashOriginDigest(hash.Sum(nil)),
		ClientCertificateEnd: clientCertificateEnd,
		RemotePeer:           etcdConfig.CiliumRemotePeer,
		HostAliases:          etcdConfig.CiliumHostAliases,
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
type OriginPeerWatchSession interface {
	Run(ctx context.Context, profile OriginPeerConfig, connection *OriginPeerConnection) error
}

// IPIdentityOriginWatchSession reuses Inventory and WatchStore for one source
// connection. It never watches KVStoreMesh's cilium/cache prefix.
type IPIdentityOriginWatchSession struct {
	Factory     store.Factory
	ClusterInfo cmtypes.ClusterInfo
	Sink        SnapshotSink
	OnListDone  func()
}

func (s IPIdentityOriginWatchSession) Run(ctx context.Context, profile OriginPeerConfig, connection *OriginPeerConnection) error {
	if s.Factory == nil || s.Sink == nil || connection == nil || connection.Backend == nil || connection.Evidence == nil {
		return fmt.Errorf("direct-origin watch session dependencies are incomplete")
	}
	inventory, err := NewInventory(profile.Name, profile.ExpectedClusterID, s.ClusterInfo, connection.Evidence, s.Sink)
	if err != nil {
		return err
	}
	inventory.SetOnListDone(s.OnListDone)
	watch := s.Factory.NewWatchStore(
		profile.Name,
		func() store.Key { return &identity.IPIdentityPair{} },
		inventory,
		store.RWSWithSessionObserver(inventory),
	)
	prefix := kvstore.JoinKey(ipcache.IPIdentitiesPath, ipcache.AddressSpace)
	watch.Watch(ctx, connection.Backend, prefix)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("direct-origin watch returned while its context remained active")
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
	Now            func() time.Time
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
		connection, cancelSession, err := s.openOriginSession(ctx, peer, expectedClusterID, profile, poll, connectTimeout, now)
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

		watchCtx, cancel := context.WithCancel(ctx)
		watchDone := make(chan error, 1)
		go func() { watchDone <- s.Watch.Run(watchCtx, profile, connection) }()
		watchErr, watchReturned := s.monitorSession(ctx, cancel, peer, expectedClusterID, profile, connection, watchDone, poll, now)
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
// on success and is canceled only when this watch epoch is withdrawn.
func (s *OriginPeerSupervisor) openOriginSession(
	ctx context.Context,
	peer string,
	expectedClusterID uint32,
	initial OriginPeerConfig,
	poll time.Duration,
	timeout time.Duration,
	now func() time.Time,
) (*OriginPeerConnection, context.CancelFunc, error) {
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
				return nil, nil, result.err
			}
			if err := attemptCtx.Err(); err != nil {
				cancelSession()
				if result.connection != nil {
					result.connection.Close()
				}
				return nil, nil, err
			}
			current, err := s.Loader.Load(peer, expectedClusterID)
			if err == nil {
				err = validateOriginPeerProfile(current, peer, expectedClusterID, now())
			}
			if err != nil || current.Fingerprint != initial.Fingerprint || current.ClientCertificateEnd != initial.ClientCertificateEnd {
				if err == nil {
					err = errOriginConfigChanged
				}
				s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "origin config changed during connection: "+err.Error())
				cancelSession()
				if result.connection != nil {
					result.connection.Close()
				}
				return nil, nil, fmt.Errorf("origin config changed during connection: %w", err)
			}
			return result.connection, cancelSession, nil
		case <-ticker.C:
			current, err := s.Loader.Load(peer, expectedClusterID)
			if err == nil {
				err = validateOriginPeerProfile(current, peer, expectedClusterID, now())
			}
			if err != nil || current.Fingerprint != initial.Fingerprint || current.ClientCertificateEnd != initial.ClientCertificateEnd {
				if err == nil {
					err = errOriginConfigChanged
				}
				s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "origin config changed during connection: "+err.Error())
				cancelSession()
				return nil, nil, fmt.Errorf("origin config changed during connection: %w", err)
			}
		case <-attemptCtx.Done():
			s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "direct-origin connection attempt deadline exceeded")
			cancelSession()
			return nil, nil, fmt.Errorf("direct-origin connection attempt exceeded its deadline: %w", attemptCtx.Err())
		case <-ctx.Done():
			s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "direct-origin connection attempt canceled")
			cancelSession()
			return nil, nil, ctx.Err()
		}
	}
}

func (s *OriginPeerSupervisor) monitorSession(
	ctx context.Context,
	cancel context.CancelFunc,
	peer string,
	expectedClusterID uint32,
	initial OriginPeerConfig,
	connection *OriginPeerConnection,
	watchDone <-chan error,
	poll time.Duration,
	now func() time.Time,
) (error, bool) {
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
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
				s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "origin config became invalid: "+err.Error())
				cancel()
				return fmt.Errorf("origin config became invalid: %w", err), false
			}
			if currentProfile.Fingerprint != initial.Fingerprint || currentProfile.ClientCertificateEnd != initial.ClientCertificateEnd {
				s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, errOriginConfigChanged.Error())
				cancel()
				return errOriginConfigChanged, false
			}
			evidence, err := connection.Evidence.CurrentRemotePeerEvidence()
			if err == nil && evidence == nil {
				err = fmt.Errorf("remote peer evidence provider returned no evidence")
			}
			if err == nil && (evidence.ClusterName() != peer || evidence.ClusterID() != expectedClusterID || evidence.ProfileID() != connection.ProfileID || !originProfileAllowsSPKI(initial, evidence.SPKIHash())) {
				err = fmt.Errorf("direct-origin TLS identity no longer matches pinned cluster profile")
			}
			if err == nil && evidence.IdentityEpoch() != connection.IdentityEpoch {
				err = fmt.Errorf("direct-origin TLS identity epoch changed; a new full list is required")
			}
			if err == nil {
				err = evidence.Validate(now())
			}
			if err != nil {
				s.Invalidator.InvalidateOriginPeer(peer, expectedClusterID, "direct-origin peer evidence expired or changed: "+err.Error())
				cancel()
				return fmt.Errorf("direct-origin peer evidence expired or changed: %w", err), false
			}
		}
	}
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
var _ OriginPeerWatchSession = IPIdentityOriginWatchSession{}

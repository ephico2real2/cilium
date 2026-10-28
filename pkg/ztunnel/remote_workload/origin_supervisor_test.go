// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
)

type originCertFixture struct {
	dir        string
	configPath string
	caPath     string
	certPath   string
	keyPath    string
	caKey      *ecdsa.PrivateKey
	caCert     *x509.Certificate
}

func newOriginCertFixture(t *testing.T, leafNotAfter time.Time, eku []x509.ExtKeyUsage) originCertFixture {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "origin-test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	fixture := originCertFixture{
		dir:      dir,
		caPath:   filepath.Join(dir, "ca.pem"),
		certPath: filepath.Join(dir, "client.pem"),
		keyPath:  filepath.Join(dir, "client-key.pem"),
		caKey:    caKey,
		caCert:   caCert,
	}
	writeOriginSecretFile(t, fixture.caPath, caPEM, 0o400)
	renewOriginLeaf(t, fixture, leafNotAfter, eku)
	fixture.configPath = filepath.Join(dir, "cluster-beta")
	writeOriginEtcdConfig(t, fixture, "https://etcd.example.test:2379", 17, strings.Repeat("01", sha256.Size), nil)
	return fixture
}

// renewOriginLeaf writes a new client certificate and key signed by the
// fixture's CA: what cert-manager's renewal with rotationPolicy Always does.
func renewOriginLeaf(t *testing.T, fixture originCertFixture, leafNotAfter time.Time, eku []x509.ExtKeyUsage) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ztunnel-origin-reader"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     leafNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, fixture.caCert, &leafKey.PublicKey, fixture.caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	writeOriginSecretFile(t, fixture.certPath, certPEM, 0o400)
	writeOriginSecretFile(t, fixture.keyPath, keyPEM, 0o400)
}

func newOriginCertFixtureWithShortIntermediate(t *testing.T) (originCertFixture, time.Time) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "origin-test-root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "origin-test-intermediate"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(2 * time.Minute),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(12),
		Subject:      pkix.Name{CommonName: "ztunnel-origin-reader"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(4 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	intermediatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	fixture := originCertFixture{
		dir:      dir,
		caPath:   filepath.Join(dir, "ca.pem"),
		certPath: filepath.Join(dir, "client.pem"),
		keyPath:  filepath.Join(dir, "client-key.pem"),
	}
	writeOriginSecretFile(t, fixture.caPath, rootPEM, 0o400)
	writeOriginSecretFile(t, fixture.certPath, append(leafPEM, intermediatePEM...), 0o400)
	writeOriginSecretFile(t, fixture.keyPath, keyPEM, 0o400)
	fixture.configPath = filepath.Join(dir, "cluster-beta")
	writeOriginEtcdConfig(t, fixture, "https://etcd.example.test:2379", 17, strings.Repeat("01", sha256.Size), nil)
	return fixture, intermediate.NotAfter
}

func writeOriginEtcdConfig(t *testing.T, f originCertFixture, endpoint string, id uint32, pin string, aliases []string) {
	t.Helper()
	aliasYAML := "[]"
	if len(aliases) > 0 {
		aliasYAML = ""
		for _, alias := range aliases {
			aliasYAML += fmt.Sprintf("\n  - hostname: %q\n    ips: [\"192.0.2.10\"]", alias)
		}
	}
	contents := fmt.Sprintf(`endpoints: [%q]
trusted-ca-file: %q
cert-file: %q
key-file: %q
cilium-host-aliases: %s
cilium-remote-peer:
  cluster-id: %d
  spki-sha256: [%q]
`, endpoint, f.caPath, f.certPath, f.keyPath, aliasYAML, id, pin)
	writeOriginSecretFile(t, f.configPath, []byte(contents), 0o400)
}

func writeOriginSecretFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func originTestConfigLoader(directory string) FilesystemOriginPeerConfigLoader {
	return FilesystemOriginPeerConfigLoader{Directory: directory, ExpectedClientCommonName: "ztunnel-origin-reader"}
}

func TestFilesystemOriginPeerConfigLoaderValidatesAndFingerprintsSecret(t *testing.T) {
	fixture := newOriginCertFixture(t, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	loader := originTestConfigLoader(fixture.dir)
	profile, err := loader.Load("cluster-beta", 17)
	if err != nil {
		t.Fatal(err)
	}
	if profile.RemotePeer == nil || profile.RemotePeer.ClusterID != 17 || profile.Name != "cluster-beta" {
		t.Fatalf("pinned origin identity was not preserved: %+v", profile)
	}
	if profile.Fingerprint == [sha256.Size]byte{} || !time.Now().Before(profile.ClientCertificateEnd) {
		t.Fatalf("origin config did not produce an active fingerprint and bounded client certificate: %+v", profile)
	}

	writeOriginEtcdConfig(t, fixture, "https://etcd-rotated.example.test:2379", 17, strings.Repeat("01", sha256.Size), nil)
	rotated, err := loader.Load("cluster-beta", 17)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Fingerprint == profile.Fingerprint {
		t.Fatal("changed origin endpoint did not change the config fingerprint")
	}
}

func TestFilesystemOriginPeerConfigLoaderBoundsCredentialToVerifiedChainExpiry(t *testing.T) {
	fixture, intermediateExpiry := newOriginCertFixtureWithShortIntermediate(t)
	profile, err := originTestConfigLoader(fixture.dir).Load("cluster-beta", 17)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, err := os.ReadFile(fixture.certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		t.Fatal("fixture leaf certificate is missing")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.NotAfter.After(intermediateExpiry) {
		t.Fatalf("fixture leaf expires at %s, want after intermediate expiry %s", leaf.NotAfter, intermediateExpiry)
	}
	if !profile.ClientCertificateEnd.Equal(intermediateExpiry) {
		t.Fatalf("credential expiry %s does not use the shortest verified chain expiry %s", profile.ClientCertificateEnd, intermediateExpiry)
	}
}

func TestFilesystemOriginPeerConfigLoaderRejectsInvalidProfiles(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, f originCertFixture)
	}{
		{
			name: "missing pin",
			mutate: func(t *testing.T, f originCertFixture) {
				writeOriginSecretFile(t, f.configPath, []byte(fmt.Sprintf("endpoints: [https://etcd.example.test:2379]\ntrusted-ca-file: %q\ncert-file: %q\nkey-file: %q\n", f.caPath, f.certPath, f.keyPath)), 0o400)
			},
		},
		{
			name: "wrong cluster id",
			mutate: func(t *testing.T, f originCertFixture) {
				writeOriginEtcdConfig(t, f, "https://etcd.example.test:2379", 18, strings.Repeat("01", sha256.Size), nil)
			},
		},
		{
			name: "non TLS endpoint",
			mutate: func(t *testing.T, f originCertFixture) {
				writeOriginEtcdConfig(t, f, "http://etcd.example.test:2379", 17, strings.Repeat("01", sha256.Size), nil)
			},
		},
		{
			name: "endpoint credentials rejected",
			mutate: func(t *testing.T, f originCertFixture) {
				writeOriginEtcdConfig(t, f, "https://user:password@etcd.example.test:2379", 17, strings.Repeat("01", sha256.Size), nil)
			},
		},
		{
			name: "relative TLS paths rejected",
			mutate: func(t *testing.T, f originCertFixture) {
				contents := fmt.Sprintf("endpoints: [https://etcd.example.test:2379]\ntrusted-ca-file: ca.pem\ncert-file: %q\nkey-file: %q\ncilium-remote-peer:\n  cluster-id: 17\n  spki-sha256: [%q]\n", f.certPath, f.keyPath, strings.Repeat("01", sha256.Size))
				writeOriginSecretFile(t, f.configPath, []byte(contents), 0o400)
			},
		},
		{
			name: "duplicate host alias",
			mutate: func(t *testing.T, f originCertFixture) {
				writeOriginEtcdConfig(t, f, "https://etcd.example.test:2379", 17, strings.Repeat("01", sha256.Size), []string{"etcd.example.test", "etcd.example.test"})
			},
		},
		{
			name: "invalid pin format",
			mutate: func(t *testing.T, f originCertFixture) {
				writeOriginEtcdConfig(t, f, "https://etcd.example.test:2379", 17, "not-a-pin", nil)
			},
		},
		{
			name: "group readable key",
			mutate: func(t *testing.T, f originCertFixture) {
				if err := os.Chmod(f.keyPath, 0o440); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "expired client certificate",
			mutate: func(t *testing.T, f originCertFixture) {
				// Evaluate the currently valid leaf after its NotAfter time.
				future := time.Now().Add(2 * time.Hour)
				loader := originTestConfigLoader(f.dir)
				loader.Now = func() time.Time { return future }
				if _, err := loader.Load("cluster-beta", 17); err == nil {
					t.Fatal("expected expired certificate to be rejected")
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOriginCertFixture(t, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			test.mutate(t, fixture)
			loader := originTestConfigLoader(fixture.dir)
			if test.name == "expired client certificate" {
				return
			}
			if _, err := loader.Load("cluster-beta", 17); err == nil {
				t.Fatal("invalid origin configuration was accepted")
			}
		})
	}
}

func TestFilesystemOriginPeerConfigLoaderRejectsEscapingSecretFiles(t *testing.T) {
	fixture := newOriginCertFixture(t, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	outside := filepath.Join(t.TempDir(), "outside.pem")
	writeOriginSecretFile(t, outside, []byte("not a certificate"), 0o400)
	writeOriginEtcdConfig(t, fixture, "https://etcd.example.test:2379", 17, strings.Repeat("01", sha256.Size), nil)
	contents, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	contents = []byte(strings.ReplaceAll(string(contents), fmt.Sprintf("trusted-ca-file: %q", fixture.caPath), fmt.Sprintf("trusted-ca-file: %q", outside)))
	writeOriginSecretFile(t, fixture.configPath, contents, 0o400)
	if _, err := originTestConfigLoader(fixture.dir).Load("cluster-beta", 17); err == nil {
		t.Fatal("origin TLS input outside the read-only mount was accepted")
	}

	fixture = newOriginCertFixture(t, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	outsideConfig := filepath.Join(t.TempDir(), "peer-config")
	contents, err = os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	writeOriginSecretFile(t, outsideConfig, contents, 0o400)
	if err := os.Remove(fixture.configPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideConfig, fixture.configPath); err != nil {
		t.Fatal(err)
	}
	if _, err := originTestConfigLoader(fixture.dir).Load("cluster-beta", 17); err == nil {
		t.Fatal("origin peer config symlink outside the read-only mount was accepted")
	}
}

func TestFilesystemOriginPeerConfigLoaderRejectsWrongEKUAndCertificateKeyMismatch(t *testing.T) {
	t.Run("server only eku", func(t *testing.T) {
		fixture := newOriginCertFixture(t, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		if _, err := originTestConfigLoader(fixture.dir).Load("cluster-beta", 17); err == nil {
			t.Fatal("server-only certificate was accepted as an etcd client credential")
		}
	})
	t.Run("key mismatch", func(t *testing.T) {
		fixture := newOriginCertFixture(t, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		otherDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
		if err != nil {
			t.Fatal(err)
		}
		writeOriginSecretFile(t, fixture.keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}), 0o400)
		if _, err := originTestConfigLoader(fixture.dir).Load("cluster-beta", 17); err == nil {
			t.Fatal("mismatched etcd client certificate and key were accepted")
		}
	})
}

type originTestBackend struct {
	kvstore.BackendOperations
	value      []byte
	closeCount atomic.Int32
	bound      *originTestBoundBackend
	clientCtx  context.Context
}

func (b *originTestBackend) Get(context.Context, string) ([]byte, error) { return b.value, nil }
func (b *originTestBackend) Close() {
	b.closeCount.Add(1)
}
func (b *originTestBackend) BindRemotePeer(name string, id uint32) (kvstore.BackendOperations, error) {
	if b.bound == nil {
		return nil, errors.New("no bound backend configured")
	}
	b.bound.name, b.bound.id = name, id
	return b.bound, nil
}

type originTestBoundBackend struct {
	kvstore.BackendOperations
	base      *originTestBackend
	name      string
	id        uint32
	profileID [sha256.Size]byte
	provider  kvstore.RemotePeerEvidenceProvider
}

func (b *originTestBoundBackend) Close() { b.base.Close() }
func (b *originTestBoundBackend) PinnedRemotePeer() (string, uint32, [sha256.Size]byte) {
	return b.name, b.id, b.profileID
}
func (b *originTestBoundBackend) CurrentRemotePeerEvidence() (kvstore.RemotePeerEvidence, error) {
	return b.provider.CurrentRemotePeerEvidence()
}

func TestPinnedEtcdOriginPeerOpenerBindsLivePinnedCluster(t *testing.T) {
	profileID := [sha256.Size]byte{2}
	peer := fakePeerEvidence{name: "cluster-beta", id: 17, identityEpoch: 4, spki: originTestSPKI(), profile: profileID, notAfter: time.Now().Add(time.Hour), heartbeat: time.Now()}
	provider := &fakePeerEvidenceProvider{evidence: peer}
	var backend *originTestBackend
	var received kvstore.ExtraOptions
	// Keep the factory declaration explicitly typed without depending on a global
	// etcd client: the opener's backend and all provenance interfaces are fakes.
	clientFactory := common.RemoteClientFactoryFn(func(ctx context.Context, _ *slog.Logger, path string, extra kvstore.ExtraOptions) (kvstore.BackendOperations, chan error) {
		if path != "/secrets/cluster-beta" {
			t.Errorf("factory received unexpected config path %q", path)
		}
		received = extra
		remoteConfig, err := json.Marshal(requiredRemoteClusterConfig(17))
		if err != nil {
			t.Fatal(err)
		}
		backend = &originTestBackend{value: remoteConfig, clientCtx: ctx}
		backend.bound = &originTestBoundBackend{base: backend, profileID: profileID, provider: provider}
		ready := make(chan error)
		close(ready) // The production etcd factory closes this after initial connect.
		return backend, ready
	})
	config := OriginPeerConfig{
		Name:                 "cluster-beta",
		ExpectedClusterID:    17,
		Path:                 "/secrets/cluster-beta",
		RemotePeer:           &kvstore.RemotePeerIdentityConfig{ClusterID: 17, SPKISHA256: []string{strings.Repeat("01", sha256.Size)}},
		HostAliases:          []common.HostAlias{{Hostname: "etcd.example.test"}},
		ClientCertificateEnd: time.Now().Add(time.Hour),
	}
	connection, err := (PinnedEtcdOriginPeerOpener{Factory: clientFactory}).Open(context.Background(), slogDiscardLogger(), config)
	if err != nil {
		t.Fatal(err)
	}
	if connection.ProfileID != profileID || connection.IdentityEpoch != 4 {
		t.Fatalf("connection did not retain the verified TLS identity: %+v", connection)
	}
	if received.ClusterName != "cluster-beta" || received.RemotePeerIdentity != config.RemotePeer || len(received.DialOption) != 1 || !received.NoEndpointStatusChecks || !received.NoLockQuorumCheck {
		t.Fatalf("direct origin client options were not bounded to the pinned peer: %+v", received)
	}
	connection.Close()
	if backend.closeCount.Load() != 1 {
		t.Fatalf("origin backend closed %d times, want exactly once", backend.closeCount.Load())
	}
	if backend.clientCtx == nil || backend.clientCtx.Err() == nil {
		t.Fatal("closing a successful origin connection did not cancel its client context")
	}
}

func TestPinnedEtcdOriginPeerOpenerRejectsClusterMismatchAndReadyError(t *testing.T) {
	profile := OriginPeerConfig{Name: "cluster-beta", ExpectedClusterID: 17, Path: "/secrets/cluster-beta", RemotePeer: &kvstore.RemotePeerIdentityConfig{ClusterID: 17, SPKISHA256: []string{strings.Repeat("01", sha256.Size)}}}
	t.Run("live cluster id mismatch", func(t *testing.T) {
		value, err := json.Marshal(cmtypes.CiliumClusterConfig{ID: 18})
		if err != nil {
			t.Fatal(err)
		}
		backend := &originTestBackend{value: value}
		ready := make(chan error)
		close(ready)
		factory := common.RemoteClientFactoryFn(func(ctx context.Context, _ *slog.Logger, _ string, _ kvstore.ExtraOptions) (kvstore.BackendOperations, chan error) {
			backend.clientCtx = ctx
			return backend, ready
		})
		if _, err := (PinnedEtcdOriginPeerOpener{Factory: factory}).Open(context.Background(), slogDiscardLogger(), profile); err == nil {
			t.Fatal("live ClusterID mismatch was accepted")
		}
		if backend.closeCount.Load() != 1 {
			t.Fatalf("mismatched backend closed %d times, want 1", backend.closeCount.Load())
		}
	})
	t.Run("missing authenticated workload capabilities", func(t *testing.T) {
		value, err := json.Marshal(cmtypes.CiliumClusterConfig{ID: 17})
		if err != nil {
			t.Fatal(err)
		}
		backend := &originTestBackend{value: value}
		ready := make(chan error)
		close(ready)
		factory := common.RemoteClientFactoryFn(func(ctx context.Context, _ *slog.Logger, _ string, _ kvstore.ExtraOptions) (kvstore.BackendOperations, chan error) {
			backend.clientCtx = ctx
			return backend, ready
		})
		if _, err := (PinnedEtcdOriginPeerOpener{Factory: factory}).Open(context.Background(), slogDiscardLogger(), profile); err == nil || !strings.Contains(err.Error(), "required workload identity and membership formats") {
			t.Fatalf("direct origin lacking authenticated workload capabilities was accepted: %v", err)
		}
		if backend.closeCount.Load() != 1 {
			t.Fatalf("unsupported-capability backend closed %d times, want 1", backend.closeCount.Load())
		}
	})
	t.Run("initial connection error", func(t *testing.T) {
		backend := &originTestBackend{}
		ready := make(chan error, 1)
		ready <- errors.New("TLS pin verification failed")
		close(ready)
		factory := common.RemoteClientFactoryFn(func(ctx context.Context, _ *slog.Logger, _ string, _ kvstore.ExtraOptions) (kvstore.BackendOperations, chan error) {
			backend.clientCtx = ctx
			return backend, ready
		})
		if _, err := (PinnedEtcdOriginPeerOpener{Factory: factory}).Open(context.Background(), slogDiscardLogger(), profile); err == nil || !strings.Contains(err.Error(), "TLS pin verification failed") {
			t.Fatalf("initial TLS error was not returned: %v", err)
		}
		if backend.closeCount.Load() != 1 {
			t.Fatalf("failed backend closed %d times, want 1", backend.closeCount.Load())
		}
		if backend.clientCtx == nil || backend.clientCtx.Err() == nil {
			t.Fatal("failed backend client context remained active")
		}
	})
}

func TestPinnedEtcdOriginPeerOpenerBoundsFactoryAndReadiness(t *testing.T) {
	profile := OriginPeerConfig{Name: "cluster-beta", ExpectedClusterID: 17, Path: "/secrets/cluster-beta", RemotePeer: &kvstore.RemotePeerIdentityConfig{ClusterID: 17, SPKISHA256: []string{strings.Repeat("01", sha256.Size)}}}
	t.Run("factory does not return until canceled", func(t *testing.T) {
		backend := &originTestBackend{}
		factoryExited := make(chan struct{})
		factory := common.RemoteClientFactoryFn(func(ctx context.Context, _ *slog.Logger, _ string, _ kvstore.ExtraOptions) (kvstore.BackendOperations, chan error) {
			defer close(factoryExited)
			backend.clientCtx = ctx
			<-ctx.Done()
			return backend, make(chan error)
		})
		opener := PinnedEtcdOriginPeerOpener{Factory: factory, ConnectTimeout: 20 * time.Millisecond, FactoryStopGrace: time.Second}
		started := time.Now()
		if _, err := opener.Open(context.Background(), slogDiscardLogger(), profile); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("never-ready factory returned %v, want bounded deadline", err)
		}
		if time.Since(started) > time.Second {
			t.Fatal("timed-out client factory exceeded its bounded cleanup window")
		}
		select {
		case <-factoryExited:
		case <-time.After(time.Second):
			t.Fatal("timed-out client factory goroutine leaked")
		}
		if backend.closeCount.Load() != 1 {
			t.Fatalf("late backend close count %d, want 1", backend.closeCount.Load())
		}
		if backend.clientCtx == nil || backend.clientCtx.Err() == nil {
			t.Fatal("timed-out backend client context remained active")
		}
	})
	t.Run("factory returned but never became ready", func(t *testing.T) {
		backend := &originTestBackend{}
		ready := make(chan error)
		factory := common.RemoteClientFactoryFn(func(ctx context.Context, _ *slog.Logger, _ string, _ kvstore.ExtraOptions) (kvstore.BackendOperations, chan error) {
			backend.clientCtx = ctx
			return backend, ready
		})
		opener := PinnedEtcdOriginPeerOpener{Factory: factory, ConnectTimeout: 20 * time.Millisecond}
		started := time.Now()
		if _, err := opener.Open(context.Background(), slogDiscardLogger(), profile); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("never-ready readiness channel returned %v, want bounded deadline", err)
		}
		if time.Since(started) > time.Second {
			t.Fatal("timed-out readiness wait exceeded its bound")
		}
		if backend.closeCount.Load() != 1 {
			t.Fatalf("unready backend close count %d, want 1", backend.closeCount.Load())
		}
		if backend.clientCtx == nil || backend.clientCtx.Err() == nil {
			t.Fatal("unready backend client context remained active")
		}
	})
}

func slogDiscardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

type mutableOriginLoader struct {
	mu      lock.Mutex
	profile OriginPeerConfig
	err     error
}

func (l *mutableOriginLoader) Load(string, uint32) (OriginPeerConfig, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.profile, l.err
}

func (l *mutableOriginLoader) set(profile OriginPeerConfig, err error) {
	l.mu.Lock()
	l.profile, l.err = profile, err
	l.mu.Unlock()
}

type mutableOriginEvidence struct {
	mu       lock.RWMutex
	evidence kvstore.RemotePeerEvidence
}

func (p *mutableOriginEvidence) CurrentRemotePeerEvidence() (kvstore.RemotePeerEvidence, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.evidence, nil
}

func (p *mutableOriginEvidence) set(evidence kvstore.RemotePeerEvidence) {
	p.mu.Lock()
	p.evidence = evidence
	p.mu.Unlock()
}

type testOriginBackend struct {
	kvstore.BackendOperations
	closed       atomic.Int32
	closeOnce    sync.Once
	closeStarted chan struct{}
	closeRelease chan struct{}
	// refresh stands in for the etcd client's in-place TLS re-handshake.
	refresh      func(ctx context.Context, grace time.Duration) (kvstore.RemotePeerEvidence, error)
	refreshCalls atomic.Int32
}

func (b *testOriginBackend) RefreshRemotePeerTransport(ctx context.Context, grace time.Duration) (kvstore.RemotePeerEvidence, error) {
	b.refreshCalls.Add(1)
	if b.refresh == nil {
		return nil, errors.New("test backend has no transport refresh")
	}
	return b.refresh(ctx, grace)
}

// plainOriginBackend cannot re-handshake in place (no RemotePeerTransportRefresher).
type plainOriginBackend struct {
	kvstore.BackendOperations
}

func (plainOriginBackend) Close() {}

func (b *testOriginBackend) Close() {
	b.closeOnce.Do(func() {
		b.closed.Add(1)
		if b.closeStarted != nil {
			close(b.closeStarted)
			<-b.closeRelease
		}
	})
}

type fakeOriginOpener struct {
	evidence   *mutableOriginEvidence
	attempts   atomic.Int32
	opens      atomic.Int32
	backends   []*testOriginBackend
	mu         lock.Mutex
	openErr    error
	failNext   atomic.Int32
	newBackend func() *testOriginBackend
	// backendOps, when set, is the connection's backend instead of a
	// testOriginBackend (for a backend without a transport refresh).
	backendOps func() kvstore.BackendOperations
}

func (o *fakeOriginOpener) Open(context.Context, *slog.Logger, OriginPeerConfig) (*OriginPeerConnection, error) {
	o.attempts.Add(1)
	if remaining := o.failNext.Load(); remaining > 0 && o.failNext.CompareAndSwap(remaining, remaining-1) {
		return nil, errors.New("simulated direct TLS connection failure")
	}
	if o.openErr != nil {
		return nil, o.openErr
	}
	evidence, err := o.evidence.CurrentRemotePeerEvidence()
	if err != nil {
		return nil, err
	}
	if o.backendOps != nil {
		o.opens.Add(1)
		return &OriginPeerConnection{Backend: o.backendOps(), Evidence: o.evidence, RemoteConfig: requiredRemoteClusterConfig(17), ProfileID: evidence.ProfileID(), IdentityEpoch: evidence.IdentityEpoch()}, nil
	}
	backend := &testOriginBackend{}
	if o.newBackend != nil {
		backend = o.newBackend()
	}
	o.mu.Lock()
	o.backends = append(o.backends, backend)
	o.mu.Unlock()
	o.opens.Add(1)
	return &OriginPeerConnection{Backend: backend, Evidence: o.evidence, RemoteConfig: requiredRemoteClusterConfig(17), ProfileID: evidence.ProfileID(), IdentityEpoch: evidence.IdentityEpoch()}, nil
}

type blockingOriginWatch struct {
	started      chan int
	calls        atomic.Int32
	ignoreCancel bool
	release      chan struct{}
	// listsOnStart reports a complete initial list as soon as Run starts.
	listsOnStart bool
	listed       atomic.Bool
}

func (w *blockingOriginWatch) Listed() bool { return w.listed.Load() }

func (w *blockingOriginWatch) Run(ctx context.Context, _ OriginPeerConfig, _ *OriginPeerConnection) error {
	call := int(w.calls.Add(1))
	w.listed.Store(w.listsOnStart)
	w.started <- call
	if w.ignoreCancel {
		<-w.release
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

type failFirstOriginWatch struct {
	started chan int
	calls   atomic.Int32
	// listsBeforeFailing makes the first, failing run report a complete list.
	listsBeforeFailing bool
	listed             atomic.Bool
}

func (w *failFirstOriginWatch) Listed() bool { return w.listed.Load() }

func (w *failFirstOriginWatch) Run(ctx context.Context, _ OriginPeerConfig, _ *OriginPeerConnection) error {
	call := int(w.calls.Add(1))
	w.listed.Store(false)
	w.started <- call
	if call == 1 {
		w.listed.Store(w.listsBeforeFailing)
		return errors.New("simulated origin watch disconnect")
	}
	<-ctx.Done()
	return ctx.Err()
}

type recordingOriginInvalidator struct {
	mu      lock.Mutex
	reasons []string
}

func (i *recordingOriginInvalidator) InvalidateOriginPeer(_ string, _ uint32, reason string) {
	i.mu.Lock()
	i.reasons = append(i.reasons, reason)
	i.mu.Unlock()
}

func (i *recordingOriginInvalidator) contains(needle string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, reason := range i.reasons {
		if strings.Contains(reason, needle) {
			return true
		}
	}
	return false
}

func requiredRemoteClusterConfig(id uint32) cmtypes.CiliumClusterConfig {
	return cmtypes.CiliumClusterConfig{
		ID: id,
		Capabilities: cmtypes.CiliumClusterConfigCapabilities{
			WorkloadIdentityV1:  true,
			ZtunnelMembershipV1: true,
		},
	}
}

func validOriginProfile(fingerprint byte) OriginPeerConfig {
	return OriginPeerConfig{
		Name:                 "cluster-beta",
		ExpectedClusterID:    17,
		Path:                 "/secrets/cluster-beta",
		Fingerprint:          [sha256.Size]byte{fingerprint},
		ClientCertificateEnd: time.Now().Add(time.Hour),
		RemotePeer:           &kvstore.RemotePeerIdentityConfig{ClusterID: 17, SPKISHA256: []string{strings.Repeat("01", sha256.Size)}},
	}
}

func validOriginEvidence(epoch uint64) fakePeerEvidence {
	return fakePeerEvidence{
		name: "cluster-beta", id: 17, identityEpoch: epoch,
		spki: originTestSPKI(), profile: [sha256.Size]byte{2},
		notAfter: time.Now().Add(time.Hour), heartbeat: time.Now(),
	}
}

func originTestSPKI() [sha256.Size]byte {
	var spki [sha256.Size]byte
	for i := range spki {
		spki[i] = 1
	}
	return spki
}

func newOriginSupervisor(loader *mutableOriginLoader, opener *fakeOriginOpener, watch *blockingOriginWatch, invalidator *recordingOriginInvalidator) *OriginPeerSupervisor {
	return &OriginPeerSupervisor{
		Logger: slogDiscardLogger(), Loader: loader, Opener: opener, Watch: watch, Invalidator: invalidator,
		PollEvery: 5 * time.Millisecond, RetryMin: time.Millisecond, RetryMax: 4 * time.Millisecond, StopGrace: 20 * time.Millisecond,
	}
}

type rotateDuringOpenOriginOpener struct {
	calls      atomic.Int32
	firstStart chan struct{}
	firstDone  chan struct{}
	evidence   *mutableOriginEvidence
	mu         lock.Mutex
	backends   []*testOriginBackend
}

func (o *rotateDuringOpenOriginOpener) Open(ctx context.Context, _ *slog.Logger, _ OriginPeerConfig) (*OriginPeerConnection, error) {
	if o.calls.Add(1) == 1 {
		close(o.firstStart)
		<-ctx.Done()
		close(o.firstDone)
		return nil, ctx.Err()
	}
	evidence, err := o.evidence.CurrentRemotePeerEvidence()
	if err != nil {
		return nil, err
	}
	backend := &testOriginBackend{}
	o.mu.Lock()
	o.backends = append(o.backends, backend)
	o.mu.Unlock()
	return &OriginPeerConnection{Backend: backend, Evidence: o.evidence, RemoteConfig: requiredRemoteClusterConfig(17), ProfileID: evidence.ProfileID(), IdentityEpoch: evidence.IdentityEpoch()}, nil
}

func receiveWatchStart(t *testing.T, ch <-chan int, want int) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("watch start number %d, want %d", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("watch %d did not start", want)
	}
}

func receiveRunResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		t.Fatal("origin supervisor did not stop")
		return nil
	}
}

func TestOriginSupervisorRotatesConfigAndRequiresFreshSession(t *testing.T) {
	loader := &mutableOriginLoader{profile: validOriginProfile(1)}
	evidence := &mutableOriginEvidence{evidence: validOriginEvidence(1)}
	opener := &fakeOriginOpener{evidence: evidence}
	watch := &blockingOriginWatch{started: make(chan int, 4)}
	invalidator := &recordingOriginInvalidator{}
	supervisor := newOriginSupervisor(loader, opener, watch, invalidator)
	ctx, cancel := context.WithCancel(context.Background())
	run := make(chan error, 1)
	go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
	receiveWatchStart(t, watch.started, 1)
	loader.set(validOriginProfile(2), nil)
	receiveWatchStart(t, watch.started, 2)
	cancel()
	if err := receiveRunResult(t, run); err != nil {
		t.Fatalf("normal cancellation returned an error: %v", err)
	}
	if opener.opens.Load() != 2 {
		t.Fatalf("config rotation opened %d sessions, want 2", opener.opens.Load())
	}
	if !invalidator.contains(errOriginConfigChanged.Error()) {
		t.Fatal("config rotation did not withdraw origin membership")
	}
	opener.mu.Lock()
	defer opener.mu.Unlock()
	for index, backend := range opener.backends {
		if got := backend.closed.Load(); got != 1 {
			t.Fatalf("origin backend %d close count %d, want 1", index, got)
		}
	}
}

func TestOriginSupervisorConfigRotationDuringConnectCancelsAndRetries(t *testing.T) {
	loader := &mutableOriginLoader{profile: validOriginProfile(1)}
	evidence := &mutableOriginEvidence{evidence: validOriginEvidence(1)}
	opener := &rotateDuringOpenOriginOpener{
		firstStart: make(chan struct{}), firstDone: make(chan struct{}), evidence: evidence,
	}
	watch := &blockingOriginWatch{started: make(chan int, 2)}
	invalidator := &recordingOriginInvalidator{}
	supervisor := &OriginPeerSupervisor{
		Logger: slogDiscardLogger(), Loader: loader, Opener: opener, Watch: watch, Invalidator: invalidator,
		PollEvery: 2 * time.Millisecond, RetryMin: time.Millisecond, RetryMax: 4 * time.Millisecond, StopGrace: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := make(chan error, 1)
	go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
	select {
	case <-opener.firstStart:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("first origin connection attempt did not start")
	}
	loader.set(validOriginProfile(2), nil)
	receiveWatchStart(t, watch.started, 1)
	select {
	case <-opener.firstDone:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("rotated config did not cancel the in-progress opener")
	}
	if !invalidator.contains("origin config changed during connection") {
		cancel()
		t.Fatal("config rotation during connection did not synchronously invalidate the source")
	}
	cancel()
	if err := receiveRunResult(t, run); err != nil {
		t.Fatalf("normal cancellation returned an error: %v", err)
	}
	if got := opener.calls.Load(); got < 2 {
		t.Fatalf("config rotation opened %d attempts, want a retry with the new profile", got)
	}
	opener.mu.Lock()
	defer opener.mu.Unlock()
	if len(opener.backends) != 1 || opener.backends[0].closed.Load() != 1 {
		t.Fatalf("post-rotation connection cleanup is incomplete: %+v", opener.backends)
	}
}

func TestOriginSupervisorWithdrawsBeforeBlockingBackendClose(t *testing.T) {
	loader := &mutableOriginLoader{profile: validOriginProfile(1)}
	evidence := &mutableOriginEvidence{evidence: validOriginEvidence(1)}
	backend := &testOriginBackend{closeStarted: make(chan struct{}), closeRelease: make(chan struct{})}
	opener := &fakeOriginOpener{evidence: evidence, newBackend: func() *testOriginBackend { return backend }}
	watch := &blockingOriginWatch{started: make(chan int, 1)}
	invalidator := &recordingOriginInvalidator{}
	supervisor := newOriginSupervisor(loader, opener, watch, invalidator)
	ctx, cancel := context.WithCancel(context.Background())
	run := make(chan error, 1)
	go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
	receiveWatchStart(t, watch.started, 1)
	cancel()
	select {
	case <-backend.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("backend close did not start")
	}
	if !invalidator.contains("direct-origin watch invalidated") {
		close(backend.closeRelease)
		<-run
		t.Fatal("source snapshot was still published when blocking backend close started")
	}
	close(backend.closeRelease)
	if err := receiveRunResult(t, run); err != nil {
		t.Fatalf("normal cancellation returned an error: %v", err)
	}
}

func TestOriginSupervisorReconnectsOnTLSIdentityEpochChange(t *testing.T) {
	loader := &mutableOriginLoader{profile: validOriginProfile(1)}
	evidence := &mutableOriginEvidence{evidence: validOriginEvidence(1)}
	opener := &fakeOriginOpener{evidence: evidence}
	watch := &blockingOriginWatch{started: make(chan int, 4)}
	invalidator := &recordingOriginInvalidator{}
	supervisor := newOriginSupervisor(loader, opener, watch, invalidator)
	ctx, cancel := context.WithCancel(context.Background())
	run := make(chan error, 1)
	go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
	receiveWatchStart(t, watch.started, 1)
	evidence.set(validOriginEvidence(2))
	receiveWatchStart(t, watch.started, 2)
	cancel()
	if err := receiveRunResult(t, run); err != nil {
		t.Fatalf("normal cancellation returned an error: %v", err)
	}
	if opener.opens.Load() != 2 || !invalidator.contains("identity epoch changed") {
		t.Fatalf("TLS epoch change did not force withdrawal and fresh relist: opens=%d invalidated=%v", opener.opens.Load(), invalidator.contains("identity epoch changed"))
	}
}

func TestOriginSupervisorInvalidConfigNeverOpensAndWithdraws(t *testing.T) {
	loader := &mutableOriginLoader{profile: validOriginProfile(1), err: errors.New("pin profile is missing")}
	evidence := &mutableOriginEvidence{evidence: validOriginEvidence(1)}
	opener := &fakeOriginOpener{evidence: evidence}
	watch := &blockingOriginWatch{started: make(chan int, 1)}
	invalidator := &recordingOriginInvalidator{}
	supervisor := newOriginSupervisor(loader, opener, watch, invalidator)
	ctx, cancel := context.WithCancel(context.Background())
	run := make(chan error, 1)
	go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
	deadline := time.After(time.Second)
	for !invalidator.contains("origin config invalid") {
		select {
		case <-deadline:
			t.Fatal("invalid origin config did not invalidate the peer")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := receiveRunResult(t, run); err != nil {
		t.Fatalf("normal cancellation returned an error: %v", err)
	}
	if opener.opens.Load() != 0 {
		t.Fatalf("invalid pin profile opened %d origin backends", opener.opens.Load())
	}
}

func TestValidateOriginPeerConnectionRequiresPinnedCurrentEvidence(t *testing.T) {
	profile := validOriginProfile(1)
	connection := &OriginPeerConnection{
		Backend:       &testOriginBackend{},
		Evidence:      &fakePeerEvidenceProvider{evidence: validOriginEvidence(1)},
		RemoteConfig:  requiredRemoteClusterConfig(17),
		ProfileID:     [sha256.Size]byte{2},
		IdentityEpoch: 1,
	}
	if err := validateOriginPeerConnection(profile, connection, time.Now()); err != nil {
		t.Fatalf("matching pinned TLS evidence rejected: %v", err)
	}
	connection.RemoteConfig.Capabilities.ZtunnelMembershipV1 = false
	if err := validateOriginPeerConnection(profile, connection, time.Now()); err == nil {
		t.Fatal("direct origin without authenticated membership wire support was accepted")
	}
	connection.RemoteConfig = requiredRemoteClusterConfig(17)

	wrongSPKI := validOriginEvidence(1)
	wrongSPKI.spki[0]++
	connection.Evidence = &fakePeerEvidenceProvider{evidence: wrongSPKI}
	if err := validateOriginPeerConnection(profile, connection, time.Now()); err == nil {
		t.Fatal("TLS evidence for an SPKI outside the configured pin set was accepted")
	}

	wrongCluster := validOriginEvidence(1)
	wrongCluster.id++
	connection.Evidence = &fakePeerEvidenceProvider{evidence: wrongCluster}
	if err := validateOriginPeerConnection(profile, connection, time.Now()); err == nil {
		t.Fatal("TLS evidence for a different ClusterID was accepted")
	}
}

func TestOriginSupervisorRetriesConnectionAndWatchFailures(t *testing.T) {
	t.Run("connection failure", func(t *testing.T) {
		loader := &mutableOriginLoader{profile: validOriginProfile(1)}
		evidence := &mutableOriginEvidence{evidence: validOriginEvidence(1)}
		opener := &fakeOriginOpener{evidence: evidence}
		opener.failNext.Store(1)
		watch := &blockingOriginWatch{started: make(chan int, 2)}
		invalidator := &recordingOriginInvalidator{}
		supervisor := newOriginSupervisor(loader, opener, watch, invalidator)
		ctx, cancel := context.WithCancel(context.Background())
		run := make(chan error, 1)
		go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
		receiveWatchStart(t, watch.started, 1)
		cancel()
		if err := receiveRunResult(t, run); err != nil {
			t.Fatalf("normal cancellation returned an error: %v", err)
		}
		if opener.attempts.Load() != 2 || opener.opens.Load() != 1 {
			t.Fatalf("connection failure did not retry once: attempts=%d successful=%d", opener.attempts.Load(), opener.opens.Load())
		}
		if !invalidator.contains("origin connection rejected") {
			t.Fatal("connection failure did not invalidate the origin snapshot")
		}
	})

	t.Run("watch disconnect", func(t *testing.T) {
		loader := &mutableOriginLoader{profile: validOriginProfile(1)}
		evidence := &mutableOriginEvidence{evidence: validOriginEvidence(1)}
		opener := &fakeOriginOpener{evidence: evidence}
		watch := &failFirstOriginWatch{started: make(chan int, 2)}
		invalidator := &recordingOriginInvalidator{}
		supervisor := &OriginPeerSupervisor{
			Logger: slogDiscardLogger(), Loader: loader, Opener: opener, Watch: watch, Invalidator: invalidator,
			PollEvery: 5 * time.Millisecond, RetryMin: time.Millisecond, RetryMax: 4 * time.Millisecond, StopGrace: 20 * time.Millisecond,
		}
		ctx, cancel := context.WithCancel(context.Background())
		run := make(chan error, 1)
		go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
		receiveWatchStart(t, watch.started, 1)
		receiveWatchStart(t, watch.started, 2)
		cancel()
		if err := receiveRunResult(t, run); err != nil {
			t.Fatalf("normal cancellation returned an error: %v", err)
		}
		if opener.opens.Load() != 2 || !invalidator.contains("direct-origin watch invalidated") {
			t.Fatalf("watch failure did not withdraw and reconnect: opens=%d", opener.opens.Load())
		}
	})
}

func TestOriginSupervisorDoesNotOverlapWhenWatchIgnoresCancellation(t *testing.T) {
	loader := &mutableOriginLoader{profile: validOriginProfile(1)}
	evidence := &mutableOriginEvidence{evidence: validOriginEvidence(1)}
	opener := &fakeOriginOpener{evidence: evidence}
	watch := &blockingOriginWatch{started: make(chan int, 2), ignoreCancel: true, release: make(chan struct{})}
	invalidator := &recordingOriginInvalidator{}
	supervisor := newOriginSupervisor(loader, opener, watch, invalidator)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	run := make(chan error, 1)
	go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
	receiveWatchStart(t, watch.started, 1)
	loader.set(validOriginProfile(2), nil)
	err := receiveRunResult(t, run)
	close(watch.release)
	if !errors.Is(err, errOriginWatchDidNotStop) {
		t.Fatalf("stuck watch returned %v, want explicit no-overlap failure", err)
	}
	if opener.opens.Load() != 1 {
		t.Fatalf("supervisor opened %d backends while a watch was still running", opener.opens.Load())
	}
	if !invalidator.contains("direct-origin watch invalidated") {
		t.Fatal("stuck watcher failure did not withdraw peer membership")
	}
}

func TestWaitRemoteClientReadyHandlesErrorClosedAndCanceled(t *testing.T) {
	t.Run("error value", func(t *testing.T) {
		ready := make(chan error, 1)
		ready <- errors.New("connection denied")
		close(ready)
		if err := waitRemoteClientReady(context.Background(), ready); err == nil {
			t.Fatal("connection error was treated as ready")
		}
	})
	t.Run("closed after successful initial connect", func(t *testing.T) {
		ready := make(chan error)
		close(ready)
		if err := waitRemoteClientReady(context.Background(), ready); err != nil {
			t.Fatalf("closed success channel rejected: %v", err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := waitRemoteClientReady(ctx, make(chan error)); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled readiness wait returned %v", err)
		}
	})
}

func TestOriginEndpointValidationRejectsMalformedPorts(t *testing.T) {
	for _, endpoint := range []string{"https://etcd.example.test:0", "https://etcd.example.test:65536", "https://etcd.example.test:abc", "https://etcd.example.test:2379/path"} {
		t.Run(url.QueryEscape(endpoint), func(t *testing.T) {
			fixture := newOriginCertFixture(t, time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			writeOriginEtcdConfig(t, fixture, endpoint, 17, strings.Repeat("01", sha256.Size), nil)
			if _, err := originTestConfigLoader(fixture.dir).Load("cluster-beta", 17); err == nil {
				t.Fatalf("invalid endpoint %q was accepted", endpoint)
			}
		})
	}
}

func TestFilesystemOriginPeerConfigLoaderSeparatesTrustAndCredentialFingerprints(t *testing.T) {
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	fixture := newOriginCertFixture(t, time.Now().Add(time.Hour), eku)
	loader := originTestConfigLoader(fixture.dir)
	before, err := loader.Load("cluster-beta", 17)
	if err != nil {
		t.Fatal(err)
	}
	if before.CredentialFingerprint == [sha256.Size]byte{} {
		t.Fatal("credential fingerprint was not computed")
	}

	// A renewal (new certificate and key, same CA, same config) changes only
	// the credential fingerprint and the credential end.
	renewOriginLeaf(t, fixture, time.Now().Add(2*time.Hour), eku)
	renewed, err := loader.Load("cluster-beta", 17)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Fingerprint != before.Fingerprint {
		t.Fatal("a renewed client certificate changed the trust fingerprint; the session would restart")
	}
	if renewed.CredentialFingerprint == before.CredentialFingerprint {
		t.Fatal("a renewed client certificate did not change the credential fingerprint")
	}
	if !renewed.ClientCertificateEnd.After(before.ClientCertificateEnd) {
		t.Fatalf("renewed credential end %s is not after %s", renewed.ClientCertificateEnd, before.ClientCertificateEnd)
	}

	// A change of the trusted CA bundle (a second root) is a trust change.
	otherCA := newOriginCertFixture(t, time.Now().Add(time.Hour), eku)
	otherPEM, err := os.ReadFile(otherCA.caPath)
	if err != nil {
		t.Fatal(err)
	}
	ownPEM, err := os.ReadFile(fixture.caPath)
	if err != nil {
		t.Fatal(err)
	}
	writeOriginSecretFile(t, fixture.caPath, append(ownPEM, otherPEM...), 0o400)
	bundled, err := loader.Load("cluster-beta", 17)
	if err != nil {
		t.Fatal(err)
	}
	if bundled.Fingerprint == renewed.Fingerprint {
		t.Fatal("a changed trusted CA bundle did not change the trust fingerprint")
	}
	if bundled.CredentialFingerprint != renewed.CredentialFingerprint {
		t.Fatal("a changed trusted CA bundle changed the credential fingerprint")
	}
}

// renewedOriginProfile is validOriginProfile(trust) with a renewed client
// credential: another credential fingerprint and a later chain end.
func renewedOriginProfile(trust, credential byte, end time.Time) OriginPeerConfig {
	profile := validOriginProfile(trust)
	profile.CredentialFingerprint = [sha256.Size]byte{credential}
	profile.ClientCertificateEnd = end
	return profile
}

func waitForCount(t *testing.T, what string, counter *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.After(time.Second)
	for counter.Load() < want {
		select {
		case <-deadline:
			t.Fatalf("%s: %d, want %d", what, counter.Load(), want)
		case <-time.After(time.Millisecond):
		}
	}
}

func TestOriginSupervisorKeepsSessionThroughCredentialOnlyChange(t *testing.T) {
	loader := &mutableOriginLoader{profile: validOriginProfile(1)}
	evidence := &mutableOriginEvidence{evidence: validOriginEvidence(1)}
	backend := &testOriginBackend{}
	backend.refresh = func(context.Context, time.Duration) (kvstore.RemotePeerEvidence, error) {
		// The re-handshake sees the peer's renewed server leaf: same key,
		// same epoch, later NotAfter.
		renewed := validOriginEvidence(1)
		renewed.notAfter = time.Now().Add(3 * time.Hour)
		evidence.set(renewed)
		return renewed, nil
	}
	opener := &fakeOriginOpener{evidence: evidence, newBackend: func() *testOriginBackend { return backend }}
	watch := &blockingOriginWatch{started: make(chan int, 2)}
	invalidator := &recordingOriginInvalidator{}
	supervisor := newOriginSupervisor(loader, opener, watch, invalidator)
	supervisor.RefreshRetry = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	run := make(chan error, 1)
	go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
	receiveWatchStart(t, watch.started, 1)

	// cert-manager renews the client certificate: new certificate and key,
	// the same CA, config and pin.
	loader.set(renewedOriginProfile(1, 2, time.Now().Add(2*time.Hour)), nil)
	waitForCount(t, "transport refreshes after a credential renewal", &backend.refreshCalls, 1)
	// A few more polls: one renewal is one refresh.
	time.Sleep(10 * supervisor.PollEvery)
	cancel()
	if err := receiveRunResult(t, run); err != nil {
		t.Fatalf("normal cancellation returned an error: %v", err)
	}
	if got := backend.refreshCalls.Load(); got != 1 {
		t.Fatalf("credential renewal refreshed the transport %d times, want 1", got)
	}
	if opener.opens.Load() != 1 || watch.calls.Load() != 1 {
		t.Fatalf("credential renewal restarted the session: opens=%d watches=%d, want 1 and 1", opener.opens.Load(), watch.calls.Load())
	}
	if invalidator.contains(errOriginConfigChanged.Error()) || invalidator.contains("transport refresh failed") || invalidator.contains("lease expired") {
		t.Fatalf("credential renewal withdrew the peer: %v", invalidator.reasons)
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("the one backend was closed %d times at shutdown, want 1", backend.closed.Load())
	}
}

func TestOriginSupervisorRefreshesTransportBeforeTheLeaseEnds(t *testing.T) {
	// The client credential lasts 5 h; the peer's server leaf ends in 1 h.
	loader := &mutableOriginLoader{profile: renewedOriginProfile(1, 1, time.Now().Add(5*time.Hour))}
	evidence := &mutableOriginEvidence{evidence: validOriginEvidence(1)}
	backend := &testOriginBackend{}
	backend.refresh = func(context.Context, time.Duration) (kvstore.RemotePeerEvidence, error) {
		renewed := validOriginEvidence(1)
		renewed.notAfter = time.Now().Add(3 * time.Hour)
		evidence.set(renewed)
		return renewed, nil
	}
	opener := &fakeOriginOpener{evidence: evidence, newBackend: func() *testOriginBackend { return backend }}
	watch := &blockingOriginWatch{started: make(chan int, 2)}
	invalidator := &recordingOriginInvalidator{}
	supervisor := newOriginSupervisor(loader, opener, watch, invalidator)
	// The lease (the server leaf, 1 h) is already inside the lead; the
	// credential on disk does not change. After the refresh the lease is
	// the renewed server leaf's (3 h), outside the lead: one refresh.
	supervisor.RefreshLead = 2 * time.Hour
	supervisor.RefreshRetry = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	run := make(chan error, 1)
	go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
	receiveWatchStart(t, watch.started, 1)
	waitForCount(t, "transport refreshes before the lease end", &backend.refreshCalls, 1)
	time.Sleep(10 * supervisor.PollEvery)
	cancel()
	if err := receiveRunResult(t, run); err != nil {
		t.Fatalf("normal cancellation returned an error: %v", err)
	}
	if got := backend.refreshCalls.Load(); got != 1 {
		t.Fatalf("lease-end refresh ran %d times, want 1 (the renewed server leaf moved the lease out of the lead)", got)
	}
	if opener.opens.Load() != 1 || invalidator.contains("lease expired") || invalidator.contains("identity epoch changed") {
		t.Fatalf("lease-end refresh restarted or withdrew the session: opens=%d reasons=%v", opener.opens.Load(), invalidator.reasons)
	}
}

func TestOriginSupervisorWithdrawsWhenTheTransportRefreshFails(t *testing.T) {
	loader := &mutableOriginLoader{profile: validOriginProfile(1)}
	evidence := &mutableOriginEvidence{evidence: validOriginEvidence(1)}
	opener := &fakeOriginOpener{evidence: evidence, newBackend: func() *testOriginBackend {
		return &testOriginBackend{refresh: func(context.Context, time.Duration) (kvstore.RemotePeerEvidence, error) {
			return nil, errors.New("simulated: the peer refused the renewed client certificate")
		}}
	}}
	watch := &blockingOriginWatch{started: make(chan int, 4)}
	invalidator := &recordingOriginInvalidator{}
	supervisor := newOriginSupervisor(loader, opener, watch, invalidator)
	supervisor.RefreshRetry = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	run := make(chan error, 1)
	go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
	receiveWatchStart(t, watch.started, 1)
	loader.set(renewedOriginProfile(1, 2, time.Now().Add(2*time.Hour)), nil)
	// Fail closed: the old transport is gone and no handshake proved the
	// peer, so the peer is withdrawn and a fresh session is opened.
	receiveWatchStart(t, watch.started, 2)
	cancel()
	if err := receiveRunResult(t, run); err != nil {
		t.Fatalf("normal cancellation returned an error: %v", err)
	}
	if !invalidator.contains("direct-origin transport refresh failed") {
		t.Fatalf("failed refresh did not withdraw the peer: %v", invalidator.reasons)
	}
	if opener.opens.Load() != 2 {
		t.Fatalf("failed refresh opened %d sessions, want 2", opener.opens.Load())
	}
	opener.mu.Lock()
	defer opener.mu.Unlock()
	if opener.backends[0].closed.Load() != 1 {
		t.Fatal("the session whose refresh failed was not closed")
	}
}

func TestOriginSupervisorWithdrawsAtTheLeaseEndWithoutARefresh(t *testing.T) {
	start := time.Now()
	var clock atomic.Pointer[time.Time]
	clock.Store(&start)
	now := func() time.Time { return *clock.Load() }

	initial := validOriginProfile(1)
	initial.ClientCertificateEnd = start.Add(time.Hour) // the credential the session handshook with
	loader := &mutableOriginLoader{profile: initial}
	peer := validOriginEvidence(1)
	peer.notAfter = start.Add(5 * time.Hour)
	peer.heartbeat = start
	evidence := &mutableOriginEvidence{evidence: peer}
	opener := &fakeOriginOpener{evidence: evidence, backendOps: func() kvstore.BackendOperations { return plainOriginBackend{} }}
	watch := &blockingOriginWatch{started: make(chan int, 4)}
	invalidator := &recordingOriginInvalidator{}
	supervisor := newOriginSupervisor(loader, opener, watch, invalidator)
	supervisor.Now = now
	ctx, cancel := context.WithCancel(context.Background())
	run := make(chan error, 1)
	go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
	receiveWatchStart(t, watch.started, 1)

	// The credential is renewed on disk (valid for 4 h) but this backend
	// cannot re-handshake in place. Two hours later the session's own
	// credential has expired: the session must not outlive it.
	loader.set(renewedOriginProfile(1, 2, start.Add(4*time.Hour)), nil)
	later := start.Add(2 * time.Hour)
	peer.heartbeat = later
	evidence.set(peer)
	clock.Store(&later)
	receiveWatchStart(t, watch.started, 2)
	cancel()
	if err := receiveRunResult(t, run); err != nil {
		t.Fatalf("normal cancellation returned an error: %v", err)
	}
	if !invalidator.contains("direct-origin session lease expired") {
		t.Fatalf("expired session credential did not withdraw the peer: %v", invalidator.reasons)
	}
	if opener.opens.Load() != 2 {
		t.Fatalf("lease expiry opened %d sessions, want 2", opener.opens.Load())
	}
}

// lockedBuffer collects the supervisor's log lines across goroutines.
type lockedBuffer struct {
	mu  lock.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestOriginSupervisorRestartsBackoffAfterAListedSession(t *testing.T) {
	restartDelay := func(t *testing.T, listed bool) string {
		t.Helper()
		logs := &lockedBuffer{}
		loader := &mutableOriginLoader{profile: validOriginProfile(1)}
		evidence := &mutableOriginEvidence{evidence: validOriginEvidence(1)}
		opener := &fakeOriginOpener{evidence: evidence}
		// Two refused connections (an earlier peer outage) ratchet the
		// backoff from RetryMin to RetryMax before the session opens.
		opener.failNext.Store(2)
		watch := &failFirstOriginWatch{started: make(chan int, 2), listsBeforeFailing: listed}
		invalidator := &recordingOriginInvalidator{}
		supervisor := &OriginPeerSupervisor{
			Logger: slog.New(slog.NewTextHandler(logs, nil)), Loader: loader, Opener: opener, Watch: watch, Invalidator: invalidator,
			PollEvery: 5 * time.Millisecond, RetryMin: time.Millisecond, RetryMax: 4 * time.Millisecond, StopGrace: 20 * time.Millisecond,
		}
		ctx, cancel := context.WithCancel(context.Background())
		run := make(chan error, 1)
		go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
		receiveWatchStart(t, watch.started, 1)
		receiveWatchStart(t, watch.started, 2)
		cancel()
		if err := receiveRunResult(t, run); err != nil {
			t.Fatalf("normal cancellation returned an error: %v", err)
		}
		for _, line := range strings.Split(logs.String(), "\n") {
			if strings.Contains(line, "stage=restart-origin-watch") {
				fields := strings.Fields(line)
				for _, field := range fields {
					if delay, ok := strings.CutPrefix(field, "retryDelay="); ok {
						return delay
					}
				}
			}
		}
		t.Fatalf("no restart-origin-watch log line with a retry delay:\n%s", logs.String())
		return ""
	}
	if got := restartDelay(t, false); got != "4ms" {
		t.Fatalf("a session that never listed restarted after %s, want the ratcheted 4ms", got)
	}
	if got := restartDelay(t, true); got != "1ms" {
		t.Fatalf("a session that listed and served restarted after %s, want RetryMin 1ms", got)
	}
}

func waitForReason(t *testing.T, invalidator *recordingOriginInvalidator, needle string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for !invalidator.contains(needle) {
		select {
		case <-deadline:
			t.Fatalf("no withdrawal containing %q: %v", needle, invalidator.reasons)
		case <-time.After(time.Millisecond):
		}
	}
}

// The poll loads the profile before the refresh; if the files
// change again between that Load and the handshake (here: to a credential
// ending at start+2h30m instead of the start+4h the poll saw), the lease's
// credentialEnd stays at 4h — but the next poll's validateOriginPeerProfile
// withdraws the session at the on-disk credential's end regardless, with no
// second refresh. (Measured on ce5c3ec031: the withdrawal reason is "origin
// config became invalid"; a "lease expired" reason would need a fix that
// bounds credentialEnd by a re-Load after the refresh.)
func TestOriginSupervisorLeaseAfterRefreshIsBoundedByTheCredentialOnDisk(t *testing.T) {
	start := time.Now()
	var clock atomic.Pointer[time.Time]
	clock.Store(&start)
	now := func() time.Time { return *clock.Load() }

	loader := &mutableOriginLoader{profile: renewedOriginProfile(1, 1, start.Add(5*time.Hour))}
	peer := validOriginEvidence(1)
	peer.notAfter = start.Add(6 * time.Hour)
	peer.heartbeat = start
	evidence := &mutableOriginEvidence{evidence: peer}
	backend := &testOriginBackend{}
	backend.refresh = func(context.Context, time.Duration) (kvstore.RemotePeerEvidence, error) {
		// The files changed between this poll's Load and the handshake.
		loader.set(renewedOriginProfile(1, 3, start.Add(150*time.Minute)), nil)
		fresh := peer
		fresh.heartbeat = now()
		evidence.set(fresh)
		return fresh, nil
	}
	opener := &fakeOriginOpener{evidence: evidence, newBackend: func() *testOriginBackend { return backend }}
	watch := &blockingOriginWatch{started: make(chan int, 4)}
	invalidator := &recordingOriginInvalidator{}
	supervisor := newOriginSupervisor(loader, opener, watch, invalidator)
	supervisor.Now = now
	ctx, cancel := context.WithCancel(context.Background())
	run := make(chan error, 1)
	go func() { run <- supervisor.Run(ctx, "cluster-beta", 17) }()
	receiveWatchStart(t, watch.started, 1)

	// Two minutes in, the credential on disk is renewed (ends start+4h): one
	// refresh. During that refresh the files change again (see above).
	t1 := start.Add(2 * time.Minute)
	fresh := peer
	fresh.heartbeat = t1
	evidence.set(fresh)
	clock.Store(&t1)
	loader.set(renewedOriginProfile(1, 2, start.Add(4*time.Hour)), nil)
	waitForCount(t, "transport refreshes after the renewal", &backend.refreshCalls, 1)
	time.Sleep(10 * supervisor.PollEvery)
	if got := backend.refreshCalls.Load(); got != 1 {
		t.Fatalf("refreshed %d times while the clock stood still, want 1", got)
	}

	// At start+2h45m the on-disk credential has ended: the session must be
	// withdrawn by the per-poll profile validation, without another refresh.
	t2 := start.Add(165 * time.Minute)
	fresh.heartbeat = t2
	evidence.set(fresh)
	clock.Store(&t2)
	waitForReason(t, invalidator, "origin config became invalid")
	cancel()
	if err := receiveRunResult(t, run); err != nil {
		t.Fatalf("normal cancellation returned an error: %v", err)
	}
	if got := backend.refreshCalls.Load(); got != 1 {
		t.Fatalf("the session needed %d refreshes before it ended; want 1", got)
	}
}

var _ OriginPeerConfigLoader = FilesystemOriginPeerConfigLoader{}
var _ OriginPeerConnectionOpener = PinnedEtcdOriginPeerOpener{}
var _ OriginPeerWatchSession = (*IPIdentityOriginWatchSession)(nil)

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
)

// testPKI issues ADS server certificates from one test root, as the cluster's
// ClusterMesh intermediate issues kube-system/cmtc-ztunnel-ads-server.
type testPKI struct {
	t     *testing.T
	root  *x509.Certificate
	key   *ecdsa.PrivateKey
	roots *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ads-test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &testPKI{t: t, root: root, key: key, roots: roots}
}

// keyPair is a PEM server certificate and its PKCS#8 key.
type keyPair struct{ cert, key []byte }

// issue returns a server certificate and key with the given serial.
func (p *testPKI) issue(serial int64) keyPair {
	p.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(p.t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "cilium-ztunnel-xds"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.root, &key.PublicKey, p.key)
	require.NoError(p.t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(p.t, err)
	return keyPair{
		cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

// secretVolume lays files out as the kubelet writes a Secret volume: each
// file is a symlink through ..data to a timestamped directory, and an update
// replaces ..data with one atomic rename.
type secretVolume struct {
	t        *testing.T
	dir      string
	revision int
}

func newSecretVolume(t *testing.T, pair keyPair) *secretVolume {
	t.Helper()
	v := &secretVolume{t: t, dir: t.TempDir()}
	v.write(pair)
	for _, name := range []string{"bootstrap-root.crt", "bootstrap-private.key"} {
		require.NoError(t, os.Symlink(filepath.Join("..data", name), filepath.Join(v.dir, name)))
	}
	return v
}

func (v *secretVolume) write(pair keyPair) {
	v.t.Helper()
	v.revision++
	revision := fmt.Sprintf("..revision_%d", v.revision)
	require.NoError(v.t, os.Mkdir(filepath.Join(v.dir, revision), 0o700))
	require.NoError(v.t, os.WriteFile(filepath.Join(v.dir, revision, "bootstrap-root.crt"), pair.cert, 0o600))
	require.NoError(v.t, os.WriteFile(filepath.Join(v.dir, revision, "bootstrap-private.key"), pair.key, 0o600))
	require.NoError(v.t, os.Symlink(revision, filepath.Join(v.dir, "..data_tmp")))
	require.NoError(v.t, os.Rename(filepath.Join(v.dir, "..data_tmp"), filepath.Join(v.dir, "..data")))
}

func (v *secretVolume) certPath() string { return filepath.Join(v.dir, "bootstrap-root.crt") }
func (v *secretVolume) keyPath() string  { return filepath.Join(v.dir, "bootstrap-private.key") }

// lockedBuffer collects log output written by the watcher goroutine.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
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

// startServerTLS serves the gRPC health service with the ADS server
// credentials, the way Serve hosts ADS, on a loopback listener.
func startServerTLS(t *testing.T, v *secretVolume) (addr string, logs *lockedBuffer) {
	t.Helper()
	logs = &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	creds, stop, err := newServerTLSCredentials(log, v.certPath(), v.keyPath())
	require.NoError(t, err)
	server := grpc.NewServer(grpc.Creds(creds))
	healthpb.RegisterHealthServer(server, health.NewServer())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		stop()
	})
	return listener.Addr().String(), logs
}

// handshakeSerial makes a new TLS connection and returns the serial of the
// server certificate it was presented.
func handshakeSerial(addr string, roots *x509.CertPool) (int64, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		NextProtos: []string{"h2"},
	})
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64(), nil
}

// grpcClient is one long-lived client connection that counts its dials, so a
// test can tell an RPC on the established connection from one on a new one.
type grpcClient struct {
	conn  *grpc.ClientConn
	dials atomic.Int32
}

func newGRPCClient(t *testing.T, addr string, roots *x509.CertPool) *grpcClient {
	t.Helper()
	c := &grpcClient{}
	dialer := func(ctx context.Context, target string) (net.Conn, error) {
		c.dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", target)
	}
	conn, err := grpc.NewClient("passthrough:///"+addr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: "localhost"})),
		grpc.WithContextDialer(dialer))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	c.conn = conn
	return c
}

// check makes one RPC and returns the serial its transport was presented.
func (c *grpcClient) check(t *testing.T) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var p peer.Peer
	_, err := healthpb.NewHealthClient(c.conn).Check(ctx, &healthpb.HealthCheckRequest{}, grpc.Peer(&p))
	require.NoError(t, err)
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	require.True(t, ok)
	return info.State.PeerCertificates[0].SerialNumber.Int64()
}

func requireServes(t *testing.T, addr string, roots *x509.CertPool, serial int64) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		got, err := handshakeSerial(addr, roots)
		require.NoError(c, err)
		require.Equal(c, serial, got)
	}, 10*time.Second, 20*time.Millisecond, "new handshakes must present serial %d", serial)
}

// The 2026-10-28 outage on kind-cmtc-a: cert-manager renewed the ADS server
// certificate, the agent kept presenting the pair it read at startup, and the
// first ztunnel reconnect after the old NotAfter failed with "certificate
// expired".
func TestServerTLSPresentsRenewedCertificateToNewHandshakes(t *testing.T) {
	pki := newTestPKI(t)
	v := newSecretVolume(t, pki.issue(3))
	addr, logs := startServerTLS(t, v)
	got, err := handshakeSerial(addr, pki.roots)
	require.NoError(t, err)
	require.Equal(t, int64(3), got)

	v.write(pki.issue(4))
	requireServes(t, addr, pki.roots, 4)
	require.Contains(t, logs.String(), "Keypair updated")
}

// Make before break: ztunnel's established ADS stream outlives the renewal,
// and only connections made after it see the renewed certificate.
func TestServerTLSRenewalKeepsEstablishedConnections(t *testing.T) {
	pki := newTestPKI(t)
	v := newSecretVolume(t, pki.issue(3))
	addr, _ := startServerTLS(t, v)
	established := newGRPCClient(t, addr, pki.roots)
	require.Equal(t, int64(3), established.check(t))

	v.write(pki.issue(4))
	requireServes(t, addr, pki.roots, 4)

	require.Equal(t, int64(3), established.check(t), "the established connection keeps its handshake")
	require.Equal(t, int32(1), established.dials.Load(), "the renewal must not close the established connection")
	fresh := newGRPCClient(t, addr, pki.roots)
	require.Equal(t, int64(4), fresh.check(t))
}

// A pair that does not load (a key that does not match the certificate, or a
// truncated file) keeps the last good pair in service and fails no handshake;
// the next good pair is then picked up.
func TestServerTLSBrokenRenewalKeepsLastGoodPair(t *testing.T) {
	pki := newTestPKI(t)
	v := newSecretVolume(t, pki.issue(3))
	addr, logs := startServerTLS(t, v)

	var handshakes, failures atomic.Int64
	var lastFailure atomic.Value
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := handshakeSerial(addr, pki.roots); err != nil {
				failures.Add(1)
				lastFailure.Store(err.Error())
			}
			handshakes.Add(1)
		}
	})

	v.write(keyPair{cert: pki.issue(4).cert, key: pki.issue(5).key})
	require.Eventually(t, func() bool { return bytes.Contains([]byte(logs.String()), []byte("Keypair update failed")) },
		10*time.Second, 20*time.Millisecond, "a mismatched pair must be logged")
	got, err := handshakeSerial(addr, pki.roots)
	require.NoError(t, err)
	require.Equal(t, int64(3), got, "the last good pair stays in service")

	truncated := pki.issue(6)
	truncated.cert = truncated.cert[:len(truncated.cert)/2]
	v.write(truncated)
	require.Eventually(t, func() bool { return bytes.Count([]byte(logs.String()), []byte("Keypair update failed")) >= 2 },
		10*time.Second, 20*time.Millisecond, "a truncated certificate must be logged")
	got, err = handshakeSerial(addr, pki.roots)
	require.NoError(t, err)
	require.Equal(t, int64(3), got, "the last good pair stays in service")

	v.write(pki.issue(7))
	requireServes(t, addr, pki.roots, 7)

	close(stop)
	wg.Wait()
	require.Positive(t, handshakes.Load())
	require.Zero(t, failures.Load(), "no handshake may fail across the renewals: %v", lastFailure.Load())
}

// The handshake keeps the semantics of credentials.NewServerTLSFromFile: no
// client certificate is requested, ALPN negotiates h2, and TLS 1.2 is the
// lowest version accepted.
func TestServerTLSKeepsHandshakeSemantics(t *testing.T) {
	pki := newTestPKI(t)
	v := newSecretVolume(t, pki.issue(3))
	addr, _ := startServerTLS(t, v)

	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		clientCertRequested := false
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			RootCAs:    pki.roots,
			ServerName: "localhost",
			NextProtos: []string{"h2"},
			MinVersion: version,
			MaxVersion: version,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				clientCertRequested = true
				return &tls.Certificate{}, nil
			},
		})
		require.NoError(t, err)
		state := conn.ConnectionState()
		require.NoError(t, conn.Close())
		require.Equal(t, version, state.Version)
		require.Equal(t, "h2", state.NegotiatedProtocol)
		require.False(t, clientCertRequested, "the ADS server does not ask for a client certificate")
	}

	_, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:    pki.roots,
		ServerName: "localhost",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS11,
		MaxVersion: tls.VersionTLS11,
	})
	require.ErrorContains(t, err, "remote error: tls: protocol version not supported", "the server refuses TLS 1.1")
}

// A missing or unreadable pair still fails the start of the server, as before.
func TestServerTLSFailsWithoutPair(t *testing.T) {
	dir := t.TempDir()
	_, _, err := newServerTLSCredentials(slog.New(slog.DiscardHandler),
		filepath.Join(dir, "bootstrap-root.crt"), filepath.Join(dir, "bootstrap-private.key"))
	require.Error(t, err)
}

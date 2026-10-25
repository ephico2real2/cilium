// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newPeerTLSFixture(t *testing.T, notAfter time.Time) (tls.Certificate, *x509.CertPool, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              notAfter,
		DNSNames:              []string{"etcd.remote.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return cert, roots, hex.EncodeToString(spki[:])
}

func openPinnedTLSConn(t *testing.T, binding *remotePeerTLSBinding, cert tls.Certificate, roots *x509.CertPool, serverName string) (net.Conn, net.Conn, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	clientRaw, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientRaw.Close() })
	serverRaw, err := listener.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverRaw.Close() })
	deadline := time.Now().Add(2 * time.Second)
	require.NoError(t, clientRaw.SetDeadline(deadline))
	require.NoError(t, serverRaw.SetDeadline(deadline))
	creds, err := newRemotePeerTransportCredentials(&tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}, binding)
	require.NoError(t, err)
	server := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}})
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Handshake()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, _, clientErr := creds.ClientHandshake(ctx, serverName, clientRaw)
	if clientErr != nil {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
		<-serverDone
		return nil, nil, clientErr
	}
	select {
	case serverErr := <-serverDone:
		if serverErr != nil {
			_ = client.Close()
			_ = server.Close()
			return nil, nil, serverErr
		}
	case <-time.After(2 * time.Second):
		_ = client.Close()
		_ = server.Close()
		return nil, nil, fmt.Errorf("TLS server handshake timed out")
	}
	require.NoError(t, client.SetDeadline(time.Time{}))
	require.NoError(t, server.SetDeadline(time.Time{}))
	return client, server, nil
}

func TestRemotePeerTLSBindingTracksCertificateIdentityEpoch(t *testing.T) {
	certA, rootsA, pinA := newPeerTLSFixture(t, time.Now().Add(time.Hour))
	certB, rootsB, pinB := newPeerTLSFixture(t, time.Now().Add(2*time.Hour))
	binding, err := newRemotePeerTLSBinding("cluster-beta", &RemotePeerIdentityConfig{ClusterID: 17, SPKISHA256: []string{pinA, pinB}})
	require.NoError(t, err)
	firstConn, firstServer, err := openPinnedTLSConn(t, binding, certA, rootsA, "etcd.remote.test")
	require.NoError(t, err)
	require.NotNil(t, firstConn)
	firstEvidence, err := binding.evidence(time.Now())
	require.NoError(t, err)
	firstEpoch := firstEvidence.IdentityEpoch()
	require.Positive(t, firstEpoch)
	require.WithinDuration(t, certA.Leaf.NotAfter, firstEvidence.CertificateNotAfter(), time.Second)

	// A concurrent reconnect using the same pinned leaf stays in one epoch.
	secondConn, secondServer, err := openPinnedTLSConn(t, binding, certA, rootsA, "etcd.remote.test")
	require.NoError(t, err)
	secondEvidence, err := binding.evidence(time.Now())
	require.NoError(t, err)
	require.Equal(t, firstEpoch, secondEvidence.IdentityEpoch())

	// A newer certificate cannot extend an older still-open transport. While
	// both real gRPC TLS sockets are active, the provider withdraws evidence.
	rotatedConn, rotatedServer, err := openPinnedTLSConn(t, binding, certB, rootsB, "etcd.remote.test")
	require.NoError(t, err)
	_, err = binding.evidence(time.Now())
	require.ErrorContains(t, err, "multiple pinned TLS identities are active")

	// Evaluate beyond certificate A's expiry. The active old socket still
	// blocks evidence even though B has a later NotAfter.
	checkAt := certA.Leaf.NotAfter.Add(time.Second)
	_, err = binding.evidenceAt(checkAt.Add(-time.Second), checkAt)
	require.ErrorContains(t, err, "certificate expired")

	// Only after all old-leaf transports close can the fresh peer identity be
	// used, and that evidence carries B's own expiry and a new epoch.
	require.NoError(t, firstConn.Close())
	require.NoError(t, firstServer.Close())
	require.NoError(t, secondConn.Close())
	require.NoError(t, secondServer.Close())
	rotated, err := binding.evidence(time.Now())
	require.NoError(t, err)
	require.Greater(t, rotated.IdentityEpoch(), firstEpoch)
	require.WithinDuration(t, certB.Leaf.NotAfter, rotated.CertificateNotAfter(), time.Second)
	_ = rotatedConn.Close()
	_ = rotatedServer.Close()
}

func TestRemotePeerTLSBindingRejectsWrongPinAndServerName(t *testing.T) {
	cert, roots, pin := newPeerTLSFixture(t, time.Now().Add(time.Hour))
	wrongPin := sha256.Sum256([]byte("wrong SPKI"))
	binding, err := newRemotePeerTLSBinding("cluster-beta", &RemotePeerIdentityConfig{ClusterID: 17, SPKISHA256: []string{hex.EncodeToString(wrongPin[:])}})
	require.NoError(t, err)
	_, _, err = openPinnedTLSConn(t, binding, cert, roots, "etcd.remote.test")
	require.ErrorContains(t, err, "SPKI is not authorized")
	_, err = binding.evidence(time.Now())
	require.Error(t, err, "failed pin handshake must not create evidence")

	binding, err = newRemotePeerTLSBinding("cluster-beta", &RemotePeerIdentityConfig{ClusterID: 17, SPKISHA256: []string{pin}})
	require.NoError(t, err)
	_, _, err = openPinnedTLSConn(t, binding, cert, roots, "wrong.remote.test")
	require.ErrorContains(t, err, "certificate is valid for")
	_, err = binding.evidence(time.Now())
	require.Error(t, err, "failed server-name handshake must not create evidence")
}

func TestRemotePeerTLSBindingRequiresTLSAndVerifiedChain(t *testing.T) {
	binding, err := newRemotePeerTLSBinding("cluster-beta", &RemotePeerIdentityConfig{ClusterID: 17, SPKISHA256: []string{hex.EncodeToString(make([]byte, sha256.Size))}})
	require.NoError(t, err)
	_, err = newRemotePeerTransportCredentials(nil, binding)
	require.ErrorContains(t, err, "requires etcd TLS")
	_, err = newRemotePeerTransportCredentials(&tls.Config{InsecureSkipVerify: true}, binding) //nolint:gosec // This negative case requires the production constructor to reject skipped verification.
	require.ErrorContains(t, err, "InsecureSkipVerify")
	require.ErrorContains(t, binding.VerifyConnection(tls.ConnectionState{}), "verified certificate chain")
}

func TestRemotePeerIdentityConfigRejectsAmbiguousPins(t *testing.T) {
	zero := hex.EncodeToString(make([]byte, sha256.Size))
	tests := []struct {
		name string
		cfg  RemotePeerIdentityConfig
	}{
		{name: "zero ID", cfg: RemotePeerIdentityConfig{SPKISHA256: []string{zero}}},
		{name: "missing pins", cfg: RemotePeerIdentityConfig{ClusterID: 17}},
		{name: "duplicate pins", cfg: RemotePeerIdentityConfig{ClusterID: 17, SPKISHA256: []string{zero, zero}}},
		{name: "uppercase", cfg: RemotePeerIdentityConfig{ClusterID: 17, SPKISHA256: []string{"AA" + zero[2:]}}},
		{name: "bad length", cfg: RemotePeerIdentityConfig{ClusterID: 17, SPKISHA256: []string{"abcd"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { require.Error(t, tt.cfg.Validate()) })
	}
}

func TestRemotePeerEvidenceExpiresWithCertificateOrHeartbeat(t *testing.T) {
	now := time.Now()
	valid := remotePeerEvidence{
		name: "cluster-beta", id: 17, identityEpoch: 1,
		notAfter: now.Add(time.Minute), heartbeatAt: now.Add(-time.Minute),
		spki: sha256.Sum256([]byte("pinned SPKI")), profileID: sha256.Sum256([]byte("local profile")),
	}
	require.NoError(t, valid.Validate(now))
	valid.notAfter = now
	require.ErrorContains(t, valid.Validate(now), "certificate expired")
	valid.notAfter = now.Add(time.Minute)
	valid.heartbeatAt = now.Add(-3 * HeartbeatWriteInterval)
	require.ErrorContains(t, valid.Validate(now), "heartbeat is stale")
}

func TestRemotePeerAdvertisedClusterIDMustMatchPinnedIdentity(t *testing.T) {
	binding, err := newRemotePeerTLSBinding("cluster-beta", &RemotePeerIdentityConfig{ClusterID: 17, SPKISHA256: []string{hex.EncodeToString(make([]byte, sha256.Size))}})
	require.NoError(t, err)
	require.NoError(t, validateRemotePeerBinding(binding, "cluster-beta", 17))
	require.ErrorContains(t, validateRemotePeerBinding(binding, "cluster-beta", 18), "does not match pinned ID")
	require.ErrorContains(t, validateRemotePeerBinding(binding, "other", 17), "does not match configured name")
}

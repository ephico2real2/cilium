// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package init

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/cilium/cilium/pkg/kvstore"
)

func covers(ranges []keyRange, key string) bool {
	for _, r := range ranges {
		if r.end == "" && key == r.start || r.end != "" && key >= r.start && key < r.end {
			return true
		}
	}
	return false
}

func TestZtunnelMembershipWriterRoleIsLimitedToMembership(t *testing.T) {
	readOnlyRanges, readWriteRanges := rangesForZtunnelMembershipWriterRole()
	for _, key := range []string{
		kvstore.ZtunnelMembershipPrefix + "/agents/cmtc-a-worker",
		kvstore.ZtunnelMembershipPrefix + "/locks/cmtc-a-worker/694d9c2b1f0a",
		kvstore.LeaseTTLWriteHeadsPrefix + "/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
	} {
		require.True(t, covers(readWriteRanges, key), "writer cannot write %s", key)
	}
	require.True(t, covers(readOnlyRanges, kvstore.HeartbeatPath), "writer cannot observe the heartbeat")
	require.False(t, covers(readWriteRanges, kvstore.HeartbeatPath), "writer may forge the heartbeat")
	for _, key := range []string{
		"cilium/state/ip/v1/default/10.10.1.7",
		"cilium/state/nodes/v1/cmtc-a/cmtc-a-worker",
		"cilium/state/identities/v1/id/12345",
		"cilium/state/services/v1/cmtc-a/default/kubernetes",
		"cilium/state/ztunnel/membership/v10/agents/cmtc-a-worker",
		"cilium/state/ztunnel/membership/v1",
		"cilium/state/lease-ttl-write-heads/v10/x",
		kvstore.InitLockPath + "/abc",
		kvstore.ClusterConfigPrefix + "/cmtc-a",
		kvstore.SyncedPrefix + "/cmtc-a/cilium/state/ip/v1",
		kvstore.CachePrefix + "/ip/v1/cmtc-b/10.20.1.7",
	} {
		require.False(t, covers(readWriteRanges, key), "writer can write %s", key)
		require.False(t, covers(readOnlyRanges, key), "writer can read %s", key)
	}
}

// The integration test below runs ClusterMeshEtcdInit against a real etcd
// server and then exercises the resulting users with client certificates, as
// clustermesh-apiserver serves them. It needs an etcd binary.
const etcdBinaryEnv = "CILIUM_ETCDINIT_ETCD_BINARY"

type testPKI struct {
	dir    string
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caFile string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "etcdinit test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	p := &testPKI{dir: t.TempDir(), ca: ca, caKey: key}
	p.caFile = p.write(t, "ca.crt", "CERTIFICATE", der)
	return p
}

func (p *testPKI) write(t *testing.T, name, kind string, der []byte) string {
	t.Helper()
	path := filepath.Join(p.dir, name)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600))
	return path
}

// issue returns the certificate and key files of a leaf with commonName.
func (p *testPKI) issue(t *testing.T, commonName string, server bool) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.ca, &key.PublicKey, p.caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return p.write(t, commonName+".crt", "CERTIFICATE", der), p.write(t, commonName+".key", "EC PRIVATE KEY", keyDER)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startEtcd runs one single-member etcd on dataDir until the test ends or the
// returned stop function is called.
func startEtcd(t *testing.T, binary, dataDir string, extra ...string) (endpoint string, stop func()) {
	t.Helper()
	clientPort, peerPort := freePort(t), freePort(t)
	scheme := "http"
	if len(extra) > 0 {
		scheme = "https"
	}
	endpoint = fmt.Sprintf("%s://127.0.0.1:%d", scheme, clientPort)
	peer := "http://127.0.0.1:" + strconv.Itoa(peerPort)
	args := append([]string{
		"--name=etcdinit-test", "--data-dir=" + dataDir,
		"--listen-client-urls=" + endpoint, "--advertise-client-urls=" + endpoint,
		"--listen-peer-urls=" + peer, "--initial-advertise-peer-urls=" + peer,
		"--initial-cluster=etcdinit-test=" + peer, "--log-level=error",
	}, extra...)
	cmd := exec.Command(binary, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	require.NoError(t, cmd.Start())
	var stopped bool
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
	}
	t.Cleanup(stop)
	return endpoint, stop
}

func certClient(t *testing.T, endpoint string, pki *testPKI, certFile, keyFile string) *clientv3.Client {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(pki.ca)
	cl, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{endpoint},
		DialTimeout: 10 * time.Second,
		TLS:         &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: roots, MinVersion: tls.VersionTLS12},
	})
	require.NoError(t, err)
	t.Cleanup(func() { cl.Close() })
	return cl
}

func waitHealthy(t *testing.T, cl *clientv3.Client) {
	t.Helper()
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := cl.Get(ctx, "health-probe")
		return err == nil || rpctypes.Error(err) == rpctypes.ErrPermissionDenied
	}, 20*time.Second, 100*time.Millisecond)
}

func TestClusterMeshEtcdInitZtunnelMembershipUsers(t *testing.T) {
	binary := os.Getenv(etcdBinaryEnv)
	if binary == "" {
		t.Skipf("set %s to an etcd server binary to run this integration test", etcdBinaryEnv)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pki := newTestPKI(t)
	dataDir := filepath.Join(t.TempDir(), "etcd")

	// First-time initialisation over loopback without authentication, as the
	// etcd-init container does, with keys a writer must not be able to change.
	endpoint, stop := startEtcd(t, binary, dataDir)
	plain, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 10 * time.Second})
	require.NoError(t, err)
	waitHealthy(t, plain)
	_, err = plain.Put(ctx, kvstore.HeartbeatPath, "heartbeat")
	require.NoError(t, err)
	_, err = plain.Put(ctx, "cilium/state/ip/v1/default/10.10.1.7", "ipcache")
	require.NoError(t, err)
	require.NoError(t, ClusterMeshEtcdInit(ctx, hivetest.Logger(t), plain, "cmtc-a", true, true))
	plain.Close()
	stop()

	// Serve it as clustermesh-apiserver does: TLS with client certificate auth.
	serverCert, serverKey := pki.issue(t, "clustermesh-apiserver.kube-system.svc", true)
	endpoint, _ = startEtcd(t, binary, dataDir, "--client-cert-auth", "--trusted-ca-file="+pki.caFile,
		"--cert-file="+serverCert, "--key-file="+serverKey)

	writerCert, writerKey := pki.issue(t, ZtunnelMembershipWriterUser+"-cmtc-a", false)
	writer := certClient(t, endpoint, pki, writerCert, writerKey)
	waitHealthy(t, writer)
	denied := func(err error, what string) {
		t.Helper()
		require.ErrorIs(t, rpctypes.Error(err), rpctypes.ErrPermissionDenied, what)
	}
	record := kvstore.ZtunnelMembershipPrefix + "/agents/cmtc-a-worker"
	lease, err := writer.Grant(ctx, 30)
	require.NoError(t, err, "writer cannot grant a short lease")
	_, err = writer.Put(ctx, record, "membership", clientv3.WithLease(lease.ID))
	require.NoError(t, err, "writer cannot publish a leased membership record")
	_, err = writer.Put(ctx, kvstore.LeaseTTLWriteHeadsPrefix+"/head", "1")
	require.NoError(t, err, "writer cannot advance a write head")
	_, err = writer.Get(ctx, kvstore.HeartbeatPath)
	require.NoError(t, err, "writer cannot observe the heartbeat")
	_, err = writer.Put(ctx, kvstore.HeartbeatPath, "forged")
	denied(err, "writer forged the heartbeat")
	_, err = writer.Put(ctx, "cilium/state/ip/v1/default/10.10.1.7", "forged")
	denied(err, "writer changed ipcache state")
	_, err = writer.Get(ctx, "cilium/state/ip/v1/default/10.10.1.7")
	denied(err, "writer read ipcache state")
	_, err = writer.Put(ctx, kvstore.InitLockPath+"/x", "lock")
	denied(err, "writer wrote the init lock")
	_, err = writer.Put(ctx, "cilium/state/ztunnel/membership/v10/agents/cmtc-a-worker", "forged")
	denied(err, "writer escaped the membership prefix")

	// Cilium's own etcd backend, configured as the agent's dedicated
	// membership connection, takes the writer lock and publishes under it.
	config := filepath.Join(pki.dir, "membership-etcd.yaml")
	require.NoError(t, os.WriteFile(config, fmt.Appendf(nil,
		"endpoints:\n- %s\ntrusted-ca-file: %s\ncert-file: %s\nkey-file: %s\n", endpoint, pki.caFile, writerCert, writerKey), 0o600))
	backend, errCh := kvstore.NewClient(ctx, hivetest.Logger(t), kvstore.EtcdBackendName,
		map[string]string{kvstore.EtcdOptionConfig: config},
		kvstore.ExtraOptions{NoLockQuorumCheck: true, NoEndpointStatusChecks: true, LeaseTTL: 15 * time.Minute})
	require.NoError(t, <-errCh, "dedicated membership connection was not established")
	t.Cleanup(backend.Close)
	locker, err := backend.LockPath(ctx, kvstore.ZtunnelMembershipPrefix+"/locks/cmtc-a-worker")
	require.NoError(t, err, "dedicated connection cannot take the writer lock")
	leaseWriter, ok := kvstore.LeaseTTLWriterFor(kvstore.StandaloneClient(backend))
	require.True(t, ok, "etcd backend lost its short-lease capability")
	require.NoError(t, leaseWriter.UpdateWithLeaseTTLIfLocked(ctx, record, []byte("fenced"), 30*time.Second, locker),
		"dedicated connection cannot publish a fenced short-lease record")
	require.Error(t, backend.Update(ctx, "cilium/state/nodes/v1/cmtc-a/cmtc-a-worker", []byte("forged"), false),
		"dedicated connection wrote node state")
	require.NoError(t, locker.Unlock(ctx))

	// A writer certificate of another cluster has no user in this etcd.
	otherCert, otherKey := pki.issue(t, ZtunnelMembershipWriterUser+"-cmtc-b", false)
	other := certClient(t, endpoint, pki, otherCert, otherKey)
	_, err = other.Put(ctx, record, "foreign")
	require.Error(t, err, "another cluster's writer published local membership")

	// The direct-origin reader reads membership and state, and writes nothing.
	readerCert, readerKey := pki.issue(t, ZtunnelOriginReaderUser, false)
	reader := certClient(t, endpoint, pki, readerCert, readerKey)
	got, err := reader.Get(ctx, record)
	require.NoError(t, err, "origin reader cannot read membership")
	require.Len(t, got.Kvs, 1)
	require.Equal(t, "fenced", string(got.Kvs[0].Value))
	_, err = reader.Get(ctx, "cilium/state/ip/v1/default/10.10.1.7")
	require.NoError(t, err, "origin reader cannot read the source cluster state")
	_, err = reader.Put(ctx, record, "forged")
	denied(err, "origin reader wrote membership")
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	status "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/issuerprofile"
)

type profileTestServer struct {
	v3.UnimplementedAggregatedDiscoveryServiceServer
	source *issuerProfileSource
}

func (s *profileTestServer) DeltaAggregatedResources(stream v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer) error {
	sp := NewStreamProcessor(&StreamProcessorParams{NodeNames: mustFixtureNodeNames(), Stream: stream, StreamRecv: make(chan *v3.DeltaDiscoveryRequest, 1), EndpointEventRecv: make(chan *EndpointEvent), Log: slog.New(slog.DiscardHandler), IssuerProfile: s.source})
	// Exercise the actual native router with a package-private test deadline.
	return sp.Start()
}
func profileTestSource(t *testing.T) (*issuerProfileSource, *fake.Clientset, *atomic.Int64) {
	t.Helper()
	var f struct {
		NowUnix, ApprovalJSON, PublicationJSON string
		Wire                                   issuerprofile.DERProfile
	}
	raw, err := os.ReadFile("../issuerprofile/testdata/issuer-profile-v1.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &f))
	now, err := strconv.ParseInt(f.NowUnix, 10, 64)
	require.NoError(t, err)
	clock := &atomic.Int64{}
	clock.Store(now)
	immutable := true
	source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: f.Wire.SourceNamespace, Name: f.Wire.SourceName, UID: types.UID(f.Wire.SourceUID), ResourceVersion: "17"}, Immutable: &immutable, Data: map[string]string{issuerprofile.ApprovalKey: f.ApprovalJSON}}
	output := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: f.Wire.OutputNamespace, Name: f.Wire.OutputName, UID: types.UID(f.Wire.OutputUID), ResourceVersion: "23", Labels: map[string]string{issuerprofile.OutputLabel: "true"}, Annotations: map[string]string{issuerprofile.InitializedAnnotation: "true"}}, Data: map[string]string{issuerprofile.DataKey: f.PublicationJSON}}
	client := fake.NewClientset(source, output)
	pins := issuerprofile.Install{Expected: issuerprofile.Expected{OutputUID: f.Wire.OutputUID, SourceUID: f.Wire.SourceUID, SourceNamespace: f.Wire.SourceNamespace, SourceName: f.Wire.SourceName, Cluster: f.Wire.Cluster, MinimumGeneration: 7, MinimumSequence: 10, RootPins: []string{f.Wire.RootSHA256}}, OutputNamespace: f.Wire.OutputNamespace, OutputName: f.Wire.OutputName, Node: f.Wire.Node, ApprovalDigestAtMinimum: f.Wire.ApprovalDigest, PublicationDigestAtMinimum: f.Wire.PublicationDigest}
	return &issuerProfileSource{core: client.CoreV1(), pins: pins, clock: func() time.Time { return time.Unix(clock.Load(), 0) }, log: slog.New(slog.DiscardHandler), timing: &issuerProfileTiming{poll: 5 * time.Millisecond, ack: 250 * time.Millisecond}}, client, clock
}
func profileTLSStream(t *testing.T, source *issuerProfileSource) (v3.AggregatedDiscoveryService_DeltaAggregatedResourcesClient, context.CancelFunc) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})))
	v3.RegisterAggregatedDiscoveryServiceServer(server, &profileTestServer{source: source})
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///profile", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close(); server.Stop(); listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	stream, err := v3.NewAggregatedDiscoveryServiceClient(conn).DeltaAggregatedResources(ctx)
	require.NoError(t, err)
	metadata, err := structpb.NewStruct(map[string]any{"NODE_NAME": source.pins.Node})
	require.NoError(t, err)
	require.NoError(t, stream.Send(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLIssuerProfile, Node: &corev3.Node{Id: "profile-test", Metadata: metadata}}))
	return stream, cancel
}
func TestIssuerProfileNativeTLSADSCorrelation(t *testing.T) {
	for _, kind := range []string{"nack", "wrong-nonce", "replay", "ack-renewal", "ack-timeout", "api-outage", "lease-expiry", "disconnect-recovery"} {
		t.Run(kind, func(t *testing.T) {
			source, api, clock := profileTestSource(t)
			acks := make(chan struct{}, 4)
			source.log = slog.New(&profileAckLog{acks: acks})
			unavailable := &atomic.Bool{}
			api.PrependReactor("get", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
				if unavailable.Load() {
					return true, nil, errors.New("API unavailable")
				}
				return false, nil, nil
			})
			stream, cancel := profileTLSStream(t, source)
			response, err := stream.Recv()
			require.NoError(t, err)
			require.Equal(t, xdsTypeURLIssuerProfile, response.TypeUrl)
			require.Len(t, response.Resources, 1)
			require.Equal(t, response.SystemVersionInfo, response.Resources[0].Version)
			require.NotEmpty(t, response.Nonce)
			switch kind {
			case "nack":
				require.NoError(t, stream.Send(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLIssuerProfile, ResponseNonce: response.Nonce, ErrorDetail: &status.Status{Code: 9, Message: "durable provider unavailable"}}))
			case "wrong-nonce":
				require.NoError(t, stream.Send(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLIssuerProfile, ResponseNonce: "foreign"}))
			case "replay":
				req := &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLIssuerProfile, ResponseNonce: response.Nonce}
				require.NoError(t, stream.Send(req))
				select {
				case <-acks:
				case <-time.After(time.Second):
					t.Fatal("matching native ACK was not observed")
				}
				require.NoError(t, stream.Send(req))
			case "ack-renewal":
				require.NoError(t, stream.Send(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLIssuerProfile, ResponseNonce: response.Nonce}))
				select {
				case <-acks:
				case <-time.After(time.Second):
					t.Fatal("matching native ACK was not observed")
				}
				// Positive control: deliberately renew between completed API
				// observations. Production writes do not acquire this mutex;
				// the separate concurrent-observation test exercises that race.
				profileRenewBetweenObservations(t, source, api)
				renewed, err := stream.Recv()
				require.NoError(t, err)
				require.NotEqual(t, response.Nonce, renewed.Nonce)
				require.NotEqual(t, response.Resources[0].Version, renewed.Resources[0].Version)
				require.NoError(t, stream.Send(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLIssuerProfile, ResponseNonce: renewed.Nonce, ErrorDetail: &status.Status{Code: 9, Message: "probe remains fenced"}}))
			case "api-outage":
				unavailable.Store(true)
			case "lease-expiry":
				require.NoError(t, stream.Send(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLIssuerProfile, ResponseNonce: response.Nonce}))
				clock.Add(30)
			case "disconnect-recovery":
				cancel()
				_, err = stream.Recv()
				require.Error(t, err)
				recovered, _ := profileTLSStream(t, source)
				fresh, err := recovered.Recv()
				require.NoError(t, err)
				require.NotEqual(t, response.Nonce, fresh.Nonce)
				require.Equal(t, response.Resources[0].Version, fresh.Resources[0].Version)
				return
			}
			_, err = stream.Recv()
			require.Error(t, err, "invalid or stale subscriber must not receive another usable profile")
			if kind == "api-outage" {
				require.Equal(t, codes.Unavailable, grpcstatus.Code(err))
				unavailable.Store(false)
				recovered, _ := profileTLSStream(t, source)
				fresh, err := recovered.Recv()
				require.NoError(t, err)
				require.NotEqual(t, response.Nonce, fresh.Nonce)
			}
			if kind == "lease-expiry" {
				out, err := api.CoreV1().ConfigMaps(source.pins.OutputNamespace).Get(context.Background(), source.pins.OutputName, metav1.GetOptions{})
				require.NoError(t, err)
				p, err := issuerprofile.DecodePublication([]byte(out.Data[issuerprofile.DataKey]))
				require.NoError(t, err)
				p.Sequence++
				p.PublishedAt = issuerprofile.Stamp(source.clock())
				p.ValidUntil = issuerprofile.Stamp(source.clock().Add(30 * time.Second))
				body, err := issuerprofile.Encode(*p)
				require.NoError(t, err)
				out.Data[issuerprofile.DataKey] = string(body)
				out.ResourceVersion = "24"
				_, err = api.CoreV1().ConfigMaps(out.Namespace).Update(context.Background(), out, metav1.UpdateOptions{})
				require.NoError(t, err)
				recovered, _ := profileTLSStream(t, source)
				fresh, err := recovered.Recv()
				require.NoError(t, err)
				require.NotEqual(t, response.Resources[0].Version, fresh.Resources[0].Version)
			}
		})
	}
}
func TestIssuerProfileAPITLSRejectsUnsafeTransportAndWrongRoot(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"issuer-approval","namespace":"cmtc-system"}}`)
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	valid := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}}
	core, err := verifiedIssuerProfileCore(valid)
	require.NoError(t, err)
	_, err = core.ConfigMaps("cmtc-system").Get(context.Background(), "issuer-approval", metav1.GetOptions{})
	require.NoError(t, err)
	for _, kind := range []string{"http", "insecure", "no-ca", "transport", "wrapper", "dialer", "proxy", "wrong-name", "wrong-root"} {
		t.Run(kind, func(t *testing.T) {
			rc := rest.CopyConfig(valid)
			switch kind {
			case "http":
				rc.Host = "http://127.0.0.1:80"
			case "insecure":
				rc.Insecure = true
			case "no-ca":
				rc.CAData = nil
			case "transport":
				rc.Transport = http.DefaultTransport
			case "wrapper":
				rc.WrapTransport = func(rt http.RoundTripper) http.RoundTripper { return rt }
			case "dialer":
				rc.Dial = (&net.Dialer{}).DialContext
			case "proxy":
				rc.Proxy = http.ProxyFromEnvironment
			case "wrong-name":
				rc.ServerName = "foreign.invalid"
			case "wrong-root":
				rc.CAData = []byte("not a CA")
			}
			core, err := verifiedIssuerProfileCore(rc)
			if err == nil {
				_, err = core.ConfigMaps("cmtc-system").Get(context.Background(), "issuer-approval", metav1.GetOptions{})
			}
			require.Error(t, err)
		})
	}
}

func TestIssuerProfileProbePinsRejectAliasesAndUnboundedFloors(t *testing.T) {
	source, _, _ := profileTestSource(t)
	pins := issuerProfileProbePins{Cluster: source.pins.Cluster, Node: source.pins.Node, SourceNamespace: source.pins.SourceNamespace, SourceName: source.pins.SourceName, SourceUID: source.pins.SourceUID, OutputNamespace: source.pins.OutputNamespace, OutputName: source.pins.OutputName, OutputUID: source.pins.OutputUID, RootPins: source.pins.RootPins, MinimumGeneration: "7", MinimumSequence: "10", ApprovalDigestAtMinimum: source.pins.ApprovalDigestAtMinimum, PublicationDigestAtMinimum: source.pins.PublicationDigestAtMinimum}
	body, err := json.Marshal(pins)
	require.NoError(t, err)
	decoded, err := decodeIssuerProfileProbePins(body)
	require.NoError(t, err)
	require.NoError(t, issuerprofile.ValidateInstall(decoded))
	for _, bad := range []string{`{"cluster":"a","cluster":"b"}`, `{"Cluster":"a"}`, `{} {}`, `{"minimumGeneration":"01","minimumSequence":"1"}`, `{"minimumGeneration":"1","minimumSequence":"0"}`} {
		_, err = decodeIssuerProfileProbePins([]byte(bad))
		require.Error(t, err)
	}
	_, err = decodeIssuerProfileProbePins(make([]byte, maxProbePins+1))
	require.Error(t, err)
}

// Observe the real structured ACK boundary without adding a grant/test hook.
type profileAckLog struct {
	acks      chan<- struct{}
	apiErrors chan<- string
}

func (*profileAckLog) Enabled(context.Context, slog.Level) bool { return true }
func (h *profileAckLog) Handle(_ context.Context, r slog.Record) error {
	if r.Message == "Issuer-profile transport response acknowledged; activation remains unavailable" {
		select {
		case h.acks <- struct{}{}:
		default:
		}
	}
	if (r.Message == "Issuer-profile API observation unavailable" || r.Message == "Issuer-profile API observation raced a concurrent publication; observing again") && h.apiErrors != nil {
		r.Attrs(func(attr slog.Attr) bool {
			if attr.Key == "error" {
				select {
				case h.apiErrors <- attr.Value.String():
				default:
				}
			}
			return true
		})
	}
	return nil
}
func (h *profileAckLog) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *profileAckLog) WithGroup(string) slog.Handler      { return h }

func TestIssuerProfilePinsFIFOIsRejectedWithoutWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins-fifo")
	require.NoError(t, unix.Mkfifo(path, 0o600))
	done := make(chan error, 1)
	go func() { _, err := readIssuerProfileProbePins(path); done <- err }()
	select {
	case err := <-done:
		require.ErrorContains(t, err, "regular")
	case <-time.After(2 * time.Second):
		// Unblock the old implementation before reporting its startup hang.
		fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		require.NoError(t, err)
		require.NoError(t, unix.Close(fd))
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("pins reader did not stop after FIFO release")
		}
		t.Fatal("pins reader waited for a FIFO writer before rejecting its type")
	}
}

func profileRenewBetweenObservations(t *testing.T, source *issuerProfileSource, api *fake.Clientset) {
	t.Helper()
	// This only serializes the positive fixture, not the production API writer.
	// It also waits for a current observation to finish before replacing data.
	source.mu.Lock()
	defer source.mu.Unlock()
	out, err := api.CoreV1().ConfigMaps(source.pins.OutputNamespace).Get(context.Background(), source.pins.OutputName, metav1.GetOptions{})
	require.NoError(t, err)
	p, err := issuerprofile.DecodePublication([]byte(out.Data[issuerprofile.DataKey]))
	require.NoError(t, err)
	p.Sequence++
	body, err := issuerprofile.Encode(*p)
	require.NoError(t, err)
	out.Data[issuerprofile.DataKey] = string(body)
	out.ResourceVersion = "24"
	_, err = api.CoreV1().ConfigMaps(out.Namespace).Update(context.Background(), out, metav1.UpdateOptions{})
	require.NoError(t, err)
}

func TestIssuerProfileConcurrentOutputRenewalIsObservedAgainOnTheSameSession(t *testing.T) {
	source, api, _ := profileTestSource(t)
	acks := make(chan struct{}, 4)
	apiErrors := make(chan string, 4)
	source.log = slog.New(&profileAckLog{acks: acks, apiErrors: apiErrors})
	stream, _ := profileTLSStream(t, source)
	first, err := stream.Recv()
	require.NoError(t, err)
	require.NoError(t, stream.Send(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLIssuerProfile, ResponseNonce: first.Nonce}))
	select {
	case <-acks:
	case <-time.After(time.Second):
		t.Fatal("matching native transport ACK was not observed")
	}

	// Install the reactor only after any current whole observation has ended.
	// The NEXT observation receives an exact old output on its first GET, but
	// its final GET sees an actual newer tracker object. No sleeps or scheduler
	// coincidence are used to force the mutation between those two reads.
	mutated := &atomic.Bool{}
	source.mu.Lock()
	beforeSequence := source.pins.MinimumSequence
	beforeDigest := source.pins.PublicationDigestAtMinimum
	api.PrependReactor("get", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		get, ok := action.(ktesting.GetAction)
		if !ok || action.GetNamespace() != source.pins.OutputNamespace || get.GetName() != source.pins.OutputName || !mutated.CompareAndSwap(false, true) {
			return false, nil, nil
		}
		gvr := corev1.SchemeGroupVersion.WithResource("configmaps")
		old, err := api.Tracker().Get(gvr, source.pins.OutputNamespace, source.pins.OutputName)
		if err != nil {
			return true, nil, err
		}
		next := old.(*corev1.ConfigMap).DeepCopy()
		p, err := issuerprofile.DecodePublication([]byte(next.Data[issuerprofile.DataKey]))
		if err != nil {
			return true, nil, err
		}
		p.Sequence++
		body, err := issuerprofile.Encode(*p)
		if err != nil {
			return true, nil, err
		}
		next.Data[issuerprofile.DataKey] = string(body)
		next.ResourceVersion = "24"
		// The client-go Fake holds its own reactor mutex here. Calling the
		// fake client recursively would deadlock; the actual object tracker
		// has its separate lock and models the committed API-side change.
		if err := api.Tracker().Update(gvr, next, next.Namespace); err != nil {
			return true, nil, err
		}
		return true, old.DeepCopyObject(), nil
	})
	source.mu.Unlock()

	// The raced observation is never projected; the immediate re-observation
	// reads the committed newer object coherently on the SAME stream.
	renewed, err := stream.Recv()
	require.NoError(t, err, "a concurrent producer renewal must not close the session")
	require.True(t, mutated.Load(), "deterministic concurrent mutation did not execute")
	require.NotEqual(t, first.Nonce, renewed.Nonce)
	require.NotEqual(t, first.Resources[0].Version, renewed.Resources[0].Version)
	select {
	case cause := <-apiErrors:
		require.Contains(t, cause, "output changed during API observation")
	case <-time.After(time.Second):
		t.Fatal("exact API coherence race was not logged")
	}
	source.mu.Lock()
	afterSequence := source.pins.MinimumSequence
	afterDigest := source.pins.PublicationDigestAtMinimum
	source.mu.Unlock()
	require.Equal(t, beforeSequence+1, afterSequence, "only the coherent observation advances the sequence floor")
	require.NotEqual(t, beforeDigest, afterDigest, "only the coherent observation advances the digest floor")

	// Every other check still applies to the renewed delivery: a NACK ends it.
	require.NoError(t, stream.Send(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLIssuerProfile, ResponseNonce: renewed.Nonce, ErrorDetail: &status.Status{Code: 9, Message: "durable provider remains unavailable"}}))
	_, err = stream.Recv()
	require.Error(t, err)
}

func TestIssuerProfileNonRaceObservationFailureStillClosesSession(t *testing.T) {
	source, api, _ := profileTestSource(t)
	acks := make(chan struct{}, 4)
	apiErrors := make(chan string, 4)
	source.log = slog.New(&profileAckLog{acks: acks, apiErrors: apiErrors})
	stream, _ := profileTLSStream(t, source)
	first, err := stream.Recv()
	require.NoError(t, err)
	require.NoError(t, stream.Send(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLIssuerProfile, ResponseNonce: first.Nonce}))
	select {
	case <-acks:
	case <-time.After(time.Second):
		t.Fatal("matching native transport ACK was not observed")
	}
	// An output that lost its pinned publication label is not a race: it fails
	// the output metadata check on every read, so the session closes as before.
	source.mu.Lock()
	out, err := api.CoreV1().ConfigMaps(source.pins.OutputNamespace).Get(context.Background(), source.pins.OutputName, metav1.GetOptions{})
	require.NoError(t, err)
	out.Labels[issuerprofile.OutputLabel] = "false"
	out.ResourceVersion = "24"
	_, err = api.CoreV1().ConfigMaps(out.Namespace).Update(context.Background(), out, metav1.UpdateOptions{})
	require.NoError(t, err)
	source.mu.Unlock()
	usable, err := stream.Recv()
	require.Error(t, err)
	require.Nil(t, usable, "an unpinned output must not publish any profile")
	require.Equal(t, codes.Unavailable, grpcstatus.Code(err))
	select {
	case cause := <-apiErrors:
		require.NotContains(t, cause, "changed during API observation")
	case <-time.After(time.Second):
		t.Fatal("API observation failure was not logged")
	}
}

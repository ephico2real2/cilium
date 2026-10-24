// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

func TestSpireADSHasNoWorkloadSigner(t *testing.T) {
	x := &Server{caType: config.CATypeSpire}
	loadedSigningKey := false
	server, err := x.newGRPCServer(insecure.NewCredentials(), func() (pb.IstioCertificateServiceServer, error) {
		loadedSigningKey = true
		return nil, errors.New("workload signing keys must not be loaded in SPIRE mode")
	})
	require.NoError(t, err)
	require.False(t, loadedSigningKey)
	require.Contains(t, server.GetServiceInfo(), "envoy.service.discovery.v3.AggregatedDiscoveryService")
	require.NotContains(t, server.GetServiceInfo(), "istio.v1.auth.IstioCertificateService")

	listener := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///spire-ads-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = pb.NewIstioCertificateServiceClient(conn).CreateCertificate(ctx, &pb.IstioCertificateRequest{Csr: "must never be signed"})
	require.Equal(t, codes.Unimplemented, status.Code(err))
}

func TestInternalADSKeepsWorkloadSigner(t *testing.T) {
	x := &Server{caType: config.CATypeInternal}
	loads := 0
	server, err := x.newGRPCServer(insecure.NewCredentials(), func() (pb.IstioCertificateServiceServer, error) {
		loads++
		return &pb.UnimplementedIstioCertificateServiceServer{}, nil
	})
	require.NoError(t, err)
	t.Cleanup(server.Stop)
	require.Equal(t, 1, loads)
	require.Contains(t, server.GetServiceInfo(), "istio.v1.auth.IstioCertificateService")
}

func TestInternalADSRejectsUnavailableSigner(t *testing.T) {
	x := &Server{caType: config.CATypeInternal}
	missingKey := errors.New("signing key unavailable")
	server, err := x.newGRPCServer(insecure.NewCredentials(), func() (pb.IstioCertificateServiceServer, error) { return nil, missingKey })
	require.ErrorIs(t, err, missingKey)
	require.Nil(t, server)
}

func TestADSRejectsUnknownCABackend(t *testing.T) {
	x := &Server{caType: "unrecognized"}
	server, err := x.newGRPCServer(insecure.NewCredentials(), func() (pb.IstioCertificateServiceServer, error) {
		t.Fatal("unknown CA backend must not initialize a signer")
		return nil, nil
	})
	require.ErrorContains(t, err, "unsupported ztunnel-ca-type")
	require.Nil(t, server)
	x.GracefulStop()
}

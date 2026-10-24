// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

func TestSpireStartupRetryLogsAndAcknowledgment(t *testing.T) {
	var logs bytes.Buffer
	c := &Client{log: slog.New(slog.NewJSONHandler(&logs, nil)).With(logfields.LogSubsys, "spire-client")}
	health, _ := cell.NewSimpleHealth()
	attempts := 0
	expected := &spireConnection{}
	actual, err := c.initialize(t.Context(), health, func(context.Context) (*spireConnection, error) {
		attempts++
		if attempts < 3 {
			return nil, status.Error(codes.Unavailable, "SPIRE restarting")
		}
		return expected, nil
	}, func(int) time.Duration { return time.Millisecond })
	require.NoError(t, err)
	require.Same(t, expected, actual)
	require.Equal(t, 3, attempts)
	decoder := json.NewDecoder(&logs)
	for i := 1; i <= 3; i++ {
		var record map[string]any
		require.NoError(t, decoder.Decode(&record))
		require.Equal(t, "spire-client", record[logfields.LogSubsys])
		require.Equal(t, "server-ack", record["stage"])
		require.Equal(t, float64(i), record[logfields.Attempt])
		require.Contains(t, record, logfields.ElapsedDuration)
		if i < 3 {
			require.Equal(t, "retry", record["event"])
			require.Contains(t, record, logfields.Backoff)
			require.Contains(t, record, logfields.Error)
		} else {
			require.Equal(t, "ack", record["event"])
		}
	}
}

func TestSpireStartupRejectsPermanentFailures(t *testing.T) {
	for _, code := range []codes.Code{codes.PermissionDenied, codes.Unauthenticated, codes.InvalidArgument, codes.FailedPrecondition} {
		t.Run(code.String(), func(t *testing.T) {
			c := &Client{log: hivetest.Logger(t)}
			health, _ := cell.NewSimpleHealth()
			attempts := 0
			conn, err := c.initialize(t.Context(), health, func(context.Context) (*spireConnection, error) {
				attempts++
				return nil, status.Error(code, "rejected")
			}, func(int) time.Duration { t.Fatal("permanent errors must not retry"); return 0 })
			require.Nil(t, conn)
			require.ErrorContains(t, err, "startup rejected")
			require.Equal(t, 1, attempts)
		})
	}
}

func TestSpireStartupDeadlineAndCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "canceled"}[canceled], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			if canceled {
				cancel()
			}
			c := &Client{log: hivetest.Logger(t)}
			health, _ := cell.NewSimpleHealth()
			attempts := 0
			conn, err := c.initialize(ctx, health, func(context.Context) (*spireConnection, error) {
				attempts++
				return nil, status.Error(codes.Unavailable, "offline")
			}, func(int) time.Duration { return time.Hour })
			require.Nil(t, conn)
			require.ErrorIs(t, err, ctx.Err())
			if canceled {
				require.Zero(t, attempts)
			}
		})
	}
}

func TestSpireStartupPublishesOnlyAfterACKAndClosesOnStop(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := &Client{log: hivetest.Logger(t), initialized: make(chan struct{})}
	health, _ := cell.NewSimpleHealth()
	request := make(chan struct{})
	reply := make(chan struct{})
	var closed atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- c.runWithConnector(ctx, health, func(context.Context) (*spireConnection, error) {
			close(request)
			<-reply
			return &spireConnection{entry: mockEntryClient{}, close: func() { closed.Store(true) }}, nil
		}, func(int) time.Duration { return time.Millisecond })
	}()
	<-request
	select {
	case <-c.Initialized():
		t.Fatal("initialized before authenticated response")
	default:
	}
	close(reply)
	select {
	case <-c.Initialized():
	case <-time.After(5 * time.Second):
		t.Fatal("acknowledgment not published")
	}
	cancel()
	require.NoError(t, <-done)
	require.True(t, closed.Load())
	require.Nil(t, c.entry)
}

type acknowledgmentServer struct {
	entryv1.UnimplementedEntryServer
	code codes.Code
}

func (s acknowledgmentServer) CountEntries(context.Context, *entryv1.CountEntriesRequest) (*entryv1.CountEntriesResponse, error) {
	if s.code != codes.OK {
		return nil, status.Error(s.code, "server did not acknowledge")
	}
	return &entryv1.CountEntriesResponse{}, nil
}

func TestSpireServerAcknowledgmentRequiresRPCResponse(t *testing.T) {
	for _, code := range []codes.Code{codes.OK, codes.PermissionDenied, codes.Unavailable} {
		t.Run(code.String(), func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			server := grpc.NewServer()
			entryv1.RegisterEntryServer(server, acknowledgmentServer{code: code})
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() { server.Stop(); _ = listener.Close() })
			var dials atomic.Int32
			conn, err := grpc.NewClient("passthrough:///spire-ack-test", grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { dials.Add(1); return listener.Dial() }))
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			require.Zero(t, dials.Load(), "NewClient must not be mistaken for a handshake")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err = acknowledgeServer(ctx, entryv1.NewEntryClient(conn))
			require.Equal(t, code, status.Code(err))
			require.Positive(t, dials.Load())
		})
	}
}

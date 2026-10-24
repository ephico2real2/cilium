// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

func zdsSocketPair(t *testing.T) (*ztunnelConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	connections := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		file := os.NewFile(uintptr(fd), "zds-ack-test")
		conn, err := net.FileConn(file)
		file.Close()
		require.NoError(t, err)
		connections[i] = conn.(*net.UnixConn)
		t.Cleanup(func() { conn.Close() })
	}
	return &ztunnelConn{conn: connections[0]}, connections[1]
}

func TestZDSRequiresExplicitAck(t *testing.T) {
	for _, tc := range []struct {
		name      string
		response  []byte
		wantError string
	}{
		{name: "success", response: []byte{0x0a, 0x00}},
		{name: "missing-ack", response: []byte{0x12, 0x00}, wantError: "did not contain an acknowledgment"},
		{name: "malformed", response: []byte{0xff}, wantError: "cannot parse"},
		{name: "nack", response: []byte{0x0a, 0x08, 0x0a, 0x06, 'd', 'e', 'n', 'i', 'e', 'd'}, wantError: "ack error: denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, peer := zdsSocketPair(t)
			responded := make(chan error, 1)
			go func() {
				var request [1024]byte
				_, err := peer.Read(request[:])
				if err == nil {
					_, err = peer.Write(tc.response)
				}
				responded <- err
			}()
			err := server.sendAndWaitForAckWithTimeout(&pb.WorkloadRequest{Payload: &pb.WorkloadRequest_SnapshotSent{SnapshotSent: &pb.SnapshotSent{}}}, "", time.Second)
			if tc.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantError)
			}
			require.NoError(t, <-responded)
		})
	}
}

func TestZDSAckTimeoutAndRecovery(t *testing.T) {
	server, peer := zdsSocketPair(t)
	request := &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_SnapshotSent{SnapshotSent: &pb.SnapshotSent{}}}
	started := time.Now()
	err := server.sendAndWaitForAckWithTimeout(request, "", 20*time.Millisecond)
	var timeout net.Error
	require.ErrorAs(t, err, &timeout)
	require.True(t, timeout.Timeout())
	require.Less(t, time.Since(started), time.Second)
	// The connection is normally discarded on error. A fresh connection must
	// successfully exchange a real ACK after the previous peer stalled.
	peer.Close()
	server.Close()
	server, peer = zdsSocketPair(t)
	responded := make(chan error, 1)
	go func() {
		var buffer [1024]byte
		_, err := peer.Read(buffer[:])
		if err == nil {
			data, marshalErr := proto.Marshal(&pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Ack{Ack: &pb.Ack{}}})
			err = marshalErr
			if err == nil {
				_, err = peer.Write(data)
			}
		}
		responded <- err
	}()
	require.NoError(t, server.sendAndWaitForAckWithTimeout(request, "", time.Second))
	require.NoError(t, <-responded)
}

func TestZDSUpdateWaitIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name          string
		queueCapacity int
		response      *error
		closed        bool
	}{
		{name: "queue-full"},
		{name: "missing-ack", queueCapacity: 1},
		{name: "closed-without-result", queueCapacity: 1, closed: true},
		{name: "ack", queueCapacity: 1, response: new(error)},
		{name: "nack", queueCapacity: 1, response: func() *error { err := errors.New("proxy rejected workload"); return &err }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := &Server{updates: make(chan zdsUpdate, tc.queueCapacity)}
			update := zdsUpdate{errCh: make(chan error, 1)}
			if tc.response != nil {
				update.errCh <- *tc.response
			}
			if tc.closed {
				close(update.errCh)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			err := server.sendUpdateAndWaitForAck(ctx, update)
			switch {
			case tc.closed:
				require.ErrorContains(t, err, "without an acknowledgment result")
			case tc.response != nil:
				require.ErrorIs(t, err, *tc.response)
			default:
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
		})
	}
}

func TestZDSExpiredUpdateIsNotTransmitted(t *testing.T) {
	connection, peer := zdsSocketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	committed := false
	update := zdsUpdate{ctx: ctx, errCh: make(chan error, 1),
		request: &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_SnapshotSent{SnapshotSent: &pb.SnapshotSent{}}},
		onAck:   func() { committed = true },
	}
	require.NoError(t, (&Server{}).processUpdate(context.Background(), connection, update))
	require.ErrorIs(t, <-update.errCh, context.Canceled)
	require.False(t, committed)
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	var buffer [1024]byte
	_, err := peer.Read(buffer[:])
	var timeout net.Error
	require.ErrorAs(t, err, &timeout)
	require.True(t, timeout.Timeout(), "Expired work must not produce any wire message")
}

func TestZDSCancellationRetiresInFlightConnection(t *testing.T) {
	connection, peer := zdsSocketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var committed atomic.Bool
	update := zdsUpdate{ctx: ctx, errCh: make(chan error, 1),
		request: &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_SnapshotSent{SnapshotSent: &pb.SnapshotSent{}}},
		onAck:   func() { committed.Store(true) },
	}
	done := make(chan error, 1)
	go func() { done <- (&Server{}).processUpdate(context.Background(), connection, update) }()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	request := &pb.WorkloadRequest{}
	require.NoError(t, (&ztunnelConn{conn: peer}).readMsg(request))
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("Cancellation did not retire the stalled connection")
	}
	require.ErrorIs(t, <-update.errCh, context.Canceled)
	require.False(t, committed.Load())
	_, err := peer.Write([]byte{0x0a, 0x00})
	require.Error(t, err, "Late ACK must not be accepted on a retired connection")
}

func TestZDSCompletedCallerCannotCancelNextUpdate(t *testing.T) {
	connection, peer := zdsSocketPair(t)
	for i := range 2 {
		ctx, cancel := context.WithCancel(context.Background())
		committed := false
		update := zdsUpdate{ctx: ctx, errCh: make(chan error, 1),
			request: &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_SnapshotSent{SnapshotSent: &pb.SnapshotSent{}}},
			onAck:   func() { committed = true },
		}
		responded := make(chan error, 1)
		go func() {
			var buffer [1024]byte
			_, err := peer.Read(buffer[:])
			if err == nil {
				_, err = peer.Write([]byte{0x0a, 0x00})
			}
			responded <- err
		}()
		require.NoError(t, (&Server{}).processUpdate(context.Background(), connection, update), "update %d", i)
		require.NoError(t, <-update.errCh)
		cancel()
		require.True(t, committed, "Cache commit must precede published success")
		require.NoError(t, <-responded)
	}
}

func liveZDSAckServer(t *testing.T, seed bool) (*Server, context.CancelFunc, <-chan struct{}, string) {
	t.Helper()
	address := filepath.Join(t.TempDir(), "zds.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: address, Net: "unixpacket"})
	require.NoError(t, err)
	server := &Server{l: listener, logger: hivetest.Logger(t), metrics: NewMetrics(),
		updates: make(chan zdsUpdate, 10), initialSnapshotSeeded: make(chan struct{}),
	}
	if seed {
		server.SeedInitialSnapshot()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("ZDS shutdown did not complete")
		}
	})
	return server, cancel, done, address
}

func dialZDSAckPeer(t *testing.T, address string) *ztunnelConn {
	t.Helper()
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: address, Net: "unixpacket"})
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	t.Cleanup(func() { conn.Close() })
	return &ztunnelConn{conn: conn}
}

func TestZDSReplacementInterruptsStalledAck(t *testing.T) {
	server, _, _, address := liveZDSAckServer(t, true)
	old := dialZDSAckPeer(t, address)
	sendHello(t, old.conn)
	expectSnapshotAndAck(t, old, old.conn, "")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	oldResult := make(chan error, 1)
	request := &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_SnapshotSent{SnapshotSent: &pb.SnapshotSent{}}}
	go func() {
		oldResult <- server.sendUpdateAndWaitForAck(ctx, zdsUpdate{request: request, errCh: make(chan error, 1)})
	}()
	// Leave the old update unacknowledged while a new connection arrives.
	require.NoError(t, old.readMsg(&pb.WorkloadRequest{}))
	replacement := dialZDSAckPeer(t, address)
	sendHello(t, replacement.conn)
	expectSnapshotAndAck(t, replacement, replacement.conn, "")
	require.Error(t, <-oldResult, "Interrupted operation must not receive a false ACK")
	newResult := make(chan error, 1)
	go func() {
		newResult <- server.sendUpdateAndWaitForAck(ctx, zdsUpdate{request: request, errCh: make(chan error, 1)})
	}()
	expectSnapshotAndAck(t, replacement, replacement.conn, "")
	require.NoError(t, <-newResult)
	require.Error(t, old.readMsg(&pb.WorkloadRequest{}), "Old connection must be retired before replacement consumes updates")
}

func TestZDSShutdownInterruptsStartupWaits(t *testing.T) {
	for _, stage := range []string{"hello", "snapshot-seed", "snapshot-ack"} {
		t.Run(stage, func(t *testing.T) {
			_, cancel, done, address := liveZDSAckServer(t, stage == "snapshot-ack")
			peer := dialZDSAckPeer(t, address)
			if stage != "hello" {
				sendHello(t, peer.conn)
			}
			if stage == "snapshot-ack" {
				require.NoError(t, peer.readMsg(&pb.WorkloadRequest{}))
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("Shutdown did not interrupt " + stage)
			}
		})
	}
}

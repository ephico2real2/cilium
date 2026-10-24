// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path"
	"sync"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/iptables"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

const (
	// defaultZDSUnixAddress is the default Unix socket address for the ZDS server.
	defaultZDSUnixAddress = "/var/run/cilium/ztunnel.sock"
	defaultZDSAckTimeout  = 30 * time.Second
	logStage              = "stage"
)

type ztunnelConn struct {
	conn *net.UnixConn
}

func (zc *ztunnelConn) Close() error {
	return zc.conn.Close()
}

func (zc *ztunnelConn) readHello() (*pb.ZdsHello, error) {
	hello := &pb.ZdsHello{}
	if err := zc.readMsg(hello); err != nil {
		return nil, err
	}
	return hello, nil
}

func (zc *ztunnelConn) readResponse() (*pb.WorkloadResponse, error) {
	resp := &pb.WorkloadResponse{}
	if err := zc.readMsg(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (zc *ztunnelConn) readMsg(msg proto.Message) error {
	var buf [1024]byte
	// Use ReadMsgUnix to detect message truncation
	n, _, flags, _, err := zc.conn.ReadMsgUnix(buf[:], nil)
	if err != nil {
		return err
	}

	// Check if message was truncated (MSG_TRUNC flag)
	if flags&unix.MSG_TRUNC != 0 {
		return fmt.Errorf("message truncated: received %d bytes but message was larger than 1024 byte buffer", n)
	}

	return proto.Unmarshal(buf[:n], msg)
}

func (zc *ztunnelConn) sendMsg(req *pb.WorkloadRequest, ns *netns.NetNS) error {
	var rights []byte
	if ns != nil {
		rights = unix.UnixRights(ns.FD())
		defer ns.Close()
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}

	_, _, err = zc.conn.WriteMsgUnix(data, rights, nil)
	return err
}

func (zc *ztunnelConn) sendAndWaitForAck(req *pb.WorkloadRequest, netnsPath string) error {
	return zc.sendAndWaitForAckWithTimeout(req, netnsPath, defaultZDSAckTimeout)
}

func (zc *ztunnelConn) sendAndWaitForAckWithTimeout(req *pb.WorkloadRequest, netnsPath string, timeout time.Duration) error {
	if err := zc.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("setting ZDS acknowledgment deadline: %w", err)
	}
	defer zc.conn.SetDeadline(time.Time{})
	var ns *netns.NetNS
	if netnsPath != "" {
		var err error
		ns, err = netns.OpenPinned(netnsPath)
		if err != nil {
			return fmt.Errorf("failed to open netns: %w", err)
		}
		defer ns.Close()
	}

	if err := zc.sendMsg(req, ns); err != nil {
		return err
	}

	resp, err := zc.readResponse()
	if err != nil {
		return err
	}

	ack := resp.GetAck()
	if ack == nil {
		return fmt.Errorf("ztunnel response did not contain an acknowledgment")
	}
	if ack.GetError() != "" {
		return fmt.Errorf("ztunnel responded with an ack error: %s", ack.GetError())
	}

	return nil
}

func endpointToWorkload(ep *endpoint.Endpoint) (*pb.AddWorkload, error) {
	pod := ep.GetPod()
	if pod == nil {
		return nil, fmt.Errorf("endpoint %d has no pod metadata", ep.GetID16())
	}

	namespace := ep.GetK8sNamespace()
	name := ep.GetK8sPodName()
	svcAccount := pod.Spec.ServiceAccountName

	return &pb.AddWorkload{
		WorkloadInfo: &pb.WorkloadInfo{
			Namespace:      namespace,
			Name:           name,
			ServiceAccount: svcAccount,
		},
		Uid: string(pod.GetUID()),
	}, nil
}

type serverParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    *slog.Logger
	Config    config.Config
	Metrics   *Metrics

	EndpointManager endpointmanager.EndpointManager

	// ZDSUnixAddr overrides the default ZDS unix socket address.
	// If empty, config.DefaultZtunnelUnixAddress is used.
	// This field is intended for testing purposes only.
	ZDSUnixAddr string `optional:"true"`
}

type serverOut struct {
	cell.Out
	*Server
	EndpointEnroller
}

// EndpointEnroller allows enrolling and disenrolling endpoints to/from the ztunnel.
type EndpointEnroller interface {
	SeedInitialSnapshot(ep ...*endpoint.Endpoint)
	EnrollEndpoint(ep *endpoint.Endpoint) error
	DisenrollEndpoint(ep *endpoint.Endpoint) error
}

var _ EndpointEnroller = &Server{}

type Server struct {
	l      *net.UnixListener
	logger *slog.Logger

	endpointCache      map[uint16]*endpoint.Endpoint
	endpointCacheMutex lock.Mutex

	updates               chan zdsUpdate // updates to send to ztunnel
	initialSnapshotSeeded chan struct{}
	metrics               *Metrics
}

type zdsUpdate struct {
	ctx       context.Context // Caller lifetime; expired queued work must not be sent.
	request   *pb.WorkloadRequest
	netnsPath string     // Path to network namespace; empty string if no netns needed
	errCh     chan error // Channel to signal if the update was sent successfully
	onAck     func()     // Commit cache state before publishing acknowledgment.
}

// newZDSServer creates a new ZDS (Ztunnel Discovery Service) server that communicates
// with ztunnel over a Unix domain socket. For details on the ZDS protocol, see
// pkg/ztunnel/pb/zds_ztunnel.proto.
func newZDSServer(p serverParams) serverOut {
	if !p.Config.EnableZTunnel {
		return serverOut{}
	}
	if p.Metrics == nil {
		p.Metrics = NewMetrics()
	}
	p.Metrics.Enable()
	server := &Server{
		logger:                p.Logger,
		updates:               make(chan zdsUpdate, 100),
		endpointCache:         make(map[uint16]*endpoint.Endpoint),
		initialSnapshotSeeded: make(chan struct{}),
		metrics:               p.Metrics,
	}

	zdsUnixAddr := defaultZDSUnixAddress
	if p.ZDSUnixAddr != "" {
		zdsUnixAddr = p.ZDSUnixAddr
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			err := os.RemoveAll(zdsUnixAddr)
			if err != nil {
				return err
			}

			// if we need to create the basedir for the zdsUnixAddr, do it
			if err := os.MkdirAll(path.Dir(zdsUnixAddr), 0755); err != nil {
				return fmt.Errorf("failed to create ztunnel unix addr directory: %w", err)
			}

			resolvedAddr, err := net.ResolveUnixAddr("unixpacket", zdsUnixAddr)
			if err != nil {
				return fmt.Errorf("failed to resolve ztunnel unix addr: %w", err)
			}

			server.l, err = net.ListenUnix("unixpacket", resolvedAddr)
			if err != nil {
				return fmt.Errorf("failed to listen on ztunnel unix addr: %w", err)
			}

			wg.Go(func() {
				server.Serve(ctx)
			})

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()
			wg.Wait()
			return nil
		},
	})

	out := serverOut{
		Server:           server,
		EndpointEnroller: server,
	}

	return out
}

func (s *Server) Serve(ctx context.Context) {
	// Start a goroutine to close the listener when the context is canceled.
	// This will cause Accept() to return an error, unblocking the main loop.
	go func() {
		<-ctx.Done()
		s.l.Close()
	}()

	var cancelPrevConn context.CancelFunc
	var previousDone <-chan struct{}
	var wg sync.WaitGroup

	for {
		conn, err := s.l.AcceptUnix()
		if err != nil {
			// If the context is done, this is an expected error on shutdown.
			if ctx.Err() != nil {
				wg.Wait() // Wait for active connection to finish
				return
			}
			s.logger.Error("failed to accept connection", logfields.Error, err)
			return
		}

		// Cancel the previous connection if it exists.
		// This causes the old handleConn to exit immediately via context.Done()
		// Only one connection will be actively reading from s.updates at a time.
		if cancelPrevConn != nil {
			s.logger.Info("canceling previous ztunnel connection for new connection")
			cancelPrevConn()
			// Cancellation closes blocked reads. Join before starting another
			// consumer of the shared update queue or replaying its snapshot.
			<-previousDone
		}

		zc := &ztunnelConn{conn: conn}
		connCtx, cancel := context.WithCancel(ctx)
		cancelPrevConn = cancel
		done := make(chan struct{})
		previousDone = done

		wg.Go(func() {
			defer close(done)
			defer cancel()
			if err := s.handleConn(connCtx, zc); err != nil {
				s.logger.Error("failed to handle connection", logfields.Error, err)
			}
		})
	}
}

func (s *Server) handleConn(ctx context.Context, zc *ztunnelConn) error {
	defer zc.Close()
	stopClose := context.AfterFunc(ctx, func() { zc.Close() })
	defer stopClose()
	s.metrics.ConnectionActive.Inc()
	defer s.metrics.ConnectionActive.Dec()

	s.logger.Info("new ztunnel connection")

	if err := zc.conn.SetReadDeadline(time.Now().Add(defaultZDSAckTimeout)); err != nil {
		return fmt.Errorf("setting ZDS hello deadline: %w", err)
	}
	hello, err := zc.readHello()
	if err != nil {
		return fmt.Errorf("failed to read hello from ztunnel: %w", err)
	}
	if err := zc.conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	if hello.GetVersion() != pb.Version_V1 {
		return fmt.Errorf("unsupported ztunnel ZDS version: %s", hello.GetVersion())
	}
	s.logger.Info("received hello from ztunnel", logfields.Version, hello.GetVersion())

	// Wait for initial snapshot to be seeded
	s.logger.Info("waiting for initial snapshot to be seeded")
	select {
	case <-s.initialSnapshotSeeded:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.logger.Info("initial snapshot seeded, sending to ztunnel")

	// Send the initial snapshot to this connection
	if err := s.sendInitialSnapshot(zc); err != nil {
		return fmt.Errorf("failed to send initial snapshot: %w", err)
	}
	s.logger.Info("initial snapshot sent, processing updates")

	for {
		select {
		case update := <-s.updates:
			if err := s.processUpdate(ctx, zc, update); err != nil {
				return fmt.Errorf("failed to send update: %w", err)
			}

		case <-ctx.Done():
			s.logger.Info("context cancelled, closing ztunnel connection")
			return nil
		}
	}
}

func (s *Server) processUpdate(ctx context.Context, zc *ztunnelConn, update zdsUpdate) error {
	complete := func(err error) {
		if update.errCh != nil {
			update.errCh <- err
			close(update.errCh)
		}
	}
	if err := ctx.Err(); err != nil {
		complete(err)
		return err
	}
	if update.ctx == nil {
		update.ctx = ctx
	}
	if err := update.ctx.Err(); err != nil {
		// Never open the namespace FD or transmit an expired queued request.
		complete(err)
		return nil
	}
	closed := make(chan struct{})
	stopClose := context.AfterFunc(update.ctx, func() {
		zc.Close()
		close(closed)
	})
	err := zc.sendAndWaitForAck(update.request, update.netnsPath)
	// Stop (or join) cancellation before publishing success: the caller
	// normally cancels its context as soon as it receives the result.
	if !stopClose() {
		<-closed
		err = update.ctx.Err()
	}
	if canceled := update.ctx.Err(); canceled != nil {
		// V1 has no request nonce. Retire this connection so an ambiguous
		// late ACK cannot be attributed to the next request.
		zc.Close()
		err = canceled
	}
	if err == nil && update.onAck != nil {
		update.onAck()
	}
	complete(err)
	return err
}

func (s *Server) EnrollEndpoint(ep *endpoint.Endpoint) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultZDSAckTimeout)
	defer cancel()
	return s.EnrollEndpointContext(ctx, ep)
}

// EnrollEndpointContext only records enrollment after an explicit successful
// proxy acknowledgment. Cancellation also bounds waiting for a disconnected
// proxy or a full update queue; installed capture rules remain fail-closed.
func (s *Server) EnrollEndpointContext(ctx context.Context, ep *endpoint.Endpoint) error {
	started := time.Now()
	s.logger.Info("enrolling endpoint to ztunnel", logfields.EndpointID, ep.GetID16())
	s.metrics.EnrollmentTotal.Inc()

	// Check if endpoint is already enrolled
	s.endpointCacheMutex.Lock()
	if _, ok := s.endpointCache[ep.GetID16()]; ok {
		s.endpointCacheMutex.Unlock()
		s.logger.Info("endpoint already in ztunnel", logfields.EndpointID, ep.GetID16())
		return nil
	}
	s.endpointCacheMutex.Unlock()

	ns, err := netns.OpenPinned(ep.GetContainerNetnsPath())
	if err != nil {
		s.metrics.EnrollmentFailures.WithLabelValues("netns_failed").Inc()
		s.logger.Error("failed to open netns file",
			logfields.EndpointID, ep.GetID16(),
			logfields.Error, err,
		)
		return err
	}
	defer ns.Close()

	if err = ns.Do(func() error {
		return iptables.CreateInPodRules(s.logger, option.Config.EnableIPv4, option.Config.EnableIPv6)
	}); err != nil {
		s.metrics.EnrollmentFailures.WithLabelValues("iptables_failed").Inc()
		return fmt.Errorf("unable to setup iptable rules for ztunnel inpod mode: %w", err)
	}

	workload, err := endpointToWorkload(ep)
	if err != nil {
		s.metrics.EnrollmentFailures.WithLabelValues("conversion_failed").Inc()
		s.logger.Error("failed to convert endpoint to workload",
			logfields.EndpointID, ep.GetID16(),
			logfields.Error, err,
		)
		return err
	}

	req := &pb.WorkloadRequest{
		Payload: &pb.WorkloadRequest_Add{
			Add: workload,
		},
	}

	update := zdsUpdate{
		request:   req,
		netnsPath: ep.GetContainerNetnsPath(),
		errCh:     make(chan error, 1),
		onAck: func() {
			s.endpointCacheMutex.Lock()
			s.endpointCache[ep.GetID16()] = ep
			s.endpointCacheMutex.Unlock()
		},
	}

	if err := s.sendUpdateAndWaitForAck(ctx, update); err != nil {
		s.metrics.EnrollmentFailures.WithLabelValues("send_failed").Inc()
		return fmt.Errorf("sending update failed: %w", err)
	}

	s.logger.Info("Endpoint enrollment acknowledged",
		logfields.EndpointID, ep.GetID16(),
		logfields.Duration, time.Since(started),
		logStage, "zds-enrollment",
	)
	return nil
}

func (s *Server) sendUpdateAndWaitForAck(ctx context.Context, update zdsUpdate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	update.ctx = ctx
	select {
	case s.updates <- update:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err, ok := <-update.errCh:
		if !ok {
			return fmt.Errorf("ZDS update completed without an acknowledgment result")
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) DisenrollEndpoint(ep *endpoint.Endpoint) error {
	s.logger.Info("disenrolling endpoint from ztunnel", logfields.EndpointID, ep.GetID16())

	ns, err := netns.OpenPinned(ep.GetContainerNetnsPath())
	if err != nil {
		s.logger.Error("failed to open netns file",
			logfields.EndpointID, ep.GetID16(),
			logfields.Error, err,
		)
		return err
	}
	defer ns.Close()

	if err = ns.Do(func() error {
		return iptables.DeleteInPodRules(s.logger, option.Config.EnableIPv4, option.Config.EnableIPv6)
	}); err != nil {
		return fmt.Errorf("unable to remove iptable rules for ztunnel inpod mode: %w", err)
	}

	pod := ep.GetPod()
	if pod == nil {
		s.logger.Error("endpoint has no pod metadata, cannot disenroll",
			logfields.EndpointID, ep.GetID16(),
		)
		return fmt.Errorf("endpoint %d has no pod metadata", ep.GetID16())
	}

	req := &pb.WorkloadRequest{
		Payload: &pb.WorkloadRequest_Del{
			Del: &pb.DelWorkload{
				Uid: string(pod.GetUID()),
			},
		},
	}

	update := zdsUpdate{
		request:   req,
		netnsPath: "",
		errCh:     make(chan error, 1),
		onAck: func() {
			s.endpointCacheMutex.Lock()
			delete(s.endpointCache, ep.GetID16())
			s.endpointCacheMutex.Unlock()
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultZDSAckTimeout)
	defer cancel()
	if err := s.sendUpdateAndWaitForAck(ctx, update); err != nil {
		return fmt.Errorf("sending update failed: %w", err)
	}

	return nil
}

// SeedInitialSnapshot seeds the initial snapshot that will be sent to each new ztunnel connection.
// This should be called once to provide the initial state. Each new connection will automatically
// receive this snapshot, solving the reconnection problem.
func (s *Server) SeedInitialSnapshot(eps ...*endpoint.Endpoint) {
	s.logger.Info("seeding initial snapshot")
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()

	// Add all endpoints to the cache
	for _, ep := range eps {
		s.endpointCache[ep.GetID16()] = ep
	}

	close(s.initialSnapshotSeeded)
	s.logger.Info("initial snapshot seeded")
}

// sendInitialSnapshot sends the seeded initial snapshot to the given connection.
// This is called by handleConn for each new connection.
func (s *Server) sendInitialSnapshot(zc *ztunnelConn) error {
	s.endpointCacheMutex.Lock()
	endpoints := make([]*endpoint.Endpoint, 0, len(s.endpointCache))
	for _, ep := range s.endpointCache {
		endpoints = append(endpoints, ep)
	}
	s.endpointCacheMutex.Unlock()
	// Network ACKs must not hold the cache mutex and prevent other callers
	// from observing their own cancellation deadlines.
	for _, ep := range endpoints {
		ns, err := netns.OpenPinned(ep.GetContainerNetnsPath())
		if err != nil {
			s.logger.Error("failed to open netns file",
				logfields.EndpointID, ep.GetID16(),
				logfields.Error, err,
			)
			return err
		}

		if err = ns.Do(func() error {
			return iptables.CreateInPodRules(s.logger, option.Config.EnableIPv4, option.Config.EnableIPv6)
		}); err != nil {
			ns.Close()
			return fmt.Errorf("unable to setup iptable rules for ztunnel inpod mode: %w", err)
		}
		ns.Close()

		workload, err := endpointToWorkload(ep)
		if err != nil {
			s.logger.Error("failed to convert endpoint to workload",
				logfields.EndpointID, ep.GetID16(),
				logfields.Error, err,
			)
			return err
		}

		req := &pb.WorkloadRequest{
			Payload: &pb.WorkloadRequest_Add{
				Add: workload,
			},
		}

		if err := zc.sendAndWaitForAck(req, ep.GetContainerNetnsPath()); err != nil {
			return fmt.Errorf("failed to send endpoint message: %w", err)
		}
	}

	req := &pb.WorkloadRequest{
		Payload: &pb.WorkloadRequest_SnapshotSent{
			SnapshotSent: &pb.SnapshotSent{},
		},
	}

	if err := zc.sendAndWaitForAck(req, ""); err != nil {
		return fmt.Errorf("failed to send snapshot message: %w", err)
	}

	return nil
}

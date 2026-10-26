// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/cilium/cilium/pkg/kpr"
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
	conn       *net.UnixConn
	proxyEpoch []byte
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

// errZDSRequestRejected marks a request refused before any byte of it was
// written. The connection is unaffected: only that request fails, and other
// endpoints keep using the connection.
var errZDSRequestRejected = errors.New("ZDS request rejected before transmission")

func rejectedBeforeWrite(err error) error {
	return fmt.Errorf("%w: %w", errZDSRequestRejected, err)
}

// errZDSNACK marks a request ztunnel parsed and refused with an ACK error. For
// a bound ADD the refusal is definitive: ztunnel installs the owner only when
// the ADD succeeds.
var errZDSNACK = errors.New("ztunnel responded with an ack error")

func (zc *ztunnelConn) sendMsg(req *pb.WorkloadRequest, ns *netns.NetNS) error {
	var rights []byte
	if ns != nil {
		rights = unix.UnixRights(ns.FD())
		defer ns.Close()
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return rejectedBeforeWrite(err)
	}

	if len(data) > 1024 {
		return rejectedBeforeWrite(fmt.Errorf("ZDS request exceeds native 1024-byte packet bound"))
	}
	n, oob, err := zc.conn.WriteMsgUnix(data, rights, nil)
	if err != nil {
		return err
	}
	if n != len(data) || oob != len(rights) {
		return fmt.Errorf("incomplete native ZDS packet write")
	}
	return nil
}

func (zc *ztunnelConn) sendAndWaitForAck(req *pb.WorkloadRequest, netnsPath string) error {
	return zc.sendAndWaitForAckWithTimeout(req, netnsPath, defaultZDSAckTimeout)
}

func (zc *ztunnelConn) sendAndWaitForAckWithTimeout(req *pb.WorkloadRequest, netnsPath string, timeout time.Duration) error {
	return zc.sendAndWaitForAckBeforeWrite(req, netnsPath, timeout, nil)
}

func (zc *ztunnelConn) sendAndWaitForAckBeforeWrite(req *pb.WorkloadRequest, netnsPath string, timeout time.Duration, beforeWrite func() error) error {
	if err := zc.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("setting ZDS acknowledgment deadline: %w", err)
	}
	defer zc.conn.SetDeadline(time.Time{})
	var ns *netns.NetNS
	if netnsPath != "" {
		var err error
		ns, err = netns.OpenPinned(netnsPath)
		if err != nil {
			return rejectedBeforeWrite(fmt.Errorf("failed to open netns: %w", err))
		}
		defer ns.Close()
	}

	if add := req.GetAdd(); add != nil && add.Binding != nil {
		if ns == nil {
			return rejectedBeforeWrite(fmt.Errorf("bound ADD has no sandbox FD"))
		}
		var st unix.Stat_t
		if err := unix.Fstat(ns.FD(), &st); err != nil {
			return rejectedBeforeWrite(err)
		}
		if add.Binding.NetnsDev != uint64(st.Dev) || add.Binding.NetnsIno != st.Ino {
			return rejectedBeforeWrite(fmt.Errorf("sandbox changed between capture and actual ADD FD"))
		}
		if len(add.Binding.ProxyEpoch) == 0 {
			add.Binding.ProxyEpoch = append([]byte(nil), zc.proxyEpoch...)
		}
		if err := validateBinding(add.Binding); err != nil {
			return rejectedBeforeWrite(err)
		}
		if !bytes.Equal(add.Binding.ProxyEpoch, zc.proxyEpoch) {
			return rejectedBeforeWrite(fmt.Errorf("ADD belongs to an earlier proxy execution; explicit recovery required"))
		}
	}

	if beforeWrite != nil {
		if err := beforeWrite(); err != nil {
			return rejectedBeforeWrite(err)
		}
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
		return fmt.Errorf("%w: %s", errZDSNACK, ack.GetError())
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

	// KPRConfig decides, with Config, whether TCP DNS bypasses ztunnel. Absent, the bypass stays off.
	KPRConfig kpr.KPRConfig `optional:"true"`

	// ZDSUnixAddr overrides the default ZDS unix socket address.
	// If empty, config.DefaultZtunnelUnixAddress is used.
	// This field is intended for testing purposes only.
	ZDSUnixAddr string `optional:"true"`
}

type serverOut struct {
	cell.Out
	*Server
	EndpointEnroller
	EndpointDeletionCleaner
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

	endpointCache map[uint16]*endpoint.Endpoint
	// Writers take the exclusive lock; read-only checks (capture
	// verification, snapshot bindings) take the shared lock and never
	// exclude each other.
	endpointCacheMutex           lock.RWMutex
	strictDeletedEndpointCleanup bool
	drainBindings                map[endpointIncarnation]*pb.WorkloadBinding
	policyADDAttempts            map[endpointIncarnation]*pb.WorkloadBinding
	policyADDHistory             map[endpointIncarnation][]*pb.WorkloadBinding
	policyADDPending             map[*pendingPolicyADD]struct{}
	endpointOperationGate        chan struct{}
	// liveProxyEpoch names the ztunnel execution whose connection delivered
	// its initial snapshot and now consumes updates. Serve keeps at most one
	// such connection. Guarded by endpointCacheMutex.
	liveProxyEpoch []byte

	updates               chan zdsUpdate // updates to send to ztunnel
	initialSnapshotSeeded chan struct{}
	metrics               *Metrics
	// directResolverDNS: approved DNS resolvers are configured, so enrolled
	// Pods send TCP DNS past ztunnel (iptables.CreateInPodRules).
	directResolverDNS bool
}

type zdsUpdate struct {
	ctx           context.Context // Caller lifetime; expired queued work must not be sent.
	request       *pb.WorkloadRequest
	netnsPath     string     // Path to network namespace; empty string if no netns needed
	errCh         chan error // Channel to signal if the update was sent successfully
	onAck         func()     // Commit cache state before publishing acknowledgment.
	policyPending *pendingPolicyADD
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
		logger:                       p.Logger,
		updates:                      make(chan zdsUpdate, 100),
		endpointCache:                make(map[uint16]*endpoint.Endpoint),
		initialSnapshotSeeded:        make(chan struct{}),
		metrics:                      p.Metrics,
		strictDeletedEndpointCleanup: p.Config.RequireMTLS,
	}
	var reason string
	server.directResolverDNS, reason = directResolverDNS(p.Config, p.KPRConfig, option.Config)
	p.Logger.Info("TCP DNS from enrolled Pods",
		logfields.Enabled, server.directResolverDNS,
		logfields.Reason, reason,
	)

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
		Server:                  server,
		EndpointEnroller:        server,
		EndpointDeletionCleaner: server,
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
	if s.strictDeletedEndpointCleanup {
		if err := requireRootProxyPeer(zc); err != nil {
			return err
		}
	}

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
	if hello.GetVersion() != pb.Version_V1 && hello.GetVersion() != pb.Version_V2_DRAIN {
		return fmt.Errorf("unsupported ztunnel ZDS version: %s", hello.GetVersion())
	}
	if s.strictDeletedEndpointCleanup && hello.GetVersion() != pb.Version_V2_DRAIN {
		return fmt.Errorf("strict capture requires typed drain protocol")
	}
	if hello.GetVersion() == pb.Version_V2_DRAIN {
		if len(hello.ProxyEpoch) != 32 {
			return fmt.Errorf("invalid proxy execution epoch")
		}
		zc.proxyEpoch = append([]byte(nil), hello.ProxyEpoch...)
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
	s.setLiveProxyEpoch(zc.proxyEpoch)
	defer s.clearLiveProxyEpoch(zc.proxyEpoch)

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
	defer s.finishPendingPolicyADD(update.policyPending)
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
	var err error
	if drain := update.request.GetDrain(); drain != nil {
		err = zc.sendDrain(drain)
	} else {
		err = zc.sendAndWaitForAckBeforeWrite(update.request, update.netnsPath, defaultZDSAckTimeout, func() error { return s.recordPolicyADDAttempt(update.request, update.netnsPath) })
		if errors.Is(err, errZDSNACK) {
			// ztunnel's whole response was read: the refused binding was not
			// installed, whatever happens to this caller's context next.
			s.forgetRefusedADD(update.request, update.netnsPath)
		}
	}
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
	if errors.Is(err, errZDSRequestRejected) {
		// Nothing was written: the connection stays in a known state.
		return nil
	}
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
	return s.EnrollEndpointForOwnerContext(ctx, ep, ep)
}

// EnrollEndpointForOwnerContext uses fresh private wire metadata while binding
// the acknowledged cache entry to the managed endpoint's actual lifetime.
func (s *Server) EnrollEndpointForOwnerContext(ctx context.Context, owner, ep *endpoint.Endpoint) error {
	if owner == nil || ep == nil {
		return fmt.Errorf("endpoint enrollment requires managed owner and wire metadata")
	}
	if s.strictDeletedEndpointCleanup && owner != ep {
		ownerKey, err := incarnation(owner)
		if err != nil || !sameIncarnation(ep, ownerKey) || owner.GetK8sNamespace() != ep.GetK8sNamespace() || owner.GetK8sPodName() != ep.GetK8sPodName() {
			return fmt.Errorf("enrollment wire metadata does not match managed endpoint incarnation")
		}
	}
	owner.ObserveZtunnelRequired()
	started := time.Now()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.strictDeletedEndpointCleanup {
		release, err := s.acquireEndpointOperation(ctx)
		if err != nil {
			return err
		}
		defer release()
		if !owner.IsAlive() {
			return fmt.Errorf("cannot enroll disconnected endpoint %d", ep.GetID16())
		}
	}
	s.logger.Info("enrolling endpoint to ztunnel", logfields.EndpointID, ep.GetID16())
	s.metrics.EnrollmentTotal.Inc()

	// An earlier ACK does not establish that capture is still installed.
	// Reassert capture and require a fresh ADD ACK on every retry.
	netnsPath := ep.GetContainerNetnsPath()
	ns, err := netns.OpenPinned(netnsPath)
	if err != nil {
		s.metrics.EnrollmentFailures.WithLabelValues("netns_failed").Inc()
		s.logger.Error("failed to open netns file",
			logfields.EndpointID, ep.GetID16(),
			logfields.Error, err,
		)
		return err
	}
	defer ns.Close()
	if err := ctx.Err(); err != nil {
		return err
	}

	if err = ns.Do(func() error {
		return iptables.CreateInPodRules(s.logger, option.Config.EnableIPv4, option.Config.EnableIPv6, s.directResolverDNS)
	}); err != nil {
		s.metrics.EnrollmentFailures.WithLabelValues("iptables_failed").Inc()
		return fmt.Errorf("unable to setup iptable rules for ztunnel inpod mode: %w", err)
	}
	if err := ctx.Err(); err != nil {
		// Keep installed capture while the caller retries or cancels creation.
		return err
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
	var acknowledged *endpoint.Endpoint
	if s.strictDeletedEndpointCleanup {
		if ep.K8sUID == "" || workload.Uid != ep.K8sUID {
			s.metrics.EnrollmentFailures.WithLabelValues("uid_mismatch").Inc()
			return fmt.Errorf("endpoint %d Pod metadata UID does not match immutable CNI UID", ep.GetID16())
		}
		acknowledged = freezeAcknowledgedEndpoint(ep, workload, netnsPath)
	}

	if s.strictDeletedEndpointCleanup {
		workload.Binding, err = bindingForCapture(ctx, ep, ns)
		if err != nil {
			return err
		}
	}

	req := &pb.WorkloadRequest{
		Payload: &pb.WorkloadRequest_Add{
			Add: workload,
		},
	}

	update := zdsUpdate{
		request:   req,
		netnsPath: netnsPath,
		errCh:     make(chan error, 1),
		onAck: func() {
			if s.strictDeletedEndpointCleanup {
				s.commitStrictEnrollment(ctx, owner, acknowledged)
				s.endpointCacheMutex.Lock()
				if ctx.Err() == nil && owner.IsAlive() {
					if s.drainBindings == nil {
						s.drainBindings = make(map[endpointIncarnation]*pb.WorkloadBinding)
					}
					key, _ := incarnation(acknowledged)
					s.drainBindings[key] = proto.Clone(workload.Binding).(*pb.WorkloadBinding)
					s.pruneAcknowledgedPolicyHistoryLocked(key, workload.Binding)
				}
				s.endpointCacheMutex.Unlock()
				return
			}
			s.endpointCacheMutex.Lock()
			s.endpointCache[ep.GetID16()] = ep
			s.endpointCacheMutex.Unlock()
		},
	}

	if err := s.sendUpdateAndWaitForAck(ctx, update); err != nil {
		s.metrics.EnrollmentFailures.WithLabelValues("send_failed").Inc()
		return fmt.Errorf("sending update failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.strictDeletedEndpointCleanup && !owner.IsAlive() {
		return fmt.Errorf("endpoint %d disconnected during enrollment", ep.GetID16())
	}

	s.logger.Info("Endpoint enrollment acknowledged",
		logfields.EndpointID, ep.GetID16(),
		logfields.K8sUID, workload.Uid,
		logfields.K8sNamespace, workload.WorkloadInfo.Namespace,
		logfields.Pod, workload.WorkloadInfo.Name,
		logfields.Duration, time.Since(started),
		logStage, "zds-enrollment",
	)
	return nil
}

func (s *Server) sendUpdateAndWaitForAck(ctx context.Context, update zdsUpdate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pending, err := s.beginPendingPolicyADD(update.request, update.netnsPath)
	if err != nil {
		return err
	}
	update.policyPending = pending
	update.ctx = ctx
	select {
	case s.updates <- update:
	case <-ctx.Done():
		s.finishPendingPolicyADD(pending) // Not enqueued: no consumer can transmit it.
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
	ctx, cancel := context.WithTimeout(context.Background(), defaultZDSAckTimeout)
	defer cancel()
	return s.DisenrollEndpointContext(ctx, ep)
}

// DisenrollEndpointContext only removes live capture in compatibility mode.
// Strict endpoints keep their capture until exact sandbox deletion; a namespace
// label change alone cannot authorize an unsafe partial release.
func (s *Server) DisenrollEndpointContext(ctx context.Context, ep *endpoint.Endpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.strictDeletedEndpointCleanup {
		return ErrStrictLiveUnenrollment
	}
	s.logger.Info("disenrolling endpoint from ztunnel", logfields.EndpointID, ep.GetID16())
	ns, err := netns.OpenPinned(ep.GetContainerNetnsPath())
	if err != nil {
		return fmt.Errorf("opening namespace for live unenrollment: %w", err)
	}
	defer ns.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ns.Do(func() error {
		return iptables.DeleteInPodRules(s.logger, option.Config.EnableIPv4, option.Config.EnableIPv6)
	}); err != nil {
		return fmt.Errorf("unable to remove iptable rules for ztunnel inpod mode: %w", err)
	}
	pod := ep.GetPod()
	if pod == nil {
		return fmt.Errorf("endpoint %d has no pod metadata", ep.GetID16())
	}
	update := zdsUpdate{
		request: &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Del{Del: &pb.DelWorkload{Uid: string(pod.GetUID())}}},
		errCh:   make(chan error, 1),
		onAck: func() {
			s.endpointCacheMutex.Lock()
			defer s.endpointCacheMutex.Unlock()
			delete(s.endpointCache, ep.GetID16())
		},
	}
	if err := s.sendUpdateAndWaitForAck(ctx, update); err != nil {
		return fmt.Errorf("sending update failed: %w", err)
	}
	return ctx.Err()
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
		if s.strictDeletedEndpointCleanup {
			// A snapshot list can have been captured before managed deletion.
			// Check lifetime under the retirement mutex so it cannot reinsert
			// an endpoint whose deletion callback already retired its cache.
			if !ep.IsAlive() {
				continue
			}
			// An acknowledged owner takes precedence over a bootstrap list.
			if s.endpointCache[ep.GetID16()] != nil {
				continue
			}
			ownedUID := false
			for _, cached := range s.endpointCache {
				if ep.K8sUID != "" && cached.K8sUID == ep.K8sUID {
					ownedUID = true
					break
				}
			}
			if ownedUID {
				continue
			}
		}
		s.endpointCache[ep.GetID16()] = ep
	}

	close(s.initialSnapshotSeeded)
	s.logger.Info("initial snapshot seeded")
}

// sendInitialSnapshot sends the seeded initial snapshot to the given connection.
// This is called by handleConn for each new connection.
// snapshotBinding returns the retained ADD binding a strict endpoint can
// replay into the ztunnel execution identified by epoch, or why it cannot.
// A later ADD of the same original binding may be installed although its
// answer was lost; ztunnel refuses a replay of the older capture generation,
// and a refused replay fails this snapshot and every later one. The newest
// retained binding of that original ADD is accepted as a refresh of either.
func (s *Server) snapshotBinding(ep *endpoint.Endpoint, epoch []byte) (*pb.WorkloadBinding, string) {
	key, err := incarnation(ep)
	if err != nil {
		return nil, "it has no immutable incarnation"
	}
	s.endpointCacheMutex.RLock()
	binding := s.drainBindings[key]
	if binding != nil {
		for _, b := range append([]*pb.WorkloadBinding{s.policyADDAttempts[key]}, s.policyADDHistory[key]...) {
			if b != nil && sameOriginalADD(b, binding) && b.CaptureGeneration > binding.CaptureGeneration {
				binding = b
			}
		}
	}
	s.endpointCacheMutex.RUnlock()
	switch {
	case binding == nil:
		return nil, "no acknowledged ADD is retained by this agent execution"
	case !bytes.Equal(binding.ProxyEpoch, epoch):
		return nil, "its ADD belongs to an earlier ztunnel execution"
	}
	return proto.Clone(binding).(*pb.WorkloadBinding), ""
}

func (s *Server) skipSnapshotEndpoint(ep *endpoint.Endpoint, reason string, err error) {
	s.logger.Info("Leaving Required endpoint out of the initial snapshot until it is re-admitted",
		logStage, "zds-initial-snapshot",
		logfields.EndpointID, ep.GetID16(),
		logfields.K8sUID, ep.K8sUID,
		logfields.Reason, reason,
		logfields.Error, err)
}

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
		if !s.strictSnapshotStillDesired(ep) {
			continue
		}
		// A strict endpoint's ADD can be replayed only into the ztunnel
		// execution that acknowledged it; decide that before touching its
		// sandbox. Any per-endpoint failure leaves that endpoint out instead of
		// failing the snapshot: a failed snapshot fails every reconnect, while
		// admission needs this connection to re-capture the endpoint. A left-out
		// endpoint stays quarantined until admission sends a fresh ADD.
		var binding *pb.WorkloadBinding
		if s.strictDeletedEndpointCleanup {
			var reason string
			binding, reason = s.snapshotBinding(ep, zc.proxyEpoch)
			if reason != "" {
				s.skipSnapshotEndpoint(ep, reason, nil)
				continue
			}
		}
		ns, err := netns.OpenPinned(ep.GetContainerNetnsPath())
		if err != nil {
			if !s.strictSnapshotStillDesired(ep) {
				continue
			}
			if s.strictDeletedEndpointCleanup {
				s.skipSnapshotEndpoint(ep, "its network namespace cannot be opened", err)
				continue
			}
			s.logger.Error("failed to open netns file",
				logfields.EndpointID, ep.GetID16(),
				logfields.Error, err,
			)
			return err
		}
		if !s.strictSnapshotStillDesired(ep) {
			ns.Close()
			continue
		}

		if err = ns.Do(func() error {
			return iptables.CreateInPodRules(s.logger, option.Config.EnableIPv4, option.Config.EnableIPv6, s.directResolverDNS)
		}); err != nil {
			ns.Close()
			if s.strictDeletedEndpointCleanup {
				s.skipSnapshotEndpoint(ep, "its capture rules cannot be installed", err)
				continue
			}
			return fmt.Errorf("unable to setup iptable rules for ztunnel inpod mode: %w", err)
		}
		ns.Close()
		if !s.strictSnapshotStillDesired(ep) {
			continue
		}

		workload, err := endpointToWorkload(ep)
		if err != nil {
			if s.strictDeletedEndpointCleanup {
				s.skipSnapshotEndpoint(ep, "it cannot be converted to a workload", err)
				continue
			}
			s.logger.Error("failed to convert endpoint to workload",
				logfields.EndpointID, ep.GetID16(),
				logfields.Error, err,
			)
			return err
		}
		workload.Binding = binding

		req := &pb.WorkloadRequest{
			Payload: &pb.WorkloadRequest_Add{
				Add: workload,
			},
		}

		if !s.strictSnapshotStillDesired(ep) {
			continue
		}
		if err := zc.sendAndWaitForAck(req, ep.GetContainerNetnsPath()); err != nil {
			if errors.Is(err, errZDSRequestRejected) {
				s.skipSnapshotEndpoint(ep, "its request was rejected before transmission", err)
				continue
			}
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

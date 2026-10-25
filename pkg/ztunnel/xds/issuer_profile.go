// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/hive/cell"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	typedcore "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/issuerprofile"
	"github.com/cilium/cilium/pkg/ztunnel/pb/trust"
)

const xdsTypeURLIssuerProfile = "type.googleapis.com/cilium.ztunnel.v1.IssuerProfile"
const maxProbePins = 16 * 1024
const issuerProfileLogComponent = "component"
const issuerProfileLogStage = "stage"

type IssuerProfileProbeConfig struct {
	IssuerProfileProbePins string `mapstructure:"ztunnel-issuer-profile-probe-pins"`
}

func (IssuerProfileProbeConfig) Flags(f *pflag.FlagSet) {
	f.String("ztunnel-issuer-profile-probe-pins", "", "Experimental transport-only issuer-profile probe pins file; no trust activation")
}

// Pins come from an administrator-controlled local mount, never the profile.
// Strings preserve exact uint64 values across JSON implementations.
type issuerProfileProbePins struct {
	Cluster                    string   `json:"cluster"`
	Node                       string   `json:"node"`
	SourceNamespace            string   `json:"sourceNamespace"`
	SourceName                 string   `json:"sourceName"`
	SourceUID                  string   `json:"sourceUID"`
	OutputNamespace            string   `json:"outputNamespace"`
	OutputName                 string   `json:"outputName"`
	OutputUID                  string   `json:"outputUID"`
	RootPins                   []string `json:"rootPins"`
	MinimumGeneration          string   `json:"minimumGeneration"`
	MinimumSequence            string   `json:"minimumSequence"`
	ApprovalDigestAtMinimum    string   `json:"approvalDigestAtMinimum"`
	PublicationDigestAtMinimum string   `json:"publicationDigestAtMinimum"`
}

func canonicalPositive(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != s {
		return 0, errors.New("positive canonical checkpoint required")
	}
	return n, nil
}
func decodeIssuerProfileProbePins(body []byte) (issuerprofile.Install, error) {
	var pins issuerProfileProbePins
	if len(body) == 0 || len(body) > maxProbePins {
		return issuerprofile.Install{}, errors.New("bounded probe pins required")
	}
	allowed := map[string]bool{}
	for _, key := range []string{"cluster", "node", "sourceNamespace", "sourceName", "sourceUID", "outputNamespace", "outputName", "outputUID", "rootPins", "minimumGeneration", "minimumSequence", "approvalDigestAtMinimum", "publicationDigestAtMinimum"} {
		allowed[key] = true
	}
	// Decode each top-level value once, rejecting duplicate and aliased keys.
	d := json.NewDecoder(bytes.NewReader(body))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return issuerprofile.Install{}, errors.New("probe pins object required")
	}
	values := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return issuerprofile.Install{}, err
		}
		key, ok := token.(string)
		if !ok || !allowed[key] || values[key] != nil {
			return issuerprofile.Install{}, errors.New("unknown, duplicate or aliased probe pin")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return issuerprofile.Install{}, err
		}
		values[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return issuerprofile.Install{}, errors.New("invalid probe pins object")
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return issuerprofile.Install{}, errors.New("one probe pins object required")
	}
	canonical, err := json.Marshal(values)
	if err != nil {
		return issuerprofile.Install{}, err
	}
	if err = json.Unmarshal(canonical, &pins); err != nil {
		return issuerprofile.Install{}, err
	}
	generation, err := canonicalPositive(pins.MinimumGeneration)
	if err != nil {
		return issuerprofile.Install{}, err
	}
	sequence, err := canonicalPositive(pins.MinimumSequence)
	if err != nil {
		return issuerprofile.Install{}, err
	}
	return issuerprofile.Install{Expected: issuerprofile.Expected{Cluster: pins.Cluster, SourceNamespace: pins.SourceNamespace, SourceName: pins.SourceName, SourceUID: pins.SourceUID, OutputUID: pins.OutputUID, MinimumGeneration: generation, MinimumSequence: sequence, RootPins: pins.RootPins}, OutputNamespace: pins.OutputNamespace, OutputName: pins.OutputName, Node: pins.Node, ApprovalDigestAtMinimum: pins.ApprovalDigestAtMinimum, PublicationDigestAtMinimum: pins.PublicationDigestAtMinimum}, nil
}

func readIssuerProfileProbePins(path string) (issuerprofile.Install, error) {
	if !filepath.IsAbs(path) {
		return issuerprofile.Install{}, errors.New("absolute probe pins path required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return issuerprofile.Install{}, fmt.Errorf("open probe pins: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return issuerprofile.Install{}, err
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return issuerprofile.Install{}, err
	}
	if stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() > maxProbePins {
		return issuerprofile.Install{}, errors.New("probe pins must be bounded root-owned regular non-writable-by-others file")
	}
	body, err := io.ReadAll(io.LimitReader(f, maxProbePins+1))
	if err != nil {
		return issuerprofile.Install{}, err
	}
	return decodeIssuerProfileProbePins(body)
}

type issuerProfileSourceParams struct {
	cell.In
	Pins    IssuerProfileProbeConfig
	Config  config.Config
	Cluster cmtypes.ClusterInfo
	Client  client.Clientset
	Log     *slog.Logger
}

type issuerProfileSource struct {
	mu     lock.Mutex
	core   typedcore.CoreV1Interface
	pins   issuerprofile.Install
	clock  func() time.Time
	log    *slog.Logger
	timing *issuerProfileTiming
}

func newIssuerProfileSource(p issuerProfileSourceParams) (*issuerProfileSource, error) {
	if p.Pins.IssuerProfileProbePins == "" {
		return nil, nil
	}
	if !p.Config.EnableZTunnel || !p.Config.RequireMTLS || p.Config.CAType != config.CATypeSpire || p.Client == nil || !p.Client.IsEnabled() {
		return nil, errors.New("issuer-profile transport probe requires Kubernetes, ztunnel strict mTLS and SPIRE backend")
	}
	pins, err := readIssuerProfileProbePins(p.Pins.IssuerProfileProbePins)
	if err != nil {
		return nil, err
	}
	if err = issuerprofile.ValidateInstall(pins); err != nil {
		return nil, err
	}
	if pins.Cluster != p.Cluster.Name || pins.Node != nodeTypes.GetName() {
		return nil, errors.New("probe pins differ from local Cilium cluster/node")
	}
	// No successful startup read is cached as continuing authority. Every stream
	// publication obtains current API data again and fails closed on any error.
	core, err := verifiedIssuerProfileCore(p.Client.RestConfig())
	if err != nil {
		return nil, err
	}
	s := &issuerProfileSource{core: core, pins: pins, clock: time.Now, log: p.Log}
	return s, nil
}

// Build a dedicated native client. The interface type does not attest the
// configured transport. Never reuse an unchecked injected RoundTripper.
func verifiedIssuerProfileCore(input *rest.Config) (typedcore.CoreV1Interface, error) {
	if input == nil {
		return nil, errors.New("explicit Kubernetes REST configuration required")
	}
	rc := rest.CopyConfig(input)
	endpoint, err := url.Parse(rc.Host)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || rc.Insecure || len(rc.CAData) == 0 && rc.CAFile == "" {
		return nil, errors.New("issuer-profile requires HTTPS Kubernetes API with explicit verified CA and hostname")
	}
	if rc.Transport != nil || rc.WrapTransport != nil || rc.Dial != nil || rc.Proxy != nil || rc.ExecProvider != nil || rc.AuthProvider != nil {
		return nil, errors.New("custom Kubernetes transport, proxy, dialer or credential plugin unsupported by issuer-profile probe")
	}
	// A configured TLS ServerName is an independent administrator pin. Otherwise
	// net/http checks the exact URL host. The profile cannot change either value.
	tlsConfig, err := rest.TLSConfigFor(rc)
	if err != nil {
		return nil, fmt.Errorf("construct verified Kubernetes TLS: %w", err)
	}
	if tlsConfig == nil || tlsConfig.InsecureSkipVerify || tlsConfig.RootCAs == nil {
		return nil, errors.New("missing verified Kubernetes TLS roots")
	}
	rc.Timeout = 4 * time.Second
	rc.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	httpClient, err := rest.HTTPClientFor(rc)
	if err != nil {
		return nil, err
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return typedcore.NewForConfigAndClient(rc, httpClient)
}

func issuerProfileName(node string) string { return "cilium/issuer-profile/" + node }

type issuerProfileSnapshot struct {
	body           []byte
	version, state string
	until          time.Time
}

func (s *issuerProfileSource) snapshot(ctx context.Context) (issuerProfileSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, err := issuerprofile.ReadAndProject(ctx, s.core, s.pins, s.clock)
	if err != nil {
		return issuerProfileSnapshot{}, err
	}
	var wire issuerprofile.DERProfile
	if err = json.Unmarshal(body, &wire); err != nil {
		return issuerProfileSnapshot{}, err
	}
	sequence, err := canonicalPositive(wire.Sequence)
	if err != nil {
		return issuerProfileSnapshot{}, err
	}
	generation, err := canonicalPositive(wire.Generation)
	if err != nil {
		return issuerProfileSnapshot{}, err
	}
	until, err := strconv.ParseInt(wire.ValidUntilUnix, 10, 64)
	if err != nil {
		return issuerProfileSnapshot{}, err
	}
	// These process-local floors prevent within-process rollback. They are NOT
	// durable trust state and cannot permit the proxy to ACK or admit traffic.
	s.pins.MinimumSequence = sequence
	s.pins.PublicationDigestAtMinimum = wire.PublicationDigest
	s.pins.MinimumGeneration = generation
	s.pins.ApprovalDigestAtMinimum = wire.ApprovalDigest
	return issuerProfileSnapshot{body: body, version: wire.Sequence + "/" + wire.PublicationDigest, state: wire.State, until: time.Unix(until, 0)}, nil
}
func (s *issuerProfileSource) checkNode(node *corev3.Node) error {
	if node == nil || node.Id == "" || node.Metadata == nil || node.Metadata.Fields["NODE_NAME"].GetStringValue() != s.pins.Node {
		return errors.New("issuer-profile subscription lacks exact local node routing")
	}
	return nil
}

type issuerProfileTiming struct{ poll, ack time.Duration }

func (s *issuerProfileSource) protocolTiming() issuerProfileTiming {
	if s.timing != nil {
		return *s.timing
	}
	return issuerProfileTiming{poll: 2 * time.Second, ack: 5 * time.Second}
}

type issuerProfilePending struct {
	nonce, version string
	until          time.Time
}

// runIssuerProfileStream runs on the same serialized authenticated ADS stream.
// One response can be pending. An ACK records transport receipt only. A NACK,
// replay, API failure, expiry or missing ACK terminates this session.
func (s *issuerProfileSource) run(ctx context.Context, requests <-chan *v3.DeltaDiscoveryRequest, stream v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer, timing issuerProfileTiming) (retErr error) {
	started := time.Now()
	attempt := 0
	stage := "issuer-profile-subscription"
	defer func() {
		if retErr != nil && !errors.Is(retErr, context.Canceled) && s.log != nil {
			s.log.Warn("Issuer-profile transport session rejected",
				issuerProfileLogComponent, "ztunnel-xds",
				issuerProfileLogStage, stage,
				logfields.Attempt, attempt,
				logfields.ElapsedDuration, time.Since(started),
				logfields.Error, retErr,
			)
		}
	}()
	ticker := time.NewTicker(timing.poll)
	defer ticker.Stop()
	var subscribed bool
	var pending *issuerProfilePending
	var current issuerProfileSnapshot
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}
	var deadline <-chan time.Time
	resetDeadline := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		deadline = nil
		var d time.Duration
		if pending != nil {
			d = time.Until(pending.until)
		} else if current.state == "published" {
			d = current.until.Sub(s.clock())
		} else {
			return
		}
		if d < 0 {
			d = 0
		}
		timer.Reset(d)
		deadline = timer.C
	}
	publish := func() error {
		attempt++
		stage = "issuer-profile-api-poll"
		next, err := s.snapshot(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			// A double-GET coherence failure closes this session immediately.
			// It is not permission to reuse the last good profile. Classify it
			// as Unavailable so the native client backs off instead of treating
			// a generic gRPC Unknown as a normal 10ms reconnect/GOAWAY.
			if s.log != nil {
				s.log.Warn("Issuer-profile API observation unavailable",
					issuerProfileLogComponent, "ztunnel-xds",
					issuerProfileLogStage, stage,
					logfields.Attempt, attempt,
					logfields.ElapsedDuration, time.Since(started),
					logfields.Error, err,
				)
			}
			return grpcstatus.Error(codes.Unavailable, "issuer-profile current API observation unavailable; fresh session required")
		}
		if next.version == current.version {
			return nil
		}
		if pending != nil {
			return errors.New("issuer-profile changed before matching ACK; resync required")
		}
		message, err := anypb.New(&trust.IssuerProfile{TransportVersion: 1, StrictDerProfileJson: next.body})
		if err != nil {
			return err
		}
		nonce := rand.Text()
		response := &v3.DeltaDiscoveryResponse{TypeUrl: xdsTypeURLIssuerProfile, SystemVersionInfo: next.version, Nonce: nonce, Resources: []*v3.Resource{{Name: issuerProfileName(s.pins.Node), Version: next.version, Resource: message}}}
		if err = stream.SendMsg(response); err != nil {
			return err
		}
		pending = &issuerProfilePending{nonce: nonce, version: next.version, until: time.Now().Add(timing.ack)}
		current = next
		if next.state == "published" {
			remaining := next.until.Sub(s.clock())
			if remaining < timing.ack {
				pending.until = time.Now().Add(remaining)
			}
		}
		stage = "issuer-profile-await-ack"
		resetDeadline()
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			if pending != nil {
				return fmt.Errorf("issuer-profile matching ACK deadline exceeded for version %s", pending.version)
			}
			return errors.New("issuer-profile lease expired")
		case <-ticker.C:
			if subscribed {
				if err := publish(); err != nil {
					return err
				}
				resetDeadline()
			}
		case req, ok := <-requests:
			if !ok || req == nil {
				return errors.New("issuer-profile request channel closed")
			}
			if req.TypeUrl != xdsTypeURLIssuerProfile || len(req.ResourceNamesSubscribe) != 0 || len(req.ResourceNamesUnsubscribe) != 0 {
				return errors.New("issuer-profile requires a full typed subscription")
			}
			if req.ResponseNonce != "" {
				if pending == nil || !time.Now().Before(pending.until) || req.ResponseNonce != pending.nonce {
					return errors.New("issuer-profile unexpected or replayed nonce")
				}
				if req.ErrorDetail != nil {
					return fmt.Errorf("issuer-profile version %s rejected by subscriber", pending.version)
				}
				if s.log != nil {
					s.log.Info("Issuer-profile transport response acknowledged; activation remains unavailable",
						logfields.Resource, xdsTypeURLIssuerProfile,
						issuerProfileLogStage, "issuer-profile-transport-ack",
						logfields.Version, pending.version,
					)
				}
				pending = nil
				resetDeadline()
				continue
			}
			if subscribed || req.ErrorDetail != nil {
				return errors.New("duplicate or malformed issuer-profile subscription")
			}
			if err := s.checkNode(req.Node); err != nil {
				return err
			}
			for name := range req.InitialResourceVersions {
				if name != issuerProfileName(s.pins.Node) {
					return errors.New("foreign initial issuer-profile resource")
				}
			}
			subscribed = true
			if err := publish(); err != nil {
				return err
			}
		}
	}
}

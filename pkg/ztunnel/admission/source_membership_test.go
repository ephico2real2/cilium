// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hive"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	k8stestutils "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/option"
	testendpointmanager "github.com/cilium/cilium/pkg/testutils/endpointmanager"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

type recordingHealth struct {
	mu       sync.Mutex
	degraded []string
	ok       []string
}

func (h *recordingHealth) OK(status string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ok = append(h.ok, status)
}
func (h *recordingHealth) Stopped(string) {}
func (h *recordingHealth) Degraded(reason string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.degraded = append(h.degraded, reason+": "+err.Error())
}
func (h *recordingHealth) NewScope(string) cell.Health { return h }
func (h *recordingHealth) Close()                      {}

type closeCountingBackend struct {
	kvstore.BackendOperations
	closed *int
}

func (b closeCountingBackend) Close() { *b.closed++ }

func membershipPublisherFixture(t *testing.T) (*gate, membership.SourcePublisherConfig) {
	t.Helper()
	g := &gate{logger: hivetest.Logger(t), membership: membership.NewRegistry(1),
		membershipRetryMin: time.Millisecond, membershipRetryMax: 2 * time.Millisecond}
	cfg := membership.SourcePublisherConfig{
		ClusterInfo: cmtypes.ClusterInfo{ID: 1, Name: "cmtc-a", MaxConnectedClusters: 255}, NodeName: "cmtc-a-worker"}
	return g, cfg
}

func TestDedicatedSourcePublisherRetriesConnectionsWithoutStoppingTheAgent(t *testing.T) {
	g, cfg := membershipPublisherFixture(t)
	health := &recordingHealth{}
	var attempts, closed int
	open := func(context.Context) (kvstore.BackendOperations, error) {
		attempts++
		if attempts < 3 {
			return nil, errors.New("connection refused")
		}
		// The in-memory backend has no lock-fenced short leases: the
		// publisher must refuse it permanently instead of publishing.
		return closeCountingBackend{BackendOperations: kvstore.NewInMemoryClient(statedb.New(), "cmtc-a"), closed: &closed}, nil
	}
	err := g.dedicatedSourcePublisher(open, testendpointmanager.NewMockEndpointManager(), cfg, "/etc/membership/etcd.yaml")(t.Context(), health)
	require.ErrorContains(t, err, "lock-fenced short")
	require.Equal(t, 3, attempts, "connection failures were not retried")
	require.Equal(t, 1, closed, "refused backend connection was not closed")
	require.Len(t, health.degraded, 2)
	require.Contains(t, health.degraded[0], "connection refused")
	require.Empty(t, health.ok, "an unusable connection was reported healthy")
}

func TestDedicatedSourcePublisherStopsCleanlyWhileRetrying(t *testing.T) {
	g, cfg := membershipPublisherFixture(t)
	g.membershipRetryMin, g.membershipRetryMax = time.Hour, time.Hour
	ctx, cancel := context.WithCancel(t.Context())
	var attempts int
	open := func(context.Context) (kvstore.BackendOperations, error) {
		attempts++
		cancel()
		return nil, errors.New("connection refused")
	}
	done := make(chan error, 1)
	go func() {
		done <- g.dedicatedSourcePublisher(open, testendpointmanager.NewMockEndpointManager(), cfg, "/etc/membership/etcd.yaml")(ctx, &recordingHealth{})
	}()
	select {
	case err := <-done:
		require.NoError(t, err, "agent shutdown during a connection retry is not an error")
	case <-time.After(10 * time.Second):
		t.Fatal("publisher did not stop while waiting to retry")
	}
	require.Equal(t, 1, attempts)
}

func TestRemoteMembershipSelectsTheDedicatedConnection(t *testing.T) {
	for _, tc := range []struct {
		name, path, err string
	}{
		{name: "dedicated", path: "/var/lib/cilium/ztunnel-membership/etcd.yaml"},
		{name: "none", err: "requires a dedicated membership etcd connection or an enabled KVStore"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			_, cs := k8stestutils.NewFakeClientset(logger)
			h := hive.New(
				cell.Provide(func() config.Config {
					cfg := config.DefaultConfig
					cfg.EnableZTunnel, cfg.RequireMTLS = true, true
					cfg.EnableRemoteWorkloadMembership, cfg.RemoteOriginConfigDirectory = true, "/var/lib/cilium/ztunnel-origin"
					cfg.SourceMembershipEtcdConfig = tc.path
					return cfg
				}),
				cell.Provide(func() k8sclient.Clientset { return cs }),
				cell.Provide(func() cmtypes.ClusterInfo {
					return cmtypes.ClusterInfo{ID: 1, Name: "cmtc-a", MaxConnectedClusters: 255}
				}),
				cell.Provide(func() *option.DaemonConfig {
					return &option.DaemonConfig{K8sNamespace: "kube-system", StateDir: t.TempDir()}
				}),
				cell.Provide(func() endpointmanager.EndpointManager { return testendpointmanager.NewMockEndpointManager() }),
				zds.Cell,
				Cell,
				cell.Invoke(func(in gateGroupInput) {}),
			)
			// Populate-only: no ZDS socket and no etcd connection is opened.
			err := h.Populate(logger)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
		})
	}
}

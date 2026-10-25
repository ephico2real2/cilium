// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/time"
)

type registeredWatchFunctions map[string]store.WSMFunc

func (m registeredWatchFunctions) Register(prefix string, fn store.WSMFunc) { m[prefix] = fn }
func (registeredWatchFunctions) Run(context.Context)                        {}

func newOriginObserver(t *testing.T, logger *slog.Logger) (*clusterMeshObserver, *pairedWatchFactory) {
	factory := &pairedWatchFactory{started: make(chan string, 1)}
	return &clusterMeshObserver{
		logger: logger, cluster: "cluster-beta",
		storeFactory: factory,
		clusterInfo:  cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255},
		sink:         &recordingSink{}, enableZTunnel: true, enableSourceMembership: true,
		originConfigDirectory: t.TempDir(), originClientCommonName: "ztunnel-origin-reader",
		remoteClientFactory: common.RemoteClientFactoryFn(func(context.Context, *slog.Logger, string, kvstore.ExtraOptions) (kvstore.BackendOperations, chan error) {
			return nil, nil
		}),
	}, factory
}

func originPeerConfig(id uint32, cached bool) cmtypes.CiliumClusterConfig {
	return cmtypes.CiliumClusterConfig{
		ID: id,
		Capabilities: cmtypes.CiliumClusterConfigCapabilities{
			Cached: cached, WorkloadIdentityV1: true, ZtunnelMembershipV1: true,
		},
	}
}

var cachedIPIdentitiesPath = kvstore.StateToCachePrefix(ipcache.IPIdentitiesPath)

func TestClusterMeshObserverUsesPinnedOriginAlongsideCachedRouting(t *testing.T) {
	observer, factory := newOriginObserver(t, slog.New(slog.DiscardHandler))
	manager := registeredWatchFunctions{}
	observer.Register(manager, nil, originPeerConfig(17, true))
	// Through KVStoreMesh the only IP identity sync canary is the cache one.
	if _, ok := manager[cachedIPIdentitiesPath]; !ok || len(manager) != 1 {
		t.Fatalf("observer must wait for the KVStoreMesh IP identity canary %q, registered %v", cachedIPIdentitiesPath, manager)
	}
	if !observer.Status().Enabled {
		t.Fatal("observer should report that its direct-origin supervisor is registered")
	}
	if observer.originSession == nil || observer.originSession.Factory != factory || observer.joiner == nil {
		t.Fatal("observer did not retain its dedicated direct-origin session and source-join gate")
	}
	if observer.Status().Synced {
		t.Fatal("observer reported synchronization before either source watch completed")
	}
}

func TestClusterMeshObserverIsDisabledWithoutExplicitOptIn(t *testing.T) {
	manager := registeredWatchFunctions{}
	observer := &clusterMeshObserver{
		logger: slog.New(slog.DiscardHandler), cluster: "cluster-beta",
		storeFactory: &pairedWatchFactory{started: make(chan string, 1)},
		sink:         &recordingSink{}, enableZTunnel: true,
	}
	observer.Register(manager, nil, cmtypes.CiliumClusterConfig{ID: 17})
	if len(manager) != 0 {
		t.Fatalf("disabled-by-default observer registered %d source watches", len(manager))
	}
	if observer.Status().Enabled {
		t.Fatal("observer reported enabled without the explicit membership opt-in")
	}
}

func TestClusterMeshObserverWaitsForTheOriginCanaryWithoutKVStoreMesh(t *testing.T) {
	observer, _ := newOriginObserver(t, slog.New(slog.DiscardHandler))
	manager := registeredWatchFunctions{}
	observer.Register(manager, nil, originPeerConfig(17, false))
	if _, ok := manager[ipcache.IPIdentitiesPath]; !ok || len(manager) != 1 {
		t.Fatalf("observer must wait for the origin IP identity canary, registered %v", manager)
	}
}

// Every ClusterMesh connection calls Register with a new manager, after the
// previous connection's functions have stopped. Each one must start a
// supervisor; the joiner and session are kept while the ClusterID is unchanged.
func TestClusterMeshObserverRegistersItsSupervisorOnEveryConnection(t *testing.T) {
	observer, _ := newOriginObserver(t, slog.New(slog.DiscardHandler))
	first := registeredWatchFunctions{}
	observer.Register(first, nil, originPeerConfig(17, true))
	joiner, session := observer.joiner, observer.originSession

	observer.Revoke()
	reconnect := registeredWatchFunctions{}
	observer.Register(reconnect, nil, originPeerConfig(17, true))
	if _, ok := reconnect[cachedIPIdentitiesPath]; !ok {
		t.Fatal("a reconnected peer got no direct-origin supervisor")
	}
	if !observer.Status().Enabled {
		t.Fatal("observer stayed disabled after its peer reconnected")
	}
	if observer.joiner != joiner || observer.originSession != session {
		t.Fatal("reconnect replaced the pinned session and source-join gate")
	}

	changed := registeredWatchFunctions{}
	observer.Register(changed, nil, originPeerConfig(18, true))
	if len(changed) != 0 || observer.Status().Enabled {
		t.Fatal("a peer whose ClusterID changed must not be observed by the same observer")
	}
}

// canaryBackend lists the given sync canary keys, then idles until canceled.
type canaryBackend struct{ keys []string }

func (b canaryBackend) ListAndWatch(ctx context.Context, _ string, _ ...kvstore.ListAndWatchOption) kvstore.EventChan {
	ch := make(chan kvstore.KeyValueEvent, len(b.keys)+1)
	for _, key := range b.keys {
		ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: key}
	}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeListDone}
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch
}

type messageRecorder struct{ messages chan string }

func (r messageRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r messageRecorder) Handle(_ context.Context, record slog.Record) error {
	select {
	case r.messages <- record.Message:
	default:
	}
	return nil
}
func (r messageRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r messageRecorder) WithGroup(string) slog.Handler      { return r }

// The deployed shape: a KVStoreMesh peer with sync canaries. The manager
// receives only the cache canary; both the native ipcache watcher and the
// direct-origin supervisor wait for it, and both must start.
func TestClusterMeshObserverStartsBesideTheIPCacheWatcherOnTheKVStoreMeshCanary(t *testing.T) {
	recorder := messageRecorder{messages: make(chan string, 64)}
	observer, _ := newOriginObserver(t, slog.New(recorder))
	factory := store.NewFactory(hivetest.Logger(t), store.MetricsProvider())
	backend := canaryBackend{keys: []string{kvstore.JoinKey(kvstore.SyncedPrefix, "cluster-beta", cachedIPIdentitiesPath)}}
	mgr := factory.NewWatchStoreManager(backend, "cluster-beta")

	ipcacheStarted := make(chan struct{})
	mgr.Register(cachedIPIdentitiesPath, func(ctx context.Context) {
		close(ipcacheStarted)
		<-ctx.Done()
	})
	observer.Register(mgr, nil, originPeerConfig(17, true))

	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() {
		mgr.Run(ctx)
		close(stopped)
	}()
	defer func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Error("watch store manager did not stop")
		}
	}()

	deadline := time.After(5 * time.Second)
	for supervisorStarted := false; !supervisorStarted; {
		select {
		case message := <-recorder.messages:
			supervisorStarted = message == "Direct-origin membership supervisor started"
		case <-deadline:
			t.Fatal("direct-origin supervisor never started on the KVStoreMesh IP identity canary")
		}
	}
	select {
	case <-ipcacheStarted:
	case <-deadline:
		t.Fatal("the native ipcache watcher no longer starts beside the supervisor")
	}
}

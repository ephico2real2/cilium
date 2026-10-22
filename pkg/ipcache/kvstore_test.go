// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/kvstore"
	storepkg "github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

type event struct {
	ev, ip  string
	source  source.Source
	k8sMeta *K8sMetadata
}

type fakeIPCache struct{ events chan event }
type fakeBackend struct{ prefix string }

func NewEvent(ev, ip string, source source.Source) event { return event{ev, ip, source, nil} }
func NewFakeIPCache() *fakeIPCache                       { return &fakeIPCache{events: make(chan event)} }
func NewFakeBackend() *fakeBackend                       { return &fakeBackend{} }

func (m *fakeIPCache) Upsert(ip string, _ net.IP, _ uint8, k8sMeta *K8sMetadata, id Identity) (bool, error) {
	m.events <- event{ev: "upsert", ip: ip, source: id.Source, k8sMeta: k8sMeta}
	return true, nil
}

func (m *fakeIPCache) Delete(ip string, source source.Source) (namedPortsChanged bool) {
	m.events <- NewEvent("delete", ip, source)
	return true
}

func (fb *fakeBackend) ListAndWatch(ctx context.Context, prefix string) kvstore.EventChan {
	var pair identity.IPIdentityPair
	ch := make(chan kvstore.KeyValueEvent, 10)

	marshal := func(pair identity.IPIdentityPair) []byte {
		out, _ := pair.Marshal()
		return out
	}

	id := func(clusterID, localID uint32) identity.NumericIdentity {
		return identity.NumericIdentity(clusterID<<identity.GetClusterIDShift() | localID)
	}

	fb.prefix = prefix

	pair = identity.IPIdentityPair{IP: net.ParseIP("10.0.0.1"), ID: id(10, 200)}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: pair.GetKeyName(), Value: marshal(pair)}
	pair = identity.IPIdentityPair{IP: net.ParseIP("10.0.1.0"), Mask: net.CIDRMask(24, 32), ID: id(10, 201)}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: pair.GetKeyName(), Value: marshal(pair)}
	pair = identity.IPIdentityPair{IP: net.ParseIP("10.0.1.0"), Mask: net.CIDRMask(24, 32)}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeListDone}

	pair = identity.IPIdentityPair{IP: net.ParseIP("10.0.1.0"), Mask: net.CIDRMask(24, 32)}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeDelete, Key: pair.GetKeyName()}
	pair = identity.IPIdentityPair{IP: net.ParseIP("10.0.0.1")}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeDelete, Key: pair.GetKeyName()}

	pair = identity.IPIdentityPair{IP: net.ParseIP("f00d::a00:0:0:c164"), ID: id(10, 202)}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: pair.GetKeyName(), Value: marshal(pair)}

	pair = identity.IPIdentityPair{IP: net.ParseIP("10.0.0.2"), ID: id(11, 203)}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: pair.GetKeyName(), Value: marshal(pair)}

	close(ch)
	return ch
}

func eventually(in <-chan event) event {
	select {
	case kv := <-in:
		return kv
	// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
	case <-time.After(5 * time.Second):
		return NewEvent("error", "timed out waiting for KV", source.Unspec)
	}
}

func TestIPIdentityWatcher(t *testing.T) {
	logger := hivetest.Logger(t)
	const src = source.Source("foo")

	var synced bool
	st := storepkg.NewFactory(logger, storepkg.MetricsProvider())
	runnable := func(body func(t *testing.T, ipcache *fakeIPCache), prefix string, opts ...IWOpt) func(t *testing.T) {
		return func(t *testing.T) {
			synced = false
			ipcache := NewFakeIPCache()
			backend := NewFakeBackend()
			watcher := NewIPIdentityWatcher(logger, "foo", ipcache, st, src, storepkg.RWSWithOnSyncCallback(func(ctx context.Context) { synced = true }))

			var wg sync.WaitGroup
			ctx, cancel := context.WithCancel(context.Background())
			defer func() {
				cancel()
				// Read possible leftover events, to fail fast.
				for event := range ipcache.events {
					assert.Failf(t, "unexpected event not yet read", "event: %v", event)
				}
				wg.Wait()
			}()

			wg.Go(func() {
				watcher.Watch(ctx, backend, opts...)
				close(ipcache.events)
			})

			body(t, ipcache)

			// Assert that the watched prefix is correct.
			require.Equal(t, prefix, backend.prefix)
		}
	}

	t.Run("without cluster ID", runnable(func(t *testing.T, ipcache *fakeIPCache) {
		require.Equal(t, NewEvent("upsert", "10.0.0.1", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "10.0.1.0/24", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.1.0/24", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.0.1", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "f00d::a00:0:0:c164", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "10.0.0.2", src), eventually(ipcache.events))
		require.True(t, synced, "The on-sync callback should have been executed")
	}, "cilium/state/ip/v1/default/"))

	t.Run("with cluster ID", runnable(func(t *testing.T, ipcache *fakeIPCache) {
		require.Equal(t, NewEvent("upsert", "10.0.0.1@10", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "10.0.1.0/24@10", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.1.0/24@10", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.0.1@10", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "f00d::a00:0:0:c164@10", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "10.0.0.2@10", src), eventually(ipcache.events))
		require.True(t, synced, "The on-sync callback should have been executed")
	}, "cilium/state/ip/v1/default/", WithClusterID(10)))

	t.Run("with cached prefix", runnable(func(t *testing.T, ipcache *fakeIPCache) {
		require.Equal(t, NewEvent("upsert", "10.0.0.1", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "10.0.1.0/24", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.1.0/24", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.0.1", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "f00d::a00:0:0:c164", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "10.0.0.2", src), eventually(ipcache.events))
		require.True(t, synced, "The on-sync callback should have been executed")
	}, "cilium/cache/ip/v1/foo/", WithCachedPrefix(true)))

	t.Run("with identity validation", runnable(func(t *testing.T, ipcache *fakeIPCache) {
		require.Equal(t, NewEvent("upsert", "10.0.0.1", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "10.0.1.0/24", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.1.0/24", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.0.1", src), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "f00d::a00:0:0:c164", src), eventually(ipcache.events))
		require.True(t, synced, "The on-sync callback should have been executed")
	}, "cilium/state/ip/v1/default/", WithIdentityValidator(10)))
}

func TestIdentityValidator(t *testing.T) {
	const (
		cid   = 5
		minID = cid << 16
		maxID = minID + 65535
	)

	var opts iwOpts
	WithIdentityValidator(cid)(&opts)

	require.Len(t, opts.validators, 1, "The validator should have been configured")
	validator := opts.validators[0]

	// Identities matching the cluster ID should pass validation
	for _, id := range []identity.NumericIdentity{minID, minID + 1, maxID - 1, maxID} {
		assert.NoError(t, validator(&identity.IPIdentityPair{ID: id}), "ID %d should have passed validation", id)
	}

	// Reserved identities should pass validation
	for _, id := range []identity.NumericIdentity{
		identity.ReservedIdentityHealth,
		identity.ReservedIdentityIngress,
		identity.ReservedCoreDNS,
		identity.UserReservedNumericIdentity,
		identity.MinimalNumericIdentity - 1,
	} {
		assert.NoError(t, validator(&identity.IPIdentityPair{ID: id}), "ID %d should have passed validation", id)
	}

	// Identities not matching the cluster ID should fail validation
	for _, id := range []identity.NumericIdentity{identity.MinimalNumericIdentity, minID - 1, maxID + 1} {
		assert.Error(t, validator(&identity.IPIdentityPair{ID: id}), "ID %d should have failed validation", id)
	}
}

func TestIPIdentityWatcherNamedPorts(t *testing.T) {
	const src = source.Source("foo")

	ipcache := &fakeIPCache{events: make(chan event, 1)}
	watcher := &IPIdentityWatcher{
		log:     hivetest.Logger(t),
		ipcache: ipcache,
		source:  src,
	}

	watcher.OnUpdate(&identity.IPIdentityPair{
		IP:           net.ParseIP("10.0.0.1"),
		ID:           identity.NumericIdentity(1000),
		K8sNamespace: "test-ns",
		K8sPodName:   "echo-1",
		NamedPorts: []identity.NamedPort{
			{Name: "http", Port: 8080, Protocol: "TCP"},
			{Name: "dns", Port: 53, Protocol: "UDP"},
		},
	})

	event := eventually(ipcache.events)
	require.Equal(t, "upsert", event.ev)
	require.Equal(t, "10.0.0.1", event.ip)
	require.Equal(t, src, event.source)
	require.NotNil(t, event.k8sMeta)
	require.Equal(t, "test-ns", event.k8sMeta.Namespace)
	require.Equal(t, "echo-1", event.k8sMeta.PodName)
	require.Equal(t, types.NamedPortMap{
		"http": {Proto: u8proto.TCP, Port: 8080},
		"dns":  {Proto: u8proto.UDP, Port: 53},
	}, event.k8sMeta.NamedPorts)
}

// The workload in a remote cluster's entry reaches the metadata Hubble reads
// (GetK8sMetadata); an entry from a writer without the field leaves it empty.
func TestIPIdentityWatcherWorkloads(t *testing.T) {
	s := setupIPCacheTestSuite(t)
	watcher := &IPIdentityWatcher{
		log:     hivetest.Logger(t),
		ipcache: s.IPIdentityCache,
		source:  source.ClusterMesh,
	}
	ip := netip.MustParseAddr("10.244.3.17")
	withoutField := `{"IP":"10.244.3.17","Mask":null,"HostIP":"172.18.0.4","ID":199480,"Key":0,"Metadata":"",` +
		`"K8sNamespace":"foo","K8sPodName":"cep-005","K8sServiceAccount":"default"}`
	withField := `{"IP":"10.244.3.17","Mask":null,"HostIP":"172.18.0.4","ID":199480,"Key":0,"Metadata":"",` +
		`"K8sNamespace":"foo","K8sPodName":"cep-005","K8sServiceAccount":"default",` +
		`"K8sWorkloads":[{"Kind":"Deployment","Name":"shop"}]}`

	for _, step := range []struct {
		name, value string
		workloads   []ciliumv2.EndpointWorkload
	}{
		{name: "older writer", value: withoutField},
		{name: "writer upgraded", value: withField, workloads: []ciliumv2.EndpointWorkload{{Kind: "Deployment", Name: "shop"}}},
		{name: "writer rolled back", value: withoutField},
	} {
		var pair identity.IPIdentityPair
		require.NoError(t, pair.Unmarshal(ip.String(), []byte(step.value)), step.name)
		watcher.OnUpdate(&pair)

		meta := s.IPIdentityCache.GetK8sMetadata(ip)
		require.NotNil(t, meta, step.name)
		require.Equal(t, "cep-005", meta.PodName, step.name)
		require.Equal(t, step.workloads, meta.Workloads, step.name)
	}
}

func TestIPIdentityWatcherWorkloadsOnly(t *testing.T) {
	s := setupIPCacheTestSuite(t)
	watcher := &IPIdentityWatcher{
		log: hivetest.Logger(t), ipcache: s.IPIdentityCache, source: source.ClusterMesh,
	}
	ip := netip.MustParseAddr("10.244.3.18")
	pair := identity.IPIdentityPair{
		IP: net.ParseIP(ip.String()), ID: 199480,
		K8sWorkloads: []identity.Workload{{Kind: "Deployment", Name: "shop"}},
	}
	watcher.OnUpdate(&pair)
	meta := s.IPIdentityCache.GetK8sMetadata(ip)
	require.NotNil(t, meta)
	require.Equal(t, []ciliumv2.EndpointWorkload{{Kind: "Deployment", Name: "shop"}}, meta.Workloads)

	// The stored metadata must not alias the input, and a workload-only
	// change must replace it even when identity and addressing stay the same.
	pair.K8sWorkloads[0].Name = "new-owner"
	require.Equal(t, "shop", s.IPIdentityCache.GetK8sMetadata(ip).Workloads[0].Name)
	watcher.OnUpdate(&pair)
	require.Equal(t, "new-owner", s.IPIdentityCache.GetK8sMetadata(ip).Workloads[0].Name)

	pair.K8sWorkloads = nil
	watcher.OnUpdate(&pair)
	require.Nil(t, s.IPIdentityCache.GetK8sMetadata(ip))
}

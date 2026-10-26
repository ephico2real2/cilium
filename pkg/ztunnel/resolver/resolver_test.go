// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resolver

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// The lab's measured CoreDNS identities: cmtc-a (cluster ID 1) and cmtc-b
// (cluster ID 2).
const (
	corednsA = identity.NumericIdentity(66322)
	corednsB = identity.NumericIdentity(131449)
	clientA  = identity.NumericIdentity(69042)
)

var (
	clusterA = cmtypes.ClusterInfo{ID: 1, Name: "cmtc-a", MaxConnectedClusters: 255}
	clusterB = cmtypes.ClusterInfo{ID: 2, Name: "cmtc-b", MaxConnectedClusters: 255}

	corednsSelector = []labels.Label{
		labels.NewLabel("io.kubernetes.pod.namespace", "kube-system", labels.LabelSourceK8s),
		labels.NewLabel("k8s-app", "kube-dns", labels.LabelSourceK8s),
		labels.NewLabel("io.cilium.k8s.policy.serviceaccount", "coredns", labels.LabelSourceK8s),
	}
)

// corednsLabels are the identity labels of a CoreDNS Pod in cluster.
func corednsLabels(cluster string) labels.Labels {
	return labels.NewLabelsFromModel([]string{
		"k8s:io.kubernetes.pod.namespace=kube-system",
		"k8s:k8s-app=kube-dns",
		"k8s:io.cilium.k8s.policy.serviceaccount=coredns",
		"k8s:io.cilium.k8s.policy.cluster=" + cluster,
		"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=kube-system",
	})
}

func without(l labels.Labels, key string) labels.Labels {
	out := maps.Clone(l)
	delete(out, key)
	return out
}

func with(l labels.Labels, model string) labels.Labels {
	out := maps.Clone(l)
	lbl := labels.ParseLabel(model)
	out[lbl.Key] = lbl
	return out
}

func TestSelectorApprovesOnlyLocalResolverIdentities(t *testing.T) {
	a := selector{labels: corednsSelector, cluster: clusterA}
	coredns := corednsLabels("cmtc-a")
	require.True(t, a.approves(corednsA, coredns))

	for name, tc := range map[string]struct {
		sel  selector
		id   identity.NumericIdentity
		lbls labels.Labels
	}{
		"empty selector approves nothing":  {selector{cluster: clusterA}, corednsA, coredns},
		"missing a configured label":       {a, corednsA, without(coredns, "io.cilium.k8s.policy.serviceaccount")},
		"another value":                    {a, corednsA, with(coredns, "k8s:k8s-app=not-dns")},
		"another namespace":                {a, corednsA, with(coredns, "k8s:io.kubernetes.pod.namespace=default")},
		"another source":                   {a, corednsA, with(coredns, "container:k8s-app=kube-dns")},
		"no cluster label":                 {a, corednsA, without(coredns, "io.cilium.k8s.policy.cluster")},
		"another cluster's labels":         {a, corednsA, corednsLabels("cmtc-b")},
		"another cluster's identity range": {a, corednsB, coredns},
		"remote resolver seen from cmtc-b": {selector{labels: corednsSelector, cluster: clusterB}, corednsA, corednsLabels("cmtc-b")},
		"reserved host":                    {a, identity.ReservedIdentityHost, coredns},
		"reserved world":                   {a, identity.ReservedIdentityWorld, coredns},
		"below the allocation range":       {a, identity.NumericIdentity(255), coredns},
		"CIDR (local scope) identity":      {a, identity.IdentityScopeLocal | 1, coredns},
		"remote-node scope identity":       {a, identity.IdentityScopeRemoteNode | 1, coredns},
		"no labels":                        {a, corednsA, nil},
	} {
		t.Run(name, func(t *testing.T) {
			require.False(t, tc.sel.approves(tc.id, tc.lbls))
		})
	}

	// Cluster ID 0 allocates from MinimalNumericIdentity upwards.
	single := selector{labels: corednsSelector, cluster: cmtypes.ClusterInfo{Name: "default", MaxConnectedClusters: 255}}
	require.True(t, single.approves(identity.MinimalNumericIdentity, corednsLabels("default")))
	require.False(t, single.approves(identity.MinimalNumericIdentity-1, corednsLabels("default")))
	require.False(t, single.approves(identity.NumericIdentity(65536), corednsLabels("default")))
}

// fakeMap is resolverMap in memory; value false is a malformed entry.
type fakeMap struct {
	mu        lock.Mutex
	entries   map[identity.NumericIdentity]bool
	failWrite map[identity.NumericIdentity]bool
	opens     int
	closes    int
	failOpen  error
}

func newFakeMap(entries map[identity.NumericIdentity]bool) *fakeMap {
	if entries == nil {
		entries = map[identity.NumericIdentity]bool{}
	}
	return &fakeMap{entries: entries, failWrite: map[identity.NumericIdentity]bool{}}
}

func (f *fakeMap) open() (resolverMap, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOpen != nil {
		return nil, f.failOpen
	}
	f.opens++
	return f, nil
}

func (f *fakeMap) List() (map[identity.NumericIdentity]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.entries), nil
}

func (f *fakeMap) Approve(id identity.NumericIdentity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWrite[id] {
		return errors.New("map full")
	}
	f.entries[id] = true
	return nil
}

func (f *fakeMap) Withdraw(id identity.NumericIdentity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWrite[id] {
		return errors.New("delete failed")
	}
	delete(f.entries, id)
	return nil
}

func (f *fakeMap) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return nil
}

func (f *fakeMap) snapshot() map[identity.NumericIdentity]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.entries)
}

func upsert(id identity.NumericIdentity, lbls labels.Labels) cache.IdentityChange {
	return cache.IdentityChange{Kind: cache.IdentityChangeUpsert, ID: id, Labels: lbls}
}

var syncEvent = cache.IdentityChange{Kind: cache.IdentityChangeSync}

func TestReconcileWritesOnlyTheApprovedSet(t *testing.T) {
	ctx := context.Background()
	// The previous agent run left the resolver, a stale identity and a
	// malformed entry in the pinned map.
	m := newFakeMap(map[identity.NumericIdentity]bool{corednsA: true, 999999: true, clientA: false})
	c := newController(hivetest.Logger(t), selector{labels: corednsSelector, cluster: clusterA}, nil, m.open)

	// Before the first Sync the map is not touched (not even opened).
	c.observe(upsert(clientA, labels.NewLabelsFromModel([]string{"k8s:app=client"})))
	require.NoError(t, c.reconcile(ctx))
	require.Equal(t, map[identity.NumericIdentity]bool{corednsA: true, 999999: true, clientA: false}, m.snapshot())
	require.Zero(t, m.opens)

	c.observe(upsert(corednsA, corednsLabels("cmtc-a")))
	c.observe(syncEvent)
	require.NoError(t, c.reconcile(ctx))
	require.Equal(t, map[identity.NumericIdentity]bool{corednsA: true}, m.snapshot(), "stale and malformed entries are withdrawn")
	require.Equal(t, m.opens, m.closes, "every pass closes its map handle")

	// A malformed value for an approved identity is rewritten.
	m.entries[corednsA] = false
	require.NoError(t, c.reconcile(ctx))
	require.Equal(t, map[identity.NumericIdentity]bool{corednsA: true}, m.snapshot())

	// The resolver identity is released: withdrawn.
	c.observe(cache.IdentityChange{Kind: cache.IdentityChangeDelete, ID: corednsA})
	require.NoError(t, c.reconcile(ctx))
	require.Empty(t, m.snapshot())

	// Approved again, then the same ID no longer matches: withdrawn.
	c.observe(upsert(corednsA, corednsLabels("cmtc-a")))
	require.NoError(t, c.reconcile(ctx))
	require.Equal(t, map[identity.NumericIdentity]bool{corednsA: true}, m.snapshot())
	c.observe(upsert(corednsA, without(corednsLabels("cmtc-a"), "k8s-app")))
	require.NoError(t, c.reconcile(ctx))
	require.Empty(t, m.snapshot())

	// A new subscription: nothing is written until its Sync.
	c.observe(upsert(corednsA, corednsLabels("cmtc-a")))
	require.NoError(t, c.reconcile(ctx))
	c.reset()
	m.entries[888888] = true
	require.NoError(t, c.reconcile(ctx))
	require.Equal(t, map[identity.NumericIdentity]bool{corednsA: true, 888888: true}, m.snapshot())
	c.observe(syncEvent)
	require.NoError(t, c.reconcile(ctx))
	require.Empty(t, m.snapshot(), "the replay carried no resolver: everything is withdrawn")
}

func TestReconcileReportsErrorsAndRetries(t *testing.T) {
	ctx := context.Background()
	m := newFakeMap(map[identity.NumericIdentity]bool{999999: true})
	c := newController(hivetest.Logger(t), selector{labels: corednsSelector, cluster: clusterA}, nil, m.open)
	c.observe(upsert(corednsA, corednsLabels("cmtc-a")))
	c.observe(upsert(corednsA+1, corednsLabels("cmtc-a")))
	c.observe(syncEvent)

	m.failWrite[corednsA] = true
	m.failWrite[999999] = true
	err := c.reconcile(ctx)
	require.ErrorContains(t, err, "approve 66322")
	require.ErrorContains(t, err, "withdraw 999999")
	require.Equal(t, map[identity.NumericIdentity]bool{999999: true, corednsA + 1: true}, m.snapshot(),
		"one failed write does not stop the others")

	clear(m.failWrite)
	require.NoError(t, c.reconcile(ctx))
	require.Equal(t, map[identity.NumericIdentity]bool{corednsA: true, corednsA + 1: true}, m.snapshot())

	m.failOpen = errors.New("no bpffs")
	require.ErrorContains(t, c.reconcile(ctx), "no bpffs")
}

// fakeIdentities is a stream of identity changes. Each subscription replays
// the next script; a script that ends with an error completes the stream.
type fakeIdentities struct {
	mu      lock.Mutex
	scripts []fakeScript
	subs    int
}

type fakeScript struct {
	events []cache.IdentityChange
	end    error
}

func (f *fakeIdentities) Observe(ctx context.Context, next func(cache.IdentityChange), complete func(error)) {
	f.mu.Lock()
	script := fakeScript{}
	if f.subs < len(f.scripts) {
		script = f.scripts[f.subs]
	}
	f.subs++
	f.mu.Unlock()

	go func() {
		for _, e := range script.events {
			next(e)
		}
		if script.end != nil {
			complete(script.end)
			return
		}
		<-ctx.Done()
		complete(ctx.Err())
	}()
}

func (f *fakeIdentities) subscriptions() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subs
}

// The controller wiring as the cell assembles it: the identity watcher, the
// reconciler timer and its trigger, without the pinned map.
func runController(t *testing.T, c *controller) {
	t.Helper()
	h := hive.New(cell.Module("test", "test",
		cell.Invoke(func(jg job.Group) {
			jg.Add(job.OneShot("ztunnel-dns-resolver-identities", c.watch))
			// An hour: only the trigger can run the reconciler in this test.
			jg.Add(job.Timer("ztunnel-dns-resolver-reconcile", c.reconcile, time.Hour, job.WithTrigger(c.trigger)))
		}),
	))
	log := hivetest.Logger(t)
	require.NoError(t, h.Start(log, context.Background()))
	t.Cleanup(func() { require.NoError(t, h.Stop(log, context.Background())) })
}

func TestIdentityStreamDrivesTheMapAndIsResubscribed(t *testing.T) {
	saved := resubscribeDelay
	resubscribeDelay = 10 * time.Millisecond
	t.Cleanup(func() { resubscribeDelay = saved })

	ids := &fakeIdentities{scripts: []fakeScript{
		// The first subscription fails before its Sync (the allocator's
		// initial-sync timeout): nothing may be written from it.
		{events: []cache.IdentityChange{upsert(corednsA, corednsLabels("cmtc-a"))}, end: errors.New("initial global identity sync was cancelled")},
		// The second one replays the cache, syncs and stays open.
		{events: []cache.IdentityChange{
			upsert(corednsA, corednsLabels("cmtc-a")),
			upsert(clientA, labels.NewLabelsFromModel([]string{"k8s:app=client", "k8s:io.cilium.k8s.policy.cluster=cmtc-a"})),
			syncEvent,
		}},
	}}
	m := newFakeMap(map[identity.NumericIdentity]bool{999999: true})
	c := newController(hivetest.Logger(t), selector{labels: corednsSelector, cluster: clusterA}, ids, m.open)
	runController(t, c)

	require.Eventually(t, func() bool {
		snap := m.snapshot()
		return len(snap) == 1 && snap[corednsA]
	}, 5*time.Second, 10*time.Millisecond, "the resubscribed stream's Sync writes the approved set")
	require.Equal(t, 2, ids.subscriptions())

	// A live change after Sync triggers the reconciler on its own.
	c.observe(cache.IdentityChange{Kind: cache.IdentityChangeDelete, ID: corednsA})
	require.Eventually(t, func() bool { return len(m.snapshot()) == 0 }, 5*time.Second, 10*time.Millisecond)
}

func TestEmptySelectorEmptiesTheMap(t *testing.T) {
	m := newFakeMap(map[identity.NumericIdentity]bool{corednsA: true})
	c := newController(hivetest.Logger(t), selector{cluster: clusterA}, nil, m.open)
	// As register does when no label is configured.
	c.observe(syncEvent)
	h := hive.New(cell.Module("test", "test",
		cell.Invoke(func(jg job.Group) {
			jg.Add(job.Timer("ztunnel-dns-resolver-reconcile", c.reconcile, time.Hour, job.WithTrigger(c.trigger)))
		}),
	))
	log := hivetest.Logger(t)
	require.NoError(t, h.Start(log, context.Background()))
	t.Cleanup(func() { require.NoError(t, h.Stop(log, context.Background())) })
	require.Eventually(t, func() bool { return len(m.snapshot()) == 0 }, 5*time.Second, 10*time.Millisecond,
		"an earlier approval is withdrawn once the labels are removed")
}

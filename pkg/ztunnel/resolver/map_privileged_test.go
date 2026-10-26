// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resolver

import (
	"context"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/config"
)

func setupPinnedMap(t *testing.T) {
	testutils.PrivilegedTest(t)
	bpf.CheckOrMountFS(hivetest.Logger(t), "")
	require.NoError(t, rlimit.RemoveMemlock())
	t.Cleanup(func() {
		if m, err := ebpf.LoadPinnedMap(bpf.MapPath(hivetest.Logger(t), MapName), nil); err == nil {
			m.Unpin()
			m.Close()
		}
	})
}

// startResolverCell runs the cell as the agent assembles it: the map registry
// with the generated datapath MapSpecs, the identity stream and the config.
func startResolverCell(t *testing.T, cfg config.Config, ids stream.Observable[cache.IdentityChange]) {
	t.Helper()
	h := hive.New(
		registry.Cell,
		cell.Provide(
			func() config.Config { return cfg },
			func() cmtypes.ClusterInfo { return clusterA },
			func() stream.Observable[cache.IdentityChange] { return ids },
		),
		Cell,
	)
	log := hivetest.Logger(t)
	require.NoError(t, h.Start(log, context.Background()))
	t.Cleanup(func() { require.NoError(t, h.Stop(log, context.Background())) })
}

func pinnedEntries(t *testing.T) map[identity.NumericIdentity]bool {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(bpf.MapPath(hivetest.Logger(t), MapName), nil)
	if err != nil {
		return nil
	}
	defer m.Close()
	out := map[identity.NumericIdentity]bool{}
	var key uint32
	var value uint8
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		out[identity.NumericIdentity(key)] = value == uint8(approved)
	}
	require.NoError(t, iter.Err())
	return out
}

func TestPrivilegedPinnedMapIsTheDatapathMap(t *testing.T) {
	setupPinnedMap(t)

	ids := &fakeIdentities{scripts: []fakeScript{{events: []cache.IdentityChange{
		upsert(corednsA, corednsLabels("cmtc-a")),
		upsert(clientA, labels.NewLabelsFromModel([]string{"k8s:app=client", "k8s:io.cilium.k8s.policy.cluster=cmtc-a"})),
		syncEvent,
	}}}}
	cfg := config.DefaultConfig
	cfg.EnableZTunnel = true
	cfg.DNSResolverLabels = []string{
		"k8s:io.kubernetes.pod.namespace=kube-system",
		"k8s:k8s-app=kube-dns",
		"k8s:io.cilium.k8s.policy.serviceaccount=coredns",
	}
	startResolverCell(t, cfg, ids)

	require.Eventually(t, func() bool {
		e := pinnedEntries(t)
		return len(e) == 1 && e[corednsA]
	}, 10*time.Second, 20*time.Millisecond, "the approved CoreDNS identity is pinned")

	// The pin has the shape bpf/lib/ztunnel_admission.h declares.
	m, err := ebpf.LoadPinnedMap(bpf.MapPath(hivetest.Logger(t), MapName), nil)
	require.NoError(t, err)
	info, err := m.Info()
	require.NoError(t, err)
	require.NoError(t, m.Close())
	require.Equal(t, ebpf.Hash, info.Type)
	require.Equal(t, uint32(4), info.KeySize)
	require.Equal(t, uint32(1), info.ValueSize)
	require.Equal(t, uint32(64), info.MaxEntries)
	require.Equal(t, uint32(unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG), info.Flags&(unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG))
}

func TestPrivilegedRestartKeepsApprovalsUntilSyncAndRemovalEmptiesTheMap(t *testing.T) {
	setupPinnedMap(t)

	cfg := config.DefaultConfig
	cfg.EnableZTunnel = true
	cfg.DNSResolverLabels = []string{"k8s:io.kubernetes.pod.namespace=kube-system", "k8s:k8s-app=kube-dns"}

	// A previous run approved CoreDNS and an identity that no longer exists.
	h := hive.New(registry.Cell, cell.Invoke(func(r *registry.MapRegistry, lc cell.Lifecycle) {
		lc.Append(cell.Hook{OnStart: func(cell.HookContext) error {
			m, err := openMap(r)
			if err != nil {
				return err
			}
			defer m.Close()
			if err := m.Approve(corednsA); err != nil {
				return err
			}
			return m.Approve(999999)
		}})
	}))
	log := hivetest.Logger(t)
	require.NoError(t, h.Start(log, context.Background()))
	require.NoError(t, h.Stop(log, context.Background()))
	require.Equal(t, map[identity.NumericIdentity]bool{corednsA: true, 999999: true}, pinnedEntries(t))

	// The agent restarts and its identity stream has not synced yet: the
	// previous approvals stay in place.
	t.Run("before sync", func(t *testing.T) {
		startResolverCell(t, cfg, &fakeIdentities{scripts: []fakeScript{{events: []cache.IdentityChange{
			upsert(corednsA, corednsLabels("cmtc-a")),
		}}}})
		time.Sleep(200 * time.Millisecond)
		require.Equal(t, map[identity.NumericIdentity]bool{corednsA: true, 999999: true}, pinnedEntries(t))
	})

	// After Sync, only the current resolver remains.
	t.Run("after sync", func(t *testing.T) {
		startResolverCell(t, cfg, &fakeIdentities{scripts: []fakeScript{{events: []cache.IdentityChange{
			upsert(corednsA, corednsLabels("cmtc-a")), syncEvent,
		}}}})
		require.Eventually(t, func() bool {
			e := pinnedEntries(t)
			return len(e) == 1 && e[corednsA]
		}, 10*time.Second, 20*time.Millisecond)
	})

	// The labels are removed: nothing is approved any more.
	t.Run("labels removed", func(t *testing.T) {
		empty := cfg
		empty.DNSResolverLabels = nil
		startResolverCell(t, empty, &fakeIdentities{})
		require.Eventually(t, func() bool {
			e := pinnedEntries(t)
			return e != nil && len(e) == 0
		}, 10*time.Second, 20*time.Millisecond)
	})
}

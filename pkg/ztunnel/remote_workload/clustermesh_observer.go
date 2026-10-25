// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	cmobserver "github.com/cilium/cilium/pkg/clustermesh/observer"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const observerName cmobserver.Name = "ztunnel-remote-workloads"

const logFieldStage = "stage"
const logFieldAdvertisedClusterID = "advertisedClusterId"

// FactoryParams are native Cilium dependencies for one remote-workload
// observer per ClusterMesh peer. The sink stores complete replacement
// snapshots; it must not translate them to local endpoint/IPIdentity APIs.
type FactoryParams struct {
	Logger        *slog.Logger
	StoreFactory  store.Factory
	ClusterInfo   cmtypes.ClusterInfo
	Sink          SnapshotSink
	EnableZTunnel bool
}

// NewClusterMeshObserverFactory implements the existing ClusterMesh observer
// extension point. It watches only direct authenticated peers. KVStoreMesh
// cache entries have no authenticated source-peer attestation and are refused.
func NewClusterMeshObserverFactory(params FactoryParams) cmobserver.Factory {
	return func(cluster string, onSync func()) cmobserver.Observer {
		return &clusterMeshObserver{
			logger:        params.Logger.With(logfields.ClusterName, cluster),
			cluster:       cluster,
			storeFactory:  params.StoreFactory,
			clusterInfo:   params.ClusterInfo,
			sink:          params.Sink,
			enableZTunnel: params.EnableZTunnel,
			onSync:        onSync,
		}
	}
}

type clusterMeshObserver struct {
	logger        *slog.Logger
	cluster       string
	storeFactory  store.Factory
	clusterInfo   cmtypes.ClusterInfo
	sink          SnapshotSink
	enableZTunnel bool
	onSync        func()

	mu        lock.Mutex
	clusterID uint32
	inventory *Inventory
	watch     store.WatchStore
	enabled   atomic.Bool
	syncOnce  sync.Once
}

var _ cmobserver.Observer = (*clusterMeshObserver)(nil)

func (o *clusterMeshObserver) Name() cmobserver.Name { return observerName }

func (o *clusterMeshObserver) Status() cmobserver.Status {
	o.mu.Lock()
	inv, watch := o.inventory, o.watch
	o.mu.Unlock()

	status := cmobserver.Status{Enabled: o.enabled.Load()}
	if inv != nil {
		status.Entries = inv.NumEntries()
		status.Synced = inv.Ready() && watch != nil && watch.Synced()
	}
	return status
}

func (o *clusterMeshObserver) Register(mgr store.WatchStoreManager, backend kvstore.BackendOperations, cfg cmtypes.CiliumClusterConfig) {
	if !o.enableZTunnel {
		o.disable("ztunnel is disabled")
		return
	}
	if cfg.Capabilities.Cached {
		o.logger.Warn("Remote workload discovery disabled for KVStoreMesh cache without source attestation",
			logFieldStage, "remote-workload-peer-check",
		)
		o.disable("KVStoreMesh origin is not authenticated")
		return
	}
	if !cfg.Capabilities.WorkloadIdentityV1 {
		o.logger.Warn("Remote workload discovery disabled because peer does not advertise namespace-incarnation metadata",
			logFieldStage, "remote-workload-peer-check",
		)
		o.disable("remote peer does not support the workload identity v1 capability")
		return
	}

	binding, ok := backend.(kvstore.RemotePeerBindingInfo)
	if !ok {
		o.logger.Warn("Remote workload discovery disabled because backend has no verified peer identity",
			logFieldStage, "remote-workload-peer-check",
		)
		o.disable("backend does not expose a verified remote peer identity")
		return
	}
	provider, ok := backend.(kvstore.RemotePeerEvidenceProvider)
	if !ok {
		o.logger.Warn("Remote workload discovery disabled because backend has no live peer evidence provider",
			logFieldStage, "remote-workload-peer-check",
		)
		o.disable("backend does not expose live verified peer evidence")
		return
	}
	pinnedName, pinnedID, profileID := binding.PinnedRemotePeer()
	if pinnedName != o.cluster || pinnedID != cfg.ID || profileID == [32]byte{} {
		o.logger.Warn("Remote workload discovery disabled because peer provenance does not match ClusterMesh config",
			logFieldStage, "remote-workload-peer-check",
			logfields.Peer, pinnedName,
			logfields.ClusterID, pinnedID,
			logFieldAdvertisedClusterID, cfg.ID,
		)
		o.disable("TLS-pinned peer identity does not match advertised ClusterMesh identity")
		return
	}

	o.mu.Lock()
	if o.sink == nil || o.storeFactory == nil {
		o.mu.Unlock()
		o.disable("remote workload snapshot dependencies are unavailable")
		return
	}
	if o.inventory != nil && o.clusterID != pinnedID {
		o.mu.Unlock()
		o.disable("remote peer ClusterID changed; explicit observer replacement is required")
		return
	}
	if o.inventory == nil {
		inv, err := NewInventory(o.cluster, pinnedID, o.clusterInfo, provider, o.sink)
		if err != nil {
			o.mu.Unlock()
			o.disable(err.Error())
			return
		}
		inv.SetOnListDone(func() {
			if o.onSync != nil {
				o.syncOnce.Do(o.onSync)
			}
		})
		o.inventory = inv
		o.clusterID = pinnedID
	}
	inv := o.inventory
	o.mu.Unlock()

	watch := o.storeFactory.NewWatchStore(
		o.cluster,
		func() store.Key { return &identity.IPIdentityPair{} },
		inv,
		store.RWSWithSessionObserver(inv),
	)
	o.mu.Lock()
	o.watch = watch
	o.enabled.Store(true)
	o.mu.Unlock()

	// Direct ClusterMesh stores cilium/state/ip/v1/<address-space>/<IP> in the
	// peer etcd. KVStoreMesh's cilium/cache path was rejected above.
	prefix := kvstore.JoinKey(ipcache.IPIdentitiesPath, ipcache.AddressSpace)
	mgr.Register(ipcache.IPIdentitiesPath, func(ctx context.Context) {
		o.runWatchSessions(ctx, watch, backend, prefix, inv, provider)
	})
}

const peerEvidenceRecheckInterval = 5 * time.Second

// runWatchSessions forces a new complete initial list whenever the immutable
// TLS-handshake proof changes, expires, or loses actual heartbeat freshness.
// Every session gets its own WatchStore Begin/ListDone/End epoch; it cannot
// continue serving the previous snapshot after a source-session transition.
func (o *clusterMeshObserver) runWatchSessions(
	ctx context.Context,
	watch store.WatchStore,
	backend kvstore.BackendOperations,
	prefix string,
	inventory *Inventory,
	provider kvstore.RemotePeerEvidenceProvider,
) {
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		evidence, err := provider.CurrentRemotePeerEvidence()
		if err == nil && evidence == nil {
			err = fmt.Errorf("remote peer evidence provider returned no evidence")
		}
		if err == nil && (evidence.ClusterName() != o.cluster || evidence.ClusterID() != inventory.clusterID) {
			err = fmt.Errorf("remote peer identity changed during watch registration")
		}
		if err == nil {
			err = evidence.Validate(time.Now())
		}
		if err != nil {
			inventory.Invalidate("remote peer evidence unavailable: " + err.Error())
			if !waitForRemoteWatchRetry(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, 10*time.Second)
			continue
		}

		sessionCtx, cancel := context.WithCancel(ctx)
		inventory.SetSessionCancel(cancel)
		guardDone := make(chan struct{})
		go func(sessionID uint64, profileID [32]byte) {
			defer close(guardDone)
			ticker := time.NewTicker(peerEvidenceRecheckInterval)
			defer ticker.Stop()
			for {
				select {
				case <-sessionCtx.Done():
					return
				case <-ticker.C:
					current, err := provider.CurrentRemotePeerEvidence()
					if err == nil && current == nil {
						err = fmt.Errorf("remote peer evidence provider returned no evidence")
					}
					if err == nil && (current.IdentityEpoch() != sessionID || current.ProfileID() != profileID) {
						err = fmt.Errorf("verified TLS peer identity changed; a fresh complete watch list is required")
					}
					if err == nil {
						err = current.Validate(time.Now())
					}
					if err != nil {
						inventory.Invalidate("remote peer evidence changed: " + err.Error())
						cancel()
						return
					}
				}
			}
		}(evidence.IdentityEpoch(), evidence.ProfileID())

		watch.Watch(sessionCtx, backend, prefix)
		cancel()
		<-guardDone
		inventory.SetSessionCancel(nil)
		if ctx.Err() != nil {
			return
		}
		if !waitForRemoteWatchRetry(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, 10*time.Second)
	}
}

func waitForRemoteWatchRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (o *clusterMeshObserver) disable(reason string) {
	o.enabled.Store(false)
	o.mu.Lock()
	inv := o.inventory
	o.mu.Unlock()
	if inv != nil {
		inv.Drain()
	}
	o.logger.Info("Remote workload discovery is unavailable",
		logFieldStage, "remote-workload-peer-check",
		logfields.Reason, reason,
	)
}

func (o *clusterMeshObserver) Drain() {
	o.disable("remote ClusterMesh observer drained")
}

func (o *clusterMeshObserver) Revoke() {
	o.disable("remote ClusterMesh observer revoked after connectivity loss")
}

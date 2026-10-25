// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	cmobserver "github.com/cilium/cilium/pkg/clustermesh/observer"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const observerName cmobserver.Name = "ztunnel-remote-workloads"

const logFieldStage = "stage"

// FactoryParams are native Cilium dependencies for one remote-workload
// observer per ClusterMesh peer. The sink stores complete replacement
// snapshots; it must not translate them to local endpoint/IPIdentity APIs.
type FactoryParams struct {
	Logger                 *slog.Logger
	StoreFactory           store.Factory
	ClusterInfo            cmtypes.ClusterInfo
	Sink                   SnapshotSink
	EnableZTunnel          bool
	EnableSourceMembership bool
	OriginConfigDirectory  string
	OriginClientCommonName string
	RemoteClientFactory    common.RemoteClientFactoryFn
}

// NewClusterMeshObserverFactory implements the existing ClusterMesh observer
// extension point. When enabled, a separately pinned direct-origin connection
// reads identity and source-membership records. It never treats KVStoreMesh's
// routing cache as source provenance and never changes the route backend.
func NewClusterMeshObserverFactory(params FactoryParams) cmobserver.Factory {
	return func(cluster string, onSync func()) cmobserver.Observer {
		return &clusterMeshObserver{
			logger:                 params.Logger.With(logfields.ClusterName, cluster),
			cluster:                cluster,
			storeFactory:           params.StoreFactory,
			clusterInfo:            params.ClusterInfo,
			sink:                   params.Sink,
			enableZTunnel:          params.EnableZTunnel,
			enableSourceMembership: params.EnableSourceMembership,
			originConfigDirectory:  params.OriginConfigDirectory,
			originClientCommonName: params.OriginClientCommonName,
			remoteClientFactory:    params.RemoteClientFactory,
			onSync:                 onSync,
		}
	}
}

type clusterMeshObserver struct {
	logger                 *slog.Logger
	cluster                string
	storeFactory           store.Factory
	clusterInfo            cmtypes.ClusterInfo
	sink                   SnapshotSink
	enableZTunnel          bool
	enableSourceMembership bool
	originConfigDirectory  string
	originClientCommonName string
	remoteClientFactory    common.RemoteClientFactoryFn
	onSync                 func()

	mu            lock.Mutex
	clusterID     uint32
	inventory     *Inventory
	joiner        *SourceMembershipJoiner
	originSession *IPIdentityOriginWatchSession
	watch         store.WatchStore
	sourceWatch   store.WatchStore
	enabled       atomic.Bool
	syncOnce      sync.Once
}

var _ cmobserver.Observer = (*clusterMeshObserver)(nil)

func (o *clusterMeshObserver) Name() cmobserver.Name { return observerName }

func (o *clusterMeshObserver) Status() cmobserver.Status {
	o.mu.Lock()
	inv, joiner, watch, sourceWatch := o.inventory, o.joiner, o.watch, o.sourceWatch
	o.mu.Unlock()

	status := cmobserver.Status{Enabled: o.enabled.Load()}
	if inv != nil {
		status.Entries = inv.NumEntries()
		status.Synced = inv.Ready() && joiner != nil && joiner.Ready() && watch != nil && watch.Synced() && sourceWatch != nil && sourceWatch.Synced()
	}
	return status
}

func (o *clusterMeshObserver) Register(mgr store.WatchStoreManager, _ kvstore.BackendOperations, cfg cmtypes.CiliumClusterConfig) {
	if !o.enableZTunnel {
		o.disable("ztunnel is disabled")
		return
	}
	if !o.enableSourceMembership {
		o.disable("remote workload membership is disabled by configuration")
		return
	}
	if o.originConfigDirectory == "" || o.originClientCommonName == "" || o.remoteClientFactory == nil {
		o.disable("direct-origin peer configuration is unavailable")
		return
	}
	if !cfg.Capabilities.WorkloadIdentityV1 {
		o.logger.Warn("Remote workload discovery disabled because peer does not advertise namespace-incarnation metadata",
			logFieldStage, "remote-workload-peer-check",
		)
		o.disable("remote peer does not support the workload identity v1 capability")
		return
	}
	if !cfg.Capabilities.ZtunnelMembershipV1 {
		o.logger.Warn("Remote workload discovery disabled because peer does not advertise required/captured membership metadata",
			logFieldStage, "remote-workload-peer-check",
		)
		o.disable("remote peer does not support the ztunnel membership v1 capability")
		return
	}
	if err := cmtypes.ValidateClusterID(cfg.ID); err != nil {
		o.disable("ClusterMesh peer has an invalid ClusterID: " + err.Error())
		return
	}
	if mgr == nil || o.storeFactory == nil || o.sink == nil {
		o.disable("remote workload snapshot dependencies are unavailable")
		return
	}

	o.mu.Lock()
	if o.originSession != nil {
		if o.clusterID != cfg.ID {
			o.mu.Unlock()
			o.disable("remote peer ClusterID changed; explicit observer replacement is required")
			return
		}
		o.mu.Unlock()
		return
	}
	joiner, err := NewSourceMembershipJoiner(o.cluster, cfg.ID, o.logger, o.sink)
	if err != nil {
		o.mu.Unlock()
		o.disable(err.Error())
		return
	}
	joiner.SetOnReady(func() {
		if o.onSync != nil {
			o.syncOnce.Do(o.onSync)
		}
	})
	session := &IPIdentityOriginWatchSession{
		Factory: o.storeFactory, ClusterInfo: o.clusterInfo,
		Logger: o.logger, Joiner: joiner,
		OnInventory: func(inventory *Inventory, workloadWatch, sourceWatch store.WatchStore) {
			o.mu.Lock()
			o.inventory, o.watch, o.sourceWatch = inventory, workloadWatch, sourceWatch
			o.mu.Unlock()
		},
	}
	o.joiner = joiner
	o.clusterID = cfg.ID
	o.originSession = session
	o.mu.Unlock()

	supervisor := &OriginPeerSupervisor{
		Logger: o.logger,
		Loader: FilesystemOriginPeerConfigLoader{
			Directory: o.originConfigDirectory, ExpectedClientCommonName: o.originClientCommonName,
		},
		Opener: PinnedEtcdOriginPeerOpener{Factory: o.remoteClientFactory, Logger: o.logger},
		Watch:  session, Invalidator: o,
	}
	o.enabled.Store(true)
	mgr.Register(ipcache.IPIdentitiesPath, func(ctx context.Context) {
		if err := supervisor.Run(ctx, o.cluster, cfg.ID); err != nil && ctx.Err() == nil {
			o.logger.Error("Direct-origin membership supervisor stopped",
				logFieldStage, "origin-supervisor",
				logfields.Error, err)
		}
	})
}

// InvalidateOriginPeer is called before an origin connection is opened and
// before its backend is closed. It withdraws the source-joined snapshot via
// the same monotonic joiner revision used for watch callbacks.
func (o *clusterMeshObserver) InvalidateOriginPeer(name string, clusterID uint32, reason string) {
	o.mu.Lock()
	joiner := o.joiner
	matches := name == o.cluster && clusterID == o.clusterID
	o.mu.Unlock()
	if matches && joiner != nil {
		joiner.Invalidate(reason)
	}
}

const peerEvidenceRecheckInterval = 5 * time.Second

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
	inv, joiner := o.inventory, o.joiner
	o.mu.Unlock()
	if joiner != nil {
		joiner.Invalidate(reason)
	}
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

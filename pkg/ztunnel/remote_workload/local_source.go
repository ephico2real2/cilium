// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
	ztunnelconfig "github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
)

const (
	localSourceRetryMin = time.Second
	localSourceRetryMax = 30 * time.Second
	logLocalSource      = "local-source-membership"
)

// LocalSourceMailbox holds the leased workloads of this cluster's other
// nodes: the same-cluster sources a destination on this node may admit. It
// is separate from PeerSnapshotStore, whose snapshots become remote
// destinations; a workload of this cluster must never be projected as one.
type LocalSourceMailbox struct{ *SnapshotMailbox }

func newLocalSourceMailbox() *LocalSourceMailbox {
	return &LocalSourceMailbox{SnapshotMailbox: NewSnapshotMailbox()}
}

type localSourceParams struct {
	cell.In

	Logger       *slog.Logger
	JobGroup     job.Group
	StoreFactory store.Factory
	ClusterInfo  cmtypes.ClusterInfo
	Config       ztunnelconfig.Config
	Mailbox      *LocalSourceMailbox
	KVStore      kvstore.Client `optional:"true"`
	Resolver     dial.Resolver  `optional:"true"`
}

// localSourceBackend opens one connection for a watch session and returns
// the function that releases it.
type localSourceBackend func(context.Context) (kvstore.BackendOperations, func(), error)

// registerLocalSourceReader reads this cluster's source records under the
// same conditions, and over the same kind of connection, as the publisher
// writes them. Without it, no destination admits a source of another node.
func registerLocalSourceReader(p localSourceParams) error {
	cfg := p.Config
	if !cfg.EnableZTunnel || !cfg.RequireMTLS || !cfg.EnableRemoteWorkloadMembership {
		return nil
	}
	var open localSourceBackend
	switch path := cfg.SourceMembershipEtcdConfig; {
	case path != "":
		dedicated := membership.OpenDedicatedBackend(p.Logger, path, p.Resolver)
		open = func(ctx context.Context) (kvstore.BackendOperations, func(), error) {
			backend, err := dedicated(ctx)
			if err != nil {
				return nil, nil, err
			}
			return backend, backend.Close, nil
		}
	case p.KVStore != nil && p.KVStore.IsEnabled():
		open = func(context.Context) (kvstore.BackendOperations, func(), error) {
			return p.KVStore, func() {}, nil
		}
	default:
		return fmt.Errorf("same-cluster source membership requires a dedicated membership etcd connection or an enabled KVStore")
	}
	joiner, err := NewLocalSourceMembershipJoiner(p.ClusterInfo.Name, p.ClusterInfo.ID, nodetypes.GetName(),
		p.Logger.With(logfields.LogSubsys, logLocalSource), p.Mailbox)
	if err != nil {
		return err
	}
	p.JobGroup.Add(job.OneShot(logLocalSource, func(ctx context.Context, health cell.Health) error {
		return runLocalSourceReader(ctx, health, p.Logger, open, p.StoreFactory, p.ClusterInfo.Name, joiner)
	}))
	return nil
}

// runLocalSourceReader keeps one watch session of this cluster's source
// records open until the agent stops. Between sessions the joiner's view is
// withdrawn, so a destination admits no same-cluster source of another node.
func runLocalSourceReader(ctx context.Context, health cell.Health, logger *slog.Logger, open localSourceBackend,
	factory store.Factory, clusterName string, joiner *SourceMembershipJoiner) error {
	delay := localSourceRetryMin
	for attempt := 1; ; attempt++ {
		started := time.Now()
		backend, release, err := open(ctx)
		if ctx.Err() != nil {
			if release != nil {
				release()
			}
			return nil
		}
		if err == nil {
			health.OK("same-cluster source membership watch running")
			watch := factory.NewWatchStore(clusterName, func() store.Key { return &SourceMembershipKey{} },
				joiner, store.RWSWithSessionObserver(joiner))
			err = runLocalSourceMembershipWatch(ctx, backend, watch, joiner)
			release()
			if ctx.Err() != nil {
				return nil
			}
			// A session that ran had a working connection; retry promptly.
			delay = localSourceRetryMin
		}
		health.Degraded("same-cluster source membership watch unavailable", err)
		logger.Warn("Same-cluster source membership watch ended; destinations admit no source of another node until it resumes",
			logfields.LogSubsys, logLocalSource,
			logfields.Attempt, attempt,
			logfields.ElapsedDuration, time.Since(started),
			logfields.RetryDelay, delay,
			logfields.Error, err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		delay = min(2*delay, localSourceRetryMax)
	}
}

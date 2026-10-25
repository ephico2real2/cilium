// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"google.golang.org/grpc"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
)

const (
	membershipConnectRetryMin = time.Second
	membershipConnectRetryMax = 30 * time.Second
)

// openMembershipBackend opens the dedicated etcd connection of the source
// membership publisher. It is separate from the agent's global kvstore, which
// stays disabled, so publishing membership does not switch on node, ipcache or
// identity kvstore synchronization. The configured credentials hold only the
// ztunnel membership writer role of this cluster's etcd.
func openMembershipBackend(logger *slog.Logger, configPath string, resolver dial.Resolver) func(context.Context) (kvstore.BackendOperations, error) {
	return func(ctx context.Context) (kvstore.BackendOperations, error) {
		opts := kvstore.ExtraOptions{
			// The writer role grants no init-lock key: the membership lock
			// and the lease-fenced writes are themselves quorum operations.
			NoLockQuorumCheck:      true,
			NoEndpointStatusChecks: true,
			LeaseTTL:               defaults.KVstoreLeaseTTL,
			ClusterName:            "ztunnel-membership",
		}
		if resolver != nil {
			// Resolve the in-cluster service without depending on cluster DNS.
			opts.DialOption = []grpc.DialOption{grpc.WithContextDialer(dial.NewContextDialer(logger, resolver))}
		}
		backend, errCh := kvstore.NewClient(ctx, logger, kvstore.EtcdBackendName,
			map[string]string{kvstore.EtcdOptionConfig: configPath}, opts)
		select {
		case err := <-errCh:
			if err != nil {
				if backend != nil {
					backend.Close()
				}
				return nil, err
			}
			return backend, nil
		case <-ctx.Done():
			if backend != nil {
				backend.Close()
			}
			return nil, ctx.Err()
		}
	}
}

// dedicatedSourcePublisher runs the source membership publisher on its own
// etcd connection until the agent stops. Connection failures are retried and
// never stop the agent. No record is published meanwhile, so peers observe
// this node's membership lease expire and withdraw its workloads.
func (g *gate) dedicatedSourcePublisher(open func(context.Context) (kvstore.BackendOperations, error), endpoints endpointmanager.EndpointsLookup,
	cfg membership.SourcePublisherConfig, target string) func(context.Context, cell.Health) error {
	return func(ctx context.Context, health cell.Health) error {
		delay := cmp.Or(g.membershipRetryMin, membershipConnectRetryMin)
		maxDelay := cmp.Or(g.membershipRetryMax, membershipConnectRetryMax)
		for attempt := 1; ; attempt++ {
			started := time.Now()
			backend, err := open(ctx)
			if ctx.Err() != nil {
				if backend != nil {
					backend.Close()
				}
				return nil
			}
			if err != nil {
				health.Degraded("dedicated source membership etcd connection unavailable", err)
				g.logger.Warn("Unable to connect the dedicated source membership etcd connection",
					logStage, "membership-connect",
					logfields.Attempt, attempt,
					logfields.ElapsedDuration, time.Since(started),
					logfields.RetryDelay, delay,
					logfields.Path, target,
					logfields.Error, err)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(delay):
				}
				delay = min(2*delay, maxDelay)
				continue
			}
			publisher, err := membership.NewSourcePublisher(g.membership, endpoints, []membership.EndpointRevalidator{g},
				kvstore.StandaloneClient(backend), g.logger, cfg)
			if err != nil {
				backend.Close()
				return fmt.Errorf("source membership publisher cannot use the dedicated etcd connection: %w", err)
			}
			health.OK("dedicated source membership etcd connection established")
			g.logger.Info("Source membership publisher connected",
				logStage, "membership-connect",
				logfields.Attempt, attempt,
				logfields.ElapsedDuration, time.Since(started),
				logfields.Path, target)
			err = publisher.Run(ctx)
			backend.Close()
			return err
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"cmp"
	"context"
	"fmt"

	"github.com/cilium/hive/cell"

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

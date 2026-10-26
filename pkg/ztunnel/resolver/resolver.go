// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package resolver programs cilium_ztunnel_dns_resolvers, the security
// identities that HBONE-only endpoints may query for DNS in plaintext
// (bpf/lib/ztunnel_admission.h). It is not a policy: it only names the
// resolvers, and native egress policy still decides every DNS flow.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// reconcileInterval bounds how long the map can drift from the desired set
// (for example after a failed write) when no identity changes.
const reconcileInterval = time.Minute

// resubscribeDelay paces resubscription when the identity stream ends.
var resubscribeDelay = 5 * time.Second

// selector decides which identities are approved resolvers.
type selector struct {
	labels  []labels.Label
	cluster cmtypes.ClusterInfo
}

// approves reports whether id is an approved resolver: an identity in the
// local cluster's allocation range (so never reserved, CIDR, remote-node or
// remote-cluster) whose labels name the local cluster and carry every
// configured label. An empty selector approves nothing.
func (s selector) approves(id identity.NumericIdentity, lbls labels.Labels) bool {
	if len(s.labels) == 0 ||
		id.Uint32() < s.cluster.MinimalAllocationIdentity() ||
		id.Uint32() > s.cluster.MaximumAllocationIdentity() {
		return false
	}
	if !lbls.HasLabel(labels.NewLabel(k8sConst.PolicyLabelCluster, s.cluster.Name, labels.LabelSourceK8s)) {
		return false
	}
	for _, l := range s.labels {
		if !lbls.HasLabel(l) {
			return false
		}
	}
	return true
}

// controller keeps the pinned map equal to the approved identities of the
// local identity cache.
//
// Before the first identity Sync the map is left as it is: after an agent
// restart it still holds the previous run's approvals, so resolution keeps
// working, and the first Sync withdraws anything no longer approved.
type controller struct {
	log        *slog.Logger
	selector   selector
	identities stream.Observable[cache.IdentityChange]
	open       func() (resolverMap, error)
	trigger    job.Trigger

	mu      lock.Mutex
	synced  bool
	desired map[identity.NumericIdentity]struct{}
}

func newController(log *slog.Logger, sel selector, identities stream.Observable[cache.IdentityChange],
	open func() (resolverMap, error)) *controller {
	return &controller{
		log:        log,
		selector:   sel,
		identities: identities,
		open:       open,
		trigger:    job.NewTrigger(),
		desired:    make(map[identity.NumericIdentity]struct{}),
	}
}

// reset forgets the desired set until the next Sync, for a new subscription
// that replays the cache.
func (c *controller) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.synced = false
	clear(c.desired)
}

// observe applies one identity change. It runs on the allocator's goroutine,
// so it only updates the desired set and triggers the reconciler.
func (c *controller) observe(change cache.IdentityChange) {
	c.mu.Lock()
	changed := false
	switch change.Kind {
	case cache.IdentityChangeSync:
		changed = !c.synced
		c.synced = true
	case cache.IdentityChangeUpsert:
		_, had := c.desired[change.ID]
		if c.selector.approves(change.ID, change.Labels) {
			c.desired[change.ID] = struct{}{}
			changed = !had
		} else {
			delete(c.desired, change.ID)
			changed = had
		}
	case cache.IdentityChangeDelete:
		_, changed = c.desired[change.ID]
		delete(c.desired, change.ID)
	}
	notify := changed && c.synced
	c.mu.Unlock()

	if notify {
		c.trigger.Trigger()
	}
}

// watch subscribes to the identity cache and subscribes again whenever the
// stream ends before shutdown, so a transient allocator failure cannot leave
// the map frozen.
func (c *controller) watch(ctx context.Context, health cell.Health) error {
	for {
		c.reset()
		done := make(chan error, 1)
		c.identities.Observe(ctx, c.observe, func(err error) { done <- err })
		health.OK("Watching identities")

		err := <-done
		if ctx.Err() != nil {
			return nil
		}
		health.Degraded("Identity stream ended; subscribing again", err)
		c.log.Warn("Identity stream ended; subscribing again",
			logfields.Error, err,
			logfields.Interval, resubscribeDelay)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(resubscribeDelay):
		}
	}
}

// reconcile writes the desired set to the map: it withdraws every entry that
// is not approved and approves every missing or malformed one. The map is
// opened for each pass so that a map the loader re-created is never missed.
func (c *controller) reconcile(ctx context.Context) error {
	c.mu.Lock()
	synced := c.synced
	desired := maps.Clone(c.desired)
	c.mu.Unlock()

	if !synced {
		return nil
	}

	m, err := c.open()
	if err != nil {
		return err
	}
	defer m.Close()

	current, err := m.List()
	if err != nil {
		return err
	}

	var errs []error
	for id := range current {
		if _, ok := desired[id]; ok {
			continue
		}
		if err := m.Withdraw(id); err != nil {
			errs = append(errs, fmt.Errorf("withdraw %d: %w", id, err))
			continue
		}
		c.log.Info("Withdrew DNS resolver identity", logfields.Identity, id)
	}
	for id := range desired {
		if valid, ok := current[id]; ok && valid {
			continue
		}
		if err := m.Approve(id); err != nil {
			errs = append(errs, fmt.Errorf("approve %d: %w", id, err))
			continue
		}
		c.log.Info("Approved DNS resolver identity", logfields.Identity, id)
	}
	return errors.Join(errs...)
}

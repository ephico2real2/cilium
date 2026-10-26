// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resolver

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/ztunnel/config"
)

// Cell programs the approved DNS resolver identities of HBONE-only endpoints
// from ztunnel-dns-resolver-labels.
var Cell = cell.Module(
	"ztunnel-dns-resolver",
	"Approved DNS resolver identities for HBONE-only endpoints",
	cell.Invoke(register),
)

type params struct {
	cell.In

	Logger      *slog.Logger
	JobGroup    job.Group
	Config      config.Config
	ClusterInfo cmtypes.ClusterInfo
	Registry    *registry.MapRegistry
	Identities  stream.Observable[cache.IdentityChange]
}

func register(p params) error {
	if !p.Config.EnableZTunnel {
		return nil
	}
	sel, err := p.Config.DNSResolverSelector()
	if err != nil {
		return err
	}

	c := newController(p.Logger, selector{labels: sel, cluster: p.ClusterInfo}, p.Identities,
		func() (resolverMap, error) { return openMap(p.Registry) })
	if len(sel) == 0 {
		// Nothing is approved, so there is nothing to watch: the reconciler
		// empties the map, which also withdraws an earlier configuration.
		c.observe(cache.IdentityChange{Kind: cache.IdentityChangeSync})
	} else {
		p.JobGroup.Add(job.OneShot("ztunnel-dns-resolver-identities", c.watch))
	}
	p.JobGroup.Add(job.Timer("ztunnel-dns-resolver-reconcile", c.reconcile, reconcileInterval,
		job.WithTrigger(c.trigger)))

	p.Logger.Info("ztunnel DNS resolver approval configured",
		"labels", p.Config.DNSResolverLabels,
		"clusterName", p.ClusterInfo.Name,
		"clusterID", p.ClusterInfo.ID)
	return nil
}

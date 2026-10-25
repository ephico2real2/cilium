// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"fmt"
	"maps"
	"net/netip"

	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
)

// nodeNameResolver binds the Kubernetes Node metadata.name of each workload's
// node into an Address batch. ztunnel compares Workload.Node with its own
// NODE_NAME (spec.nodeName), so the value is the API Node name, never an IP.
type nodeNameResolver interface {
	// bind returns copies of the CREATE events with NodeName set, the
	// address-to-name pairs it used, and a watch from the same read.
	bind(EndpointEventCollection) (EndpointEventCollection, map[netip.Addr]string, <-chan struct{}, error)
	// verify re-reads previously bound pairs in one read. It fails if any pair
	// changed, disappeared or became ambiguous, and returns a fresh watch.
	verify(map[netip.Addr]string) (<-chan struct{}, error)
}

// nativeNodeNames reads Cilium's native node table. That table is fed by
// Cilium's node discovery (Kubernetes Node / CiliumNode for the local cluster,
// ClusterMesh for remote clusters). Only nodes of the local cluster are used:
// CiliumEndpoints are local-cluster objects, so a remote node with the same
// name or address can never be substituted. This is a name projection; Pod
// incarnation authorization stays with the strict CEP and membership checks.
type nativeNodeNames struct {
	db      *statedb.DB
	nodes   statedb.Table[*node.Node]
	cluster cmtypes.ClusterInfo
}

func newNativeNodeNames(db *statedb.DB, nodes statedb.Table[*node.Node], cluster cmtypes.ClusterInfo) (*nativeNodeNames, error) {
	if db == nil || nodes == nil || cluster.Name == "" || cluster.ID == 0 {
		return nil, fmt.Errorf("native Kubernetes node discovery is unavailable")
	}
	return &nativeNodeNames{db: db, nodes: nodes, cluster: cluster}, nil
}

// snapshot indexes every address of every local-cluster node under one read.
// NodeByAddress indexes underlay addresses with cluster zero, so it is not a
// substitute for filtering Cluster and ClusterID explicitly here.
func (r *nativeNodeNames) snapshot() (map[netip.Addr]string, map[netip.Addr]bool, <-chan struct{}, error) {
	txn := r.db.ReadTxn()
	if ready, _ := r.nodes.Initialized(txn); !ready {
		return nil, nil, nil, wrapValidationError(errInvalidWorkloadData, "native Kubernetes node discovery has not synchronized")
	}
	rows, watch := r.nodes.AllWatch(txn)
	byAddress := make(map[netip.Addr]string)
	ambiguous := make(map[netip.Addr]bool)
	for n := range rows {
		if n == nil || n.Cluster != r.cluster.Name || n.ClusterID != r.cluster.ID {
			continue
		}
		for _, address := range n.IPAddresses {
			ip := address.IP.Addr.Unmap()
			if !ip.IsValid() {
				continue
			}
			if previous, found := byAddress[ip]; found && previous != n.Name {
				ambiguous[ip] = true
			}
			byAddress[ip] = n.Name
		}
	}
	return byAddress, ambiguous, watch, nil
}

func (r *nativeNodeNames) lookup(byAddress map[netip.Addr]string, ambiguous map[netip.Addr]bool, ip netip.Addr) (string, error) {
	ip = ip.Unmap()
	name := byAddress[ip]
	switch {
	case ambiguous[ip]:
		return "", wrapValidationError(errInvalidWorkloadData, "node address %s maps to more than one Kubernetes node in cluster %q", ip, r.cluster.Name)
	case name == "":
		return "", wrapValidationError(errInvalidWorkloadData, "no Kubernetes node name for node address %s in cluster %q", ip, r.cluster.Name)
	}
	return name, nil
}

func (r *nativeNodeNames) bind(events EndpointEventCollection) (EndpointEventCollection, map[netip.Addr]string, <-chan struct{}, error) {
	byAddress, ambiguous, watch, err := r.snapshot()
	if err != nil {
		return nil, nil, nil, err
	}
	bound := make(map[netip.Addr]string)
	result := make(EndpointEventCollection, 0, len(events))
	for i, event := range events {
		if event == nil {
			return nil, nil, nil, wrapValidationError(errInvalidWorkloadData, "workload event %d is nil", i)
		}
		if event.Err != nil || event.Type == REMOVED {
			// A source rejection is reported, and fails the batch, in the
			// strict converter. A removal names only the original Pod UID;
			// its node may be gone.
			result = append(result, event)
			continue
		}
		if event.Type != CREATE || event.CiliumEndpoint == nil || event.Networking == nil {
			return nil, nil, nil, wrapValidationError(errInvalidWorkloadData, "workload event %d has no endpoint networking", i)
		}
		ip, err := netip.ParseAddr(event.Networking.NodeIP)
		if err != nil {
			return nil, nil, nil, wrapValidationError(errInvalidWorkloadData, "invalid node address %q", event.Networking.NodeIP)
		}
		name, err := r.lookup(byAddress, ambiguous, ip)
		if err != nil {
			return nil, nil, nil, err
		}
		copy := *event
		copy.NodeName = name
		result = append(result, &copy)
		bound[ip.Unmap()] = name
	}
	return result, bound, watch, nil
}

func (r *nativeNodeNames) verify(bound map[netip.Addr]string) (<-chan struct{}, error) {
	byAddress, ambiguous, watch, err := r.snapshot()
	if err != nil {
		return nil, err
	}
	for ip, want := range bound {
		got, err := r.lookup(byAddress, ambiguous, ip)
		if err != nil {
			return nil, err
		}
		if got != want {
			return nil, wrapValidationError(errInvalidWorkloadData, "Kubernetes node for address %s changed from %q to %q", ip, want, got)
		}
	}
	return watch, nil
}

// bindNodeNames is the common boundary for initial replay, CEP/CES updates and
// namespace enrollment. It records what this stream has published so a later
// node-only change (with no endpoint event) still invalidates the stream.
func (sp *StreamProcessor) bindNodeNames(collection EndpointEventCollection) (EndpointEventCollection, error) {
	if sp.nodeNames == nil {
		return nil, wrapValidationError(errInvalidWorkloadData, "Kubernetes node discovery is not configured")
	}
	bound, pairs, watch, err := sp.nodeNames.bind(collection)
	if err != nil {
		return nil, err
	}
	if sp.boundNodeNames == nil {
		sp.boundNodeNames = make(map[netip.Addr]string)
	}
	for ip, name := range pairs {
		if previous, found := sp.boundNodeNames[ip]; found && previous != name {
			return nil, wrapValidationError(errInvalidWorkloadData, "node address %s was published as %q and is now %q", ip, previous, name)
		}
	}
	maps.Copy(sp.boundNodeNames, pairs)
	sp.nodeNameWatch = watch
	return bound, nil
}

// revalidateNodeNames runs when the native node table changes. Unchanged
// bindings re-arm the watch; any change ends the stream so ztunnel receives a
// complete fresh snapshot instead of keeping a stale node binding.
func (sp *StreamProcessor) revalidateNodeNames() error {
	watch, err := sp.nodeNames.verify(sp.boundNodeNames)
	if err != nil {
		sp.log.Warn("Closing ztunnel xDS stream after a Kubernetes node binding changed",
			logStage, "xds-node-binding",
			logfields.Error, err)
		return fmt.Errorf("Kubernetes node binding changed: %w", err)
	}
	sp.nodeNameWatch = watch
	return nil
}

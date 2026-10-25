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

// nodeBinding is the node address and Kubernetes Node name published for one
// workload (keyed by its immutable Pod UID).
type nodeBinding struct {
	address netip.Addr
	name    string
}

// nodeNameResolver binds the Kubernetes Node metadata.name of each workload's
// node into an Address batch. ztunnel compares Workload.Node with its own
// NODE_NAME (spec.nodeName), so the value is the API Node name, never an IP.
type nodeNameResolver interface {
	// bind returns copies of the CREATE events with NodeName set, the
	// per-Pod-UID bindings it created and the Pod UIDs of REMOVED events.
	bind(EndpointEventCollection) (EndpointEventCollection, map[string]nodeBinding, []string, error)
	// verify re-reads every binding in one read. It fails if any binding
	// changed, disappeared or became ambiguous, and returns the watch of that
	// same read.
	verify(map[string]nodeBinding) (<-chan struct{}, error)
	// localNames returns the Kubernetes Node names of the local cluster from
	// one read of the native table, and that read's watch.
	localNames() (map[string]bool, <-chan struct{}, error)
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

func (r *nativeNodeNames) localNames() (map[string]bool, <-chan struct{}, error) {
	byAddress, _, watch, err := r.snapshot()
	if err != nil {
		return nil, nil, err
	}
	names := make(map[string]bool, len(byAddress))
	for _, name := range byAddress {
		names[name] = true
	}
	return names, watch, nil
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

func (r *nativeNodeNames) bind(events EndpointEventCollection) (EndpointEventCollection, map[string]nodeBinding, []string, error) {
	byAddress, ambiguous, _, err := r.snapshot()
	if err != nil {
		return nil, nil, nil, err
	}
	created := make(map[string]nodeBinding)
	var removed []string
	result := make(EndpointEventCollection, 0, len(events))
	for i, event := range events {
		if event == nil {
			return nil, nil, nil, wrapValidationError(errInvalidWorkloadData, "workload event %d is nil", i)
		}
		if event.Err != nil {
			// A source rejection is reported, and fails the batch, in the
			// strict converter.
			result = append(result, event)
			continue
		}
		if event.Type == REMOVED {
			// A removal names only the original Pod UID; its node may be gone.
			if uid := event.getPodUID(); uid != "" {
				removed = append(removed, uid)
			}
			result = append(result, event)
			continue
		}
		if event.Type != CREATE || event.CiliumEndpoint == nil || event.Networking == nil {
			return nil, nil, nil, wrapValidationError(errInvalidWorkloadData, "workload event %d has no endpoint networking", i)
		}
		uid := event.getPodUID()
		if uid == "" {
			return nil, nil, nil, wrapValidationError(errInvalidWorkloadData, "workload event %d has no Pod UID", i)
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
		created[uid] = nodeBinding{address: ip.Unmap(), name: name}
	}
	return result, created, removed, nil
}

func (r *nativeNodeNames) verify(bindings map[string]nodeBinding) (<-chan struct{}, error) {
	byAddress, ambiguous, watch, err := r.snapshot()
	if err != nil {
		return nil, err
	}
	for _, b := range bindings {
		got, err := r.lookup(byAddress, ambiguous, b.address)
		if err != nil {
			return nil, err
		}
		if got != b.name {
			return nil, wrapValidationError(errInvalidWorkloadData, "Kubernetes node for address %s changed from %q to %q", b.address, b.name, got)
		}
	}
	return watch, nil
}

// bindNodeNames is the common boundary for initial replay, CEP/CES updates and
// namespace enrollment. It stages the stream's complete retained binding set
// (earlier published workloads minus removals plus this batch) and verifies
// ALL of it in one read. The watch comes from that same read, so a node change
// that closed the previous watch can never be hidden by an unrelated batch.
// The staged set is committed only after the response is sent.
func (sp *StreamProcessor) bindNodeNames(collection EndpointEventCollection) (EndpointEventCollection, error) {
	if sp.nodeNames == nil {
		return nil, wrapValidationError(errInvalidWorkloadData, "Kubernetes node discovery is not configured")
	}
	bound, created, removed, err := sp.nodeNames.bind(collection)
	if err != nil {
		return nil, err
	}
	retained := maps.Clone(sp.boundNodeNames)
	if retained == nil {
		retained = make(map[string]nodeBinding)
	}
	for _, uid := range removed {
		delete(retained, uid)
	}
	maps.Copy(retained, created)
	watch, err := sp.nodeNames.verify(retained)
	if err != nil {
		return nil, err
	}
	sp.pendingNodeNames = retained
	sp.pendingNodeNameWatch = watch
	return bound, nil
}

// checkNodeNamesBeforeSend re-verifies the staged bindings immediately before
// publication, so a change observed during conversion is not published. This
// is request-time consistency against the node table, not an API transaction.
func (sp *StreamProcessor) checkNodeNamesBeforeSend() error {
	if sp.pendingNodeNames == nil {
		return wrapValidationError(errInvalidDiscoveryState, "workload Address response has no staged Kubernetes node binding")
	}
	watch, err := sp.nodeNames.verify(sp.pendingNodeNames)
	if err != nil {
		return err
	}
	sp.pendingNodeNameWatch = watch
	return nil
}

// commitNodeNames records the bindings of a response that was sent.
func (sp *StreamProcessor) commitNodeNames() {
	sp.boundNodeNames = sp.pendingNodeNames
	sp.nodeNameWatch = sp.pendingNodeNameWatch
	sp.pendingNodeNames = nil
	sp.pendingNodeNameWatch = nil
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

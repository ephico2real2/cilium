// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"crypto/sha256"
	"fmt"
	"maps"
	"slices"
	"strings"

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
	"github.com/cilium/cilium/pkg/ztunnel/pb/security"
	"github.com/cilium/cilium/pkg/ztunnel/table"
)

const effectiveQuarantinePrefix = "cilium_l4_quarantine_"
const logQuarantineNamespaceUID = "namespaceUID"

// Namespace and Pod UIDs bind the resource to one incarnation. This resource
// contains a wildcard DENY. It is an explicit native quarantine, not a compiler
// completion or a surrogate membership/policy ACK.
func quarantineAuthorization(namespace, namespaceUID, podUID string) (*security.Authorization, error) {
	if namespace == "" {
		return nil, fmt.Errorf("quarantine requires an exact namespace and Pod incarnation")
	}
	for _, raw := range []string{namespaceUID, podUID} {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || id.String() != raw {
			return nil, fmt.Errorf("quarantine requires canonical namespace and Pod incarnation UIDs")
		}
	}
	sum := sha256.Sum256([]byte(namespaceUID + "\x00" + podUID))
	return &security.Authorization{Name: fmt.Sprintf("%s%x", effectiveQuarantinePrefix, sum[:]), Namespace: namespace,
		Scope: security.Scope_WORKLOAD_SELECTOR, Action: security.Action_DENY, Rules: []*security.Rule{{}}}, nil
}

func (sp *StreamProcessor) bindEffectiveQuarantine(response *v3.DeltaDiscoveryResponse) error {
	if response == nil || sp.db == nil || sp.enrolledNamespaceTable == nil {
		return fmt.Errorf("native quarantine requires current namespace enrollment inventory")
	}
	if len(response.Resources) > maxZtunnelQuarantines {
		return fmt.Errorf("quarantine response exceeds bounded size")
	}
	if sp.quarantineResources == nil {
		sp.quarantineResources = make(map[string]string)
	}
	next := make(map[string]string, len(sp.quarantineResources)+len(response.Resources))
	maps.Copy(next, sp.quarantineResources)
	var removals []string
	for _, name := range response.RemovedResources {
		if key, ok := next[name]; ok {
			removals = append(removals, key)
			delete(next, name)
		}
	}
	upserts := make(map[string]*security.Authorization, len(response.Resources))
	for _, resource := range response.Resources {
		if resource == nil || resource.Resource == nil {
			return fmt.Errorf("missing workload Address during quarantine binding")
		}
		address := new(pb.Address)
		if err := resource.Resource.UnmarshalTo(address); err != nil {
			return fmt.Errorf("decode quarantine workload: %w", err)
		}
		workload := address.GetWorkload()
		if workload == nil || workload.Uid == "" {
			return fmt.Errorf("quarantine target is not a workload incarnation")
		}
		namespace, _, found := sp.enrolledNamespaceTable.Get(sp.db.ReadTxn(), table.EnrolledNamespaceByName(workload.Namespace))
		if !found || namespace.UID == "" {
			return fmt.Errorf("current namespace UID unavailable for policy quarantine")
		}
		policy, err := quarantineAuthorization(workload.Namespace, namespace.UID, workload.Uid)
		if err != nil {
			return err
		}
		key := policy.Namespace + "/" + policy.Name
		upserts[key] = policy
		next[resource.Name] = key
		workload.AuthorizationPolicies = []string{key}
		// Marshal into the existing native Address resource. No CMTC or mock
		// address store is introduced. An absent policy on arrival denies.
		encoded, err := proto.Marshal(address)
		if err != nil {
			return err
		}
		resource.Resource.Value = encoded
		sp.log.Info("Bound native workload policy quarantine",
			logfields.Event, "effective-policy-quarantine",
			logStage, "policy-workload-binding",
			logfields.Resource, key,
			logfields.PodUID, workload.Uid,
			"namespaceUid", namespace.UID)
	}
	// Desired Authorization publication is atomic. The Address and policy ACKs
	// remain independent, and missing required policy cannot authorize traffic.
	if len(next) > maxZtunnelQuarantines {
		return fmt.Errorf("active quarantine inventory exceeds bounded size")
	}
	if err := sp.authorizations.applyQuarantines(upserts, removals); err != nil {
		return err
	}
	sp.quarantineResources = next
	return nil
}

const maxZtunnelQuarantines = 4096

// Bound the shared cache, including orphaned resources from disconnected streams.
// At capacity, refuse new bindings. Never evict another stream's live fence.
func (p *AuthorizationPolicies) applyQuarantines(upserts map[string]*security.Authorization, removals []string) error {
	p.quarantineMu.Lock()
	defer p.quarantineMu.Unlock()
	names := make(map[string]bool)
	current := p.cache.GetResources(xdsTypeURLAuthorization, 0, nil)
	if current != nil {
		for _, resource := range current.VersionedResources {
			if strings.Contains(resource.Name, "/"+effectiveQuarantinePrefix) {
				names[resource.Name] = true
			}
		}
	}
	for _, key := range removals {
		delete(names, key)
	}
	for key := range upserts {
		names[key] = true
	}
	if len(names) > maxZtunnelQuarantines {
		return fmt.Errorf("shared quarantine cache is full; native resync required")
	}
	slices.Sort(removals)
	if _, _, err := p.Apply(upserts, removals); err != nil {
		return fmt.Errorf("publish native quarantine policy: %w", err)
	}
	return nil
}

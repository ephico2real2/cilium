// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

// EndpointEventCollection holds one or more EndpointEvent.
//
// This is useful for transforming sets of models to and from EndpointEvent
// representation.
type EndpointEventCollection []*EndpointEvent

// AppendEndpoints will add the provided endpoint.Endpoint(s) to the collection,
// transforming each into an EndpointEvent.
//
// Each endpoint.Endpoint in the eps slice will be associated with the provided
// EndpointEventType.
func (c *EndpointEventCollection) AppendEndpoints(t EndpointEventType, eps []*types.CiliumEndpoint) {
	for _, ep := range eps {
		*c = append(*c, &EndpointEvent{Type: t, CiliumEndpoint: ep})
	}
}

// EmitTo sends all events in the collection to the provided channel.
// Returns early if the context is canceled.
func (c EndpointEventCollection) EmitTo(ctx context.Context, ch chan<- *EndpointEvent) {
	for _, event := range c {
		select {
		case ch <- event:
		case <-ctx.Done():
			return
		}
	}
}

// ToDeltaDiscoveryResponse will create a singular xDS DeltaDiscoveryResponse
// given a EndpointEventCollection.
//
// Per the DeltaDiscoveryResponse API, CREATE event types are transformed into
// xDS Workload objects and embedded into an xDS Address type.
//
// REMOVE events simple appends the unique ID of the Endpoint in the RemovedResources
// field in the DeltaDiscoveryResponse.
//
// The returned DeltaDiscoveryResponse can be sent directly on a DeltaAggregatedResources
// stream.
func (c EndpointEventCollection) ToDeltaDiscoveryResponse() *v3.DeltaDiscoveryResponse {
	return c.toDeltaDiscoveryResponse("", "")
}

// toDeltaDiscoveryResponse binds discovery identities to the configured issuer domain.
func (c EndpointEventCollection) toDeltaDiscoveryResponse(trustDomain, clusterName string) *v3.DeltaDiscoveryResponse {
	createResources := make([]*v3.Resource, 0)
	removedNames := make([]string, 0)
	for _, event := range c {
		switch event.Type {
		case CREATE:
			address, err := event.ToXDSAddress()
			if err != nil {
				continue
			}

			address.GetWorkload().TrustDomain = trustDomain
			address.GetWorkload().ClusterId = clusterName

			anyPBAddr, err := anypb.New(address)
			if err != nil {
				continue
			}

			// ztunnel uses a very stripped down representation of a Resource
			// see: https://github.com/istio/ztunnel/blob/58cf2a0f943ffc23c32d889018428ddfa6175144/src/xds/client.rs#L773
			res := &v3.Resource{
				Name:     event.getPodUID(),
				Resource: anyPBAddr,
			}

			createResources = append(createResources, res)
		case REMOVED:
			removedNames = append(removedNames, event.getPodUID())
		}
	}

	// create nonce from UUID
	nonce := uuid.New().String()
	resp := &v3.DeltaDiscoveryResponse{
		TypeUrl:          xdsTypeURLAddress,
		Resources:        createResources,
		RemovedResources: removedNames,
		Nonce:            nonce,
	}

	return resp
}

// toValidatedDeltaDiscoveryResponse converts a complete strict workload
// snapshot or event batch. Unlike the compatibility converter above, it never
// silently drops an invalid retained workload: strict mode must not publish an
// incomplete view of which Pods require HBONE.
func (c EndpointEventCollection) toValidatedDeltaDiscoveryResponse(trustDomain, clusterName string) (*v3.DeltaDiscoveryResponse, error) {
	if strings.TrimSpace(trustDomain) == "" {
		return nil, wrapValidationError(errInvalidWorkloadData, "strict workload discovery requires a trust domain")
	}
	if strings.TrimSpace(clusterName) == "" {
		return nil, wrapValidationError(errInvalidWorkloadData, "strict workload discovery requires a cluster name")
	}

	resources := make([]*v3.Resource, 0, len(c))
	removedNames := make([]string, 0, len(c))
	seen := make(map[string]EndpointEventType, len(c))
	addressOwners := make(map[netip.Addr]string)
	for i, event := range c {
		if event == nil {
			return nil, wrapValidationError(errInvalidWorkloadData, "strict workload discovery event %d is nil", i)
		}
		uid, err := event.validatedPodUID()
		if err != nil {
			return nil, fmt.Errorf("strict workload discovery event %d: %w", i, err)
		}
		if previous, found := seen[uid]; found {
			return nil, wrapValidationError(errInvalidWorkloadData, "strict workload discovery contains conflicting events for Pod UID %q (%d then %d)", uid, previous, event.Type)
		}
		seen[uid] = event.Type

		switch event.Type {
		case CREATE:
			address, err := event.toValidatedXDSAddress()
			if err != nil {
				return nil, fmt.Errorf("strict workload discovery cannot convert Pod UID %q: %w", uid, err)
			}
			workload := address.GetWorkload()
			workload.TrustDomain = trustDomain
			workload.ClusterId = clusterName
			for _, rawAddress := range workload.Addresses {
				ip, ok := netip.AddrFromSlice(rawAddress)
				if !ok {
					return nil, wrapValidationError(errInvalidWorkloadData, "strict workload discovery has an invalid encoded address for Pod UID %q", uid)
				}
				ip = ip.Unmap()
				if previousUID, exists := addressOwners[ip]; exists && previousUID != uid {
					return nil, wrapValidationError(errInvalidWorkloadData, "strict workload discovery assigns one address to multiple Pod UIDs %q and %q", previousUID, uid)
				}
				addressOwners[ip] = uid
			}

			resource, err := anypb.New(address)
			if err != nil {
				return nil, fmt.Errorf("strict workload discovery cannot encode Pod UID %q: %w", uid, err)
			}
			resources = append(resources, &v3.Resource{Name: uid, Resource: resource})
		case REMOVED:
			removedNames = append(removedNames, uid)
		default:
			return nil, wrapValidationError(errInvalidWorkloadData, "strict workload discovery has unknown event type %d for Pod UID %q", event.Type, uid)
		}
	}

	return &v3.DeltaDiscoveryResponse{
		TypeUrl:          xdsTypeURLAddress,
		Resources:        resources,
		RemovedResources: removedNames,
		Nonce:            uuid.New().String(),
	}, nil
}

// coalesceStrictEndpointEvents collapses a drained incremental batch to the
// last event for each immutable Pod UID. Endpoint source channels may queue
// several legitimate updates before the stream processor runs; emitting more
// than one resource operation for the same UID in a Delta response is
// ambiguous to the client. Initial snapshots do not use this helper: duplicate
// identities in a supposedly complete snapshot remain an error.
func (c EndpointEventCollection) coalesceStrictEndpointEvents() (EndpointEventCollection, error) {
	order := make([]string, 0, len(c))
	latest := make(map[string]*EndpointEvent, len(c))
	for i, event := range c {
		uid, err := event.validatedPodUID()
		if err != nil {
			return nil, fmt.Errorf("strict workload event %d: %w", i, err)
		}
		if event.Type != CREATE && event.Type != REMOVED {
			return nil, wrapValidationError(errInvalidWorkloadData, "strict workload event %d has unknown event type %d for Pod UID %q", i, event.Type, uid)
		}
		if _, exists := latest[uid]; !exists {
			order = append(order, uid)
		}
		latest[uid] = event
	}

	coalesced := make(EndpointEventCollection, 0, len(latest))
	for _, uid := range order {
		coalesced = append(coalesced, latest[uid])
	}
	return coalesced, nil
}

// strictEndpointSourceError creates an event that carries a source-validation
// failure through the existing event channel. Strict converters reject it, so
// a malformed source object can never be represented as an empty snapshot.
func strictEndpointSourceError(err error) *EndpointEvent {
	return &EndpointEvent{Err: err}
}

type EndpointEventType int

const (
	CREATE EndpointEventType = iota
	REMOVED
)

// EndpointEvent is a thin wrapper around an embedded endpoint.Endpoint.
// The wrapper provides an additional EndpointEventType field that represents
// an event type for the embedded Endpoint.
type EndpointEvent struct {
	Type EndpointEventType
	*types.CiliumEndpoint
	Err error
	// NodeName is the Kubernetes Node metadata.name bound from Cilium's native
	// node discovery at the Address response boundary. Networking.NodeIP stays
	// an address and is never used as the node identity.
	NodeName string
}

// getPodUID returns the Pod UID from the CiliumEndpoint's OwnerReferences.
// CiliumEndpoints are owned by Pods, so the Pod UID is available in OwnerReferences.
// This is consistent with the ZDS server which also uses Pod UIDs.
func (e *EndpointEvent) getPodUID() string {
	if e == nil || e.CiliumEndpoint == nil {
		return ""
	}
	for _, ref := range e.OwnerReferences {
		if ref.Kind == "Pod" {
			return string(ref.UID)
		}
	}
	return ""
}

func (e *EndpointEvent) validatedPodUID() (string, error) {
	if e == nil {
		return "", wrapValidationError(errInvalidWorkloadData, "missing CiliumEndpoint")
	}
	if e.Err != nil {
		return "", fmt.Errorf("endpoint source rejected workload data: %w", e.Err)
	}
	if e.CiliumEndpoint == nil {
		return "", wrapValidationError(errInvalidWorkloadData, "missing CiliumEndpoint")
	}
	var uid string
	for _, ref := range e.OwnerReferences {
		if ref.Kind != "Pod" {
			continue
		}
		if ref.UID == "" {
			return "", wrapValidationError(errInvalidWorkloadData, "Pod owner reference has an empty UID")
		}
		if uid != "" {
			return "", wrapValidationError(errInvalidWorkloadData, "multiple Pod owner references")
		}
		uid = string(ref.UID)
	}
	if uid == "" {
		return "", wrapValidationError(errInvalidWorkloadData, "missing Pod owner reference")
	}
	return uid, nil
}

// ToXDSAddress transforms the embedded Endpoint into a XDS Address capable of
// being used in a DeltaDiscoveryResponse.
//
// This transformation is heavily opinionated for our ZTunnel integration, make
// note of the hard-coded values in the transform.
func (e *EndpointEvent) ToXDSAddress() (*pb.Address, error) {
	if e == nil || e.CiliumEndpoint == nil || e.Name == "" {
		return nil, wrapValidationError(errInvalidWorkloadData, "cannot transform EndpointEvent to XDS Address, missing endpoint information")
	}
	if e.Networking == nil {
		return nil, wrapValidationError(errInvalidWorkloadData, "cannot transform EndpointEvent to XDS Address, missing networking information")
	}
	if e.NodeName == "" {
		return nil, wrapValidationError(errInvalidWorkloadData, "cannot transform EndpointEvent to XDS Address, missing Kubernetes node name")
	}

	ipAddresses := make([][]byte, 0)

	// TODO(hemanthmalla): Add strict address validation for non-mTLS mode.
	for _, addr := range e.Networking.Addressing {
		if addr == nil {
			continue
		}
		if addr.IPV4 != "" {
			if ipv4, err := netip.ParseAddr(addr.IPV4); err == nil && ipv4.IsValid() {
				ipAddresses = append(ipAddresses, ipv4.AsSlice())
			}
		}
		if addr.IPV6 != "" {
			if ipv6, err := netip.ParseAddr(addr.IPV6); err == nil && ipv6.IsValid() {
				ipAddresses = append(ipAddresses, ipv6.AsSlice())
			}
		}
	}

	w := &pb.Workload{
		Uid: e.getPodUID(),
		// Kubernetes Node name; ztunnel matches it with its own NODE_NAME.
		Node:           e.NodeName,
		Name:           e.Name,
		Namespace:      e.Namespace,
		ServiceAccount: e.ServiceAccount,
		TunnelProtocol: pb.TunnelProtocol_HBONE,
		Addresses:      ipAddresses,
	}

	address := &pb.Address{
		Type: &pb.Address_Workload{
			Workload: w,
		},
	}

	return address, nil
}

func (e *EndpointEvent) toValidatedXDSAddress() (*pb.Address, error) {
	if e == nil || e.CiliumEndpoint == nil {
		return nil, wrapValidationError(errInvalidWorkloadData, "missing CiliumEndpoint")
	}
	if e.Name == "" || e.Namespace == "" {
		return nil, wrapValidationError(errInvalidWorkloadData, "missing endpoint name or namespace")
	}
	if e.ServiceAccount == "" {
		return nil, wrapValidationError(errInvalidWorkloadData, "missing service account")
	}
	if _, err := e.validatedPodUID(); err != nil {
		return nil, err
	}
	if e.Networking == nil {
		return nil, wrapValidationError(errInvalidWorkloadData, "missing networking information")
	}
	if e.Networking.NodeIP == "" {
		return nil, wrapValidationError(errInvalidWorkloadData, "missing node address")
	}
	nodeIP, err := netip.ParseAddr(e.Networking.NodeIP)
	if err != nil || !strictUnicastAddress(nodeIP) {
		return nil, wrapValidationError(errInvalidWorkloadData, "invalid node address %q", e.Networking.NodeIP)
	}

	var addresses int
	seenAddresses := make(map[netip.Addr]struct{}, len(e.Networking.Addressing)*2)
	for _, address := range e.Networking.Addressing {
		if address == nil {
			return nil, wrapValidationError(errInvalidWorkloadData, "nil workload address")
		}
		for _, item := range []struct {
			value string
			isV4  bool
		}{
			{value: address.IPV4, isV4: true},
			{value: address.IPV6},
		} {
			if item.value == "" {
				continue
			}
			ip, err := netip.ParseAddr(item.value)
			if err != nil || (item.isV4 && !ip.Is4()) || (!item.isV4 && (!ip.Is6() || ip.Is4In6())) || !strictUnicastAddress(ip) {
				family := "IPv6"
				if item.isV4 {
					family = "IPv4"
				}
				return nil, wrapValidationError(errInvalidWorkloadData, "invalid %s address %q", family, item.value)
			}
			canonical := ip.Unmap()
			if _, exists := seenAddresses[canonical]; exists {
				return nil, wrapValidationError(errInvalidWorkloadData, "duplicate workload address %q", item.value)
			}
			seenAddresses[canonical] = struct{}{}
			addresses++
		}
	}
	if addresses == 0 {
		return nil, wrapValidationError(errInvalidWorkloadData, "no workload IP addresses")
	}
	return e.ToXDSAddress()
}

func strictUnicastAddress(ip netip.Addr) bool {
	return ip.IsValid() && !ip.Is4In6() && ip.Zone() == "" && ip.IsGlobalUnicast() &&
		!ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
}

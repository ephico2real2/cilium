// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"errors"
)

var errIncompleteZtunnelPolicyReachabilityIdentity = errors.New("incomplete native policy-map reachability identity")

// ZtunnelPolicyMapReachabilityIdentity binds one point-in-time kernel path
// inspection to the endpoint and native policy-map observation that requested
// it. It is not a capture, authorization, TLS, freshness, or Protected claim.
type ZtunnelPolicyMapReachabilityIdentity struct {
	EndpointID         uint16
	NamespaceUID       string
	PodUID             string
	NetNSPath          string
	NetNSCookie        uint64
	Interface          string
	IfIndex            int
	PolicyMapID        uint32
	PolicyDigest       string
	DatapathConfigHash string
	IPv4               bool
	IPv6               bool
	RequireToContainer bool
}

// ZtunnelPolicyProgramReference describes a program observed in a live Cilium
// ProgramArray. Program names and tags are diagnostic identities; callers
// must not treat them as cryptographic provenance.
type ZtunnelPolicyProgramReference struct {
	Index     uint32
	ProgramID uint32
	Name      string
	Tag       string
}

// ZtunnelPolicyMapReachabilityObservation records the kernel object IDs and
// exact tail-call targets checked for the supported endpoint profile. Success
// proves only that the observed Cilium program path reaches the observed native
// policy map at the time of the check.
type ZtunnelPolicyMapReachabilityObservation struct {
	Identity                       ZtunnelPolicyMapReachabilityIdentity
	PolicyMapID                    uint32
	CallsMapID                     uint32
	PolicyCallMapID                uint32
	FromContainerProgramID         uint32
	FromContainerLinkID            uint32
	FromContainerAttachSetRevision uint64
	ToContainerProgramID           uint32
	ToContainerLinkID              uint32
	ToContainerAttachSetRevision   uint64
	EndpointPolicyProgramID        uint32
	IngressPrograms                []ZtunnelPolicyProgramReference
	EgressPrograms                 []ZtunnelPolicyProgramReference
}

// ZtunnelPolicyMapReachabilityVerifier is an optional Linux loader extension.
// Implementations must return an error when the current kernel path cannot be
// inspected exactly; there is no best-effort success mode.
type ZtunnelPolicyMapReachabilityVerifier interface {
	VerifyZtunnelPolicyMapReachability(context.Context, ZtunnelPolicyMapReachabilityIdentity) (ZtunnelPolicyMapReachabilityObservation, error)
}

// Validate rejects incomplete or noncanonical endpoint identity before any
// kernel query. PolicyMapID must be an actual nonzero kernel ID.
func (i ZtunnelPolicyMapReachabilityIdentity) Validate() error {
	if i.EndpointID == 0 || i.NamespaceUID == "" || i.PodUID == "" ||
		i.NetNSPath == "" || i.NetNSCookie == 0 || i.Interface == "" || i.IfIndex <= 0 ||
		i.PolicyMapID == 0 || i.PolicyDigest == "" || i.DatapathConfigHash == "" ||
		(!i.IPv4 && !i.IPv6) || !i.RequireToContainer {
		return errIncompleteZtunnelPolicyReachabilityIdentity
	}
	return nil
}

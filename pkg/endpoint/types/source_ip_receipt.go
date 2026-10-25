// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"net/netip"
)

// SourceIPDatapathIdentity binds an observed source-IP guard attachment to one
// live endpoint incarnation and the exact endpoint BPF configuration that was
// loaded. It is process-local evidence; it is never persisted or restored.
type SourceIPDatapathIdentity struct {
	EndpointID      uint16
	NamespaceUID    string
	PodUID          string
	NetNSPath       string
	NetNSCookie     uint64
	Interface       string
	IfIndex         int
	ConfigHash      string
	IPv4            netip.Addr
	IPv6            netip.Addr
	SourceIPEnabled bool
	ZtunnelRequired bool
}

// SourceIPDatapathObservation describes the TCX ingress program that the
// kernel reported attached when VerifySourceIPDatapath completed. This proves
// only the configured source-IP check attachment. It does not prove traffic
// capture, policy authorization, TLS, or a complete workload-mTLS path.
type SourceIPDatapathObservation struct {
	Identity          SourceIPDatapathIdentity
	ProgramID         uint32
	ProgramTag        string
	LinkID            uint32
	AttachSetRevision uint64
	ProgramMapIDsHash string
	ConfigMapID       uint32
	ConfigMapName     string
	ConfigMapHash     string
	SIPConfigOffset   uint32
	SIPConfigSize     uint32
	SIPConfigEnabled  bool
	ConfigMapReadOnly bool
	ConfigMapFrozen   bool
}

// SourceIPDatapathVerifier is an optional extension implemented by the native
// Linux loader. Keeping this out of Loader avoids requiring test/fake loaders
// to claim support they do not provide.
type SourceIPDatapathVerifier interface {
	VerifySourceIPDatapath(context.Context, SourceIPDatapathIdentity) (SourceIPDatapathObservation, error)
}

// SourceIPDatapathIdentityProvider exposes immutable fields cached while the
// endpoint lock is held during datapath regeneration.
type SourceIPDatapathIdentityProvider interface {
	SourceIPDatapathIdentity() SourceIPDatapathIdentity
}

// ZtunnelQuarantineProvider exposes the independent datapath hold state while
// a cached endpoint is translated into BPF configuration. It must not be
// derived from SourceIPDatapathIdentity.ZtunnelRequired.
type ZtunnelQuarantineProvider interface {
	IsZtunnelQuarantined() bool
}

// ZtunnelMeshOnlyProvider exposes the sticky Required obligation as the
// load-time ztunnel_required config: such a program never forwards as an
// ordinary endpoint, even if its own endpoint-map entry is missing.
type ZtunnelMeshOnlyProvider interface {
	IsZtunnelMeshOnly() bool
}

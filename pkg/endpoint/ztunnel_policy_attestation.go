// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"

	"github.com/google/uuid"

	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
)

var ErrZtunnelPolicyMapBusy = errors.New("native policy map observation unavailable while endpoint changes")

// ZtunnelPolicyMapObservation is a bounded current observation of the native
// policy map, NOT a source-IP enforcement, capture, TLS, ACK or authorization
// attestation. All fields are process-local/public metadata; no key material.
// A producer must join the exact tuple/digest to a current kernel loader
// receipt and independently authenticated Registry.Reference before publication.
type ZtunnelPolicyMapObservation struct {
	subject            policy.ZtunnelPolicySubject
	wire               []byte
	wireDigest         string
	nodeName           string
	containerID        string
	interfaceName      string
	datapathConfigHash string
	netNSCookie        uint64
	netNSPath          string
	interfaceIndex     uint32
	policyMapID        uint32
	requireToContainer bool
	digest             string
}

func (o *ZtunnelPolicyMapObservation) Subject() policy.ZtunnelPolicySubject {
	if o == nil {
		return policy.ZtunnelPolicySubject{}
	}
	subject := o.subject
	subject.Addresses = slices.Clone(subject.Addresses)
	return subject
}
func (o *ZtunnelPolicyMapObservation) Wire() []byte {
	if o == nil {
		return nil
	}
	return slices.Clone(o.wire)
}
func (o *ZtunnelPolicyMapObservation) WireDigest() string {
	if o == nil {
		return ""
	}
	return o.wireDigest
}
func (o *ZtunnelPolicyMapObservation) NodeName() string {
	if o == nil {
		return ""
	}
	return o.nodeName
}
func (o *ZtunnelPolicyMapObservation) ContainerID() string {
	if o == nil {
		return ""
	}
	return o.containerID
}
func (o *ZtunnelPolicyMapObservation) NetNSCookie() uint64 {
	if o == nil {
		return 0
	}
	return o.netNSCookie
}
func (o *ZtunnelPolicyMapObservation) NetNSPath() string {
	if o == nil {
		return ""
	}
	return o.netNSPath
}
func (o *ZtunnelPolicyMapObservation) InterfaceIndex() uint32 {
	if o == nil {
		return 0
	}
	return o.interfaceIndex
}
func (o *ZtunnelPolicyMapObservation) KernelPolicyMapID() uint32 {
	if o == nil {
		return 0
	}
	return o.policyMapID
}
func (o *ZtunnelPolicyMapObservation) Digest() string {
	if o == nil {
		return ""
	}
	return o.digest
}

// ReachabilityIdentity converts the endpoint snapshot into the exact inputs
// needed by the loader's live BPF map/program-array inspection. A zero map ID
// (for example, a unit-test fake) is deliberately rejected.
func (o *ZtunnelPolicyMapObservation) ReachabilityIdentity() (endpointtypes.ZtunnelPolicyMapReachabilityIdentity, error) {
	if o == nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityIdentity{}, fmt.Errorf("nil native policy-map observation")
	}
	identity := endpointtypes.ZtunnelPolicyMapReachabilityIdentity{
		EndpointID: uint16(o.subject.EndpointID), NamespaceUID: o.subject.NamespaceUID,
		PodUID: o.subject.PodUID, NetNSPath: o.netNSPath, NetNSCookie: o.netNSCookie,
		Interface: o.interfaceName, IfIndex: int(o.interfaceIndex), PolicyMapID: o.policyMapID,
		PolicyDigest: o.digest, DatapathConfigHash: o.datapathConfigHash,
		RequireToContainer: o.requireToContainer,
	}
	for _, address := range o.subject.Addresses {
		if address.Is4() {
			identity.IPv4 = true
		}
		if address.Is6() {
			identity.IPv6 = true
		}
	}
	if err := identity.Validate(); err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityIdentity{}, err
	}
	return identity, nil
}

// SnapshotZtunnelPolicyMap does not wait behind regeneration or endpoint
// mutations. It compares TWO actual kernel map dumps with current native
// immutable policy snapshots under the established build→endpoint lock order.
// No loader evidence is invented: policy map reachability, actual program
// configuration/SIP enforcement and capture remain separate required inputs.
func (e *Endpoint) SnapshotZtunnelPolicyMap(ctx context.Context) (*ZtunnelPolicyMapObservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.buildMutex.TryLock() {
		return nil, ErrZtunnelPolicyMapBusy
	}
	// TryLock is inherited by the lockdebug wrapper and does not initialize its
	// timing field. Release through the real underlying tracker without timing.
	defer e.buildMutex.UnlockIgnoreTime()
	if !e.mutex.TryRLock() {
		return nil, ErrZtunnelPolicyMapBusy
	}
	defer e.runlock()
	if e.IsDisconnecting() {
		return nil, ErrNotAlive
	}
	if e.state != StateReady || e.realizedPolicy == nil || e.realizedPolicy != e.desiredPolicy ||
		e.policyRevision == 0 || e.desiredPolicyRevision != e.policyRevision || e.SecurityIdentity == nil || e.policyMap == nil {
		return nil, fmt.Errorf("current realized endpoint policy and native map are unavailable")
	}
	if e.isHost || e.isIngress || e.isSecondaryInterface ||
		e.isPropertyLocked(endpointtypes.PropertyFakeEndpoint) ||
		e.isPropertyLocked(endpointtypes.PropertyAtHostNS) ||
		e.isPropertyLocked(endpointtypes.PropertyWithouteBPFDatapath) ||
		e.isPropertyLocked(endpointtypes.PropertySkipBPFPolicy) ||
		e.isPropertyLocked(endpointtypes.PropertySkipBPFRegeneration) {
		return nil, fmt.Errorf("native policy export supports only primary Kubernetes Pod datapaths")
	}
	namespaceUID := e.GetK8sNamespaceUID()
	pod := e.GetPod()
	podUID := e.GetK8sPodUID()
	containerID := e.GetContainerID()
	if e.ID == 0 || e.ifIndex <= 0 || e.NetNsCookie == 0 || pod == nil || containerID == "" || len(containerID) > 256 ||
		e.K8sUID == "" || e.K8sUID != podUID || !filepath.IsAbs(e.containerNetnsPath) ||
		filepath.Clean(e.containerNetnsPath) != e.containerNetnsPath || len(e.containerNetnsPath) > 4096 ||
		string(pod.UID) != podUID || pod.Namespace != e.K8sNamespace || pod.Name != e.K8sPodName ||
		pod.Spec.HostNetwork || pod.Spec.ServiceAccountName == "" || pod.Spec.NodeName == "" {
		return nil, fmt.Errorf("native Kubernetes endpoint/sandbox incarnation is incomplete")
	}
	for _, value := range []string{namespaceUID, podUID} {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return nil, fmt.Errorf("canonical namespace and Pod UIDs required")
		}
	}
	snapshot, err := e.realizedPolicy.SnapshotZtunnelL4(e.policyRevision)
	if err != nil {
		return nil, err
	}
	owner := snapshot.Owner()
	if e.SecurityIdentity.ID.IsReservedIdentity() || e.SecurityIdentity.ID.HasLocalScope() ||
		e.SecurityIdentity.ID.ClusterID(owner) != owner.ID {
		return nil, fmt.Errorf("native workload identity is not bound to policy owner cluster")
	}
	wire, wireDigest, err := snapshot.MarshalNative()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	first, err := e.policyMap.DumpToMapStateMap()
	if err != nil {
		return nil, fmt.Errorf("first native policy map dump: %w", err)
	}
	if err := snapshot.VerifyNativeMap(first); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	second, err := e.policyMap.DumpToMapStateMap()
	if err != nil {
		return nil, fmt.Errorf("second native policy map dump: %w", err)
	}
	if err := snapshot.VerifyNativeMap(second); err != nil {
		return nil, err
	}
	// Selector notifications can queue without the endpoint lock. A fresh
	// snapshot refuses pending changes even when the realized revision matches.
	current, err := e.realizedPolicy.SnapshotZtunnelL4(e.policyRevision)
	if err != nil {
		return nil, err
	}
	if current.Digest() != snapshot.Digest() || current.Owner() != owner ||
		namespaceUID != e.GetK8sNamespaceUID() || pod != e.GetPod() ||
		podUID != e.GetK8sPodUID() || containerID != e.GetContainerID() {
		return nil, fmt.Errorf("native policy or Kubernetes incarnation changed during map observation")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	policyMapID, err := e.policyMap.KernelMapID()
	if err != nil && !errors.Is(err, policymap.ErrKernelMapIDUnavailable) {
		return nil, fmt.Errorf("read native endpoint policy map kernel ID: %w", err)
	}
	if errors.Is(err, policymap.ErrKernelMapIDUnavailable) {
		// Keep in-memory policy tests usable, but never allow this observation to
		// become a reachability receipt: ReachabilityIdentity rejects ID zero.
		policyMapID = 0
	}
	var addresses []netip.Addr
	families := map[bool]bool{}
	for _, ip := range []netip.Addr{e.IPv4, e.IPv6} {
		if !ip.IsValid() {
			continue
		}
		if ip.Is4In6() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || families[ip.Is4()] {
			return nil, fmt.Errorf("noncanonical native workload addresses")
		}
		families[ip.Is4()] = true
		addresses = append(addresses, ip)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("native workload address unavailable")
	}
	subject := policy.ZtunnelPolicySubject{
		ClusterID: owner.ID, ClusterName: owner.Name, EndpointID: e.ID,
		Namespace: e.K8sNamespace, NamespaceUID: namespaceUID, PodUID: podUID,
		ServiceAccount: pod.Spec.ServiceAccountName, NumericIdentity: e.SecurityIdentity.ID,
		Addresses: addresses, Policy: snapshot,
		// TrustDomain deliberately absent. An issuer-profile producer/consumer
		// must supply the independently approved cluster/domain binding later.
	}
	out := &ZtunnelPolicyMapObservation{subject: subject, wire: wire, wireDigest: wireDigest,
		nodeName: pod.Spec.NodeName, containerID: containerID,
		interfaceName: e.ifName, datapathConfigHash: e.bpfHeaderfileHash,
		netNSCookie: e.NetNsCookie, netNSPath: e.containerNetnsPath, interfaceIndex: uint32(e.ifIndex),
		policyMapID: policyMapID, requireToContainer: e.RequireEgressProg()}
	h := sha256.New()
	put := func(value string) {
		encoded := binary.BigEndian.AppendUint32(nil, uint32(len(value)))
		_, _ = h.Write(encoded)
		_, _ = h.Write([]byte(value))
	}
	// Fixed domain separator and length-prefixed fields avoid concatenation
	// ambiguity. This digest is content identity, not an authentication tag.
	put("cilium-native-policy-map-observation-v1")
	for _, value := range []string{owner.Name, fmt.Sprint(owner.ID), fmt.Sprint(owner.MaxConnectedClusters),
		fmt.Sprint(e.ID), e.K8sNamespace, namespaceUID, podUID, pod.Spec.ServiceAccountName,
		fmt.Sprint(e.SecurityIdentity.ID), out.nodeName, containerID, fmt.Sprint(out.netNSCookie),
		fmt.Sprint(out.interfaceIndex), out.interfaceName, out.datapathConfigHash,
		fmt.Sprint(out.policyMapID), fmt.Sprint(out.requireToContainer), out.netNSPath, wireDigest} {
		put(value)
	}
	for _, ip := range addresses {
		put(ip.String())
	}
	out.digest = hex.EncodeToString(h.Sum(nil))
	return out, nil
}

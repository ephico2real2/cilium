// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
)

// These indexes mirror bpf/lib/tailcall.h. The unit test below checks the
// constants against that source file so a BPF layout change fails closed.
const (
	callIPv4FromLXC             uint32 = 7
	callIPv6FromLXC             uint32 = 10
	callIPv4ToLXCPolicyOnly     uint32 = 11
	callIPv6ToLXCPolicyOnly     uint32 = 12
	callIPv4ToEndpoint          uint32 = 13
	callIPv6ToEndpoint          uint32 = 14
	callIPv4FromLXCCont         uint32 = 26
	callIPv6FromLXCCont         uint32 = 27
	callIPv4CTIngress           uint32 = 28
	callIPv4CTIngressPolicyOnly uint32 = 29
	callIPv4CTEgress            uint32 = 30
	callIPv6CTIngress           uint32 = 31
	callIPv6CTIngressPolicyOnly uint32 = 32
	callIPv6CTEgress            uint32 = 33
)

type policyPathLink struct {
	ProgramID uint32
	LinkID    uint32
	Revision  uint64
}

type policyTailCallHop struct {
	index uint32
	name  string
	maps  []uint32
}

// VerifyZtunnelPolicyMapReachability is a point-in-time read of the actual
// pinned Cilium endpoint maps, ProgramArray targets, and TCX links. A missing
// map ID, unsupported kernel query, unsupported datapath mode, or any mismatch
// returns an error. The observation is only policy-map reachability evidence;
// it does not prove packet capture, complete policy enforcement, TLS, or
// authorization freshness.
func (l *loader) VerifyZtunnelPolicyMapReachability(ctx context.Context, identity endpointtypes.ZtunnelPolicyMapReachabilityIdentity) (endpointtypes.ZtunnelPolicyMapReachabilityObservation, error) {
	if err := identity.Validate(); err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}
	if !option.Config.EnableTCX {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("TCX is disabled")
	}
	if option.Config.EnableL7Proxy || option.Config.EnableEnvoyConfig || option.Config.EnableDatapathPlugins ||
		option.Config.EnableIPv4Masquerade || option.Config.EnableIPv6Masquerade || option.Config.EnableBPFMasquerade {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("endpoint profile has an unsupported L7, plugin, or masquerade path")
	}
	if err := ctx.Err(); err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}

	first, err := l.inspectZtunnelPolicyPath(ctx, identity)
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}
	second, err := l.inspectZtunnelPolicyPath(ctx, identity)
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}
	if !reflect.DeepEqual(first, second) {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("kernel policy path changed during the two-read observation")
	}
	if err := ctx.Err(); err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}
	return second, nil
}

func (l *loader) inspectZtunnelPolicyPath(ctx context.Context, identity endpointtypes.ZtunnelPolicyMapReachabilityIdentity) (endpointtypes.ZtunnelPolicyMapReachabilityObservation, error) {
	if err := verifySourceIPNetNS(ctx, endpointtypes.SourceIPDatapathIdentity{
		NetNSPath: identity.NetNSPath, NetNSCookie: identity.NetNSCookie,
	}); err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("verify endpoint netns incarnation: %w", err)
	}
	device, err := safenetlink.LinkByName(identity.Interface)
	if err := ctx.Err(); err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("look up endpoint veth: %w", err)
	}
	if device.Type() != "veth" || device.Attrs().Index != identity.IfIndex {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("endpoint interface is not the expected veth incarnation")
	}
	for _, direction := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := safenetlink.FilterList(device, direction)
		if err := ctx.Err(); err != nil {
			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
		}
		if err != nil {
			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("inspect legacy TC filters: %w", err)
		}
		if len(filters) != 0 {
			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("legacy TC filters are present")
		}
	}

	policyPath := bpf.LocalMapPath(l.logger, policymap.MapName, identity.EndpointID)
	policyMap, policyMapID, err := loadKernelMap(
		policyPath,
		ebpf.LPMTrie,
		uint32(unsafe.Sizeof(policymap.PolicyKey{})),
		uint32(unsafe.Sizeof(policymap.PolicyEntry{})),
	)
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("open endpoint policy map: %w", err)
	}
	defer policyMap.Close()
	if policyMapID != identity.PolicyMapID {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("endpoint policy map ID changed: got %d want %d", policyMapID, identity.PolicyMapID)
	}

	callsPath := l.CallsMapPath(identity.EndpointID)
	calls, callsID, err := loadKernelMap(callsPath, ebpf.ProgramArray, 4, 4)
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("open endpoint tail-call array: %w", err)
	}
	defer calls.Close()

	policyCallPath := bpf.MapPath(l.logger, policymap.PolicyCallMapName)
	policyCalls, policyCallID, err := loadKernelMap(policyCallPath, ebpf.ProgramArray, 4, 4)
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("open global endpoint policy ProgramArray: %w", err)
	}
	defer policyCalls.Close()

	fromLink, fromInfo, err := inspectPolicyTCXLink(ctx, identity, ebpf.AttachTCXIngress, symbolFromEndpoint)
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}
	if err := requireProgramMaps(fromInfo, callsID); err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("from-container entrypoint cannot reach the endpoint tail-call array: %w", err)
	}

	toLink := policyPathLink{}
	if identity.RequireToContainer {
		var toInfo *ebpf.ProgramInfo
		toLink, toInfo, err = inspectPolicyTCXLink(ctx, identity, ebpf.AttachTCXEgress, symbolToEndpoint)
		if err != nil {
			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
		}
		if err := requireProgramMaps(toInfo, callsID); err != nil {
			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("to-container entrypoint cannot reach the native endpoint policy path: %w", err)
		}
	}

	policyProg, err := lookupProgram(policyCalls, uint32(identity.EndpointID), "cil_lxc_policy", callsID)
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("global policy ProgramArray does not point to the endpoint policy entrypoint: %w", err)
	}
	defer policyProg.Close()
	policyProgID, err := programKernelID(policyProg)
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}

	out := endpointtypes.ZtunnelPolicyMapReachabilityObservation{
		Identity: identity, PolicyMapID: policyMapID, CallsMapID: callsID, PolicyCallMapID: policyCallID,
		FromContainerProgramID: fromLink.ProgramID, FromContainerLinkID: fromLink.LinkID,
		FromContainerAttachSetRevision: fromLink.Revision, EndpointPolicyProgramID: policyProgID,
	}
	if identity.RequireToContainer {
		out.ToContainerProgramID, out.ToContainerLinkID = toLink.ProgramID, toLink.LinkID
		out.ToContainerAttachSetRevision = toLink.Revision
	}

	// bpf_lxc.c cil_lxc_policy tail-calls the policy-only CT slots only when
	// both families are compiled; single-stack objects inline that lookup.
	dualStack := option.Config.EnableIPv4 && option.Config.EnableIPv6

	if identity.IPv4 {
		from4, err := lookupProgram(calls, callIPv4FromLXC, "tail_handle_ipv4", callsID)
		if err != nil {
			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv4 egress policy path: %w", err)
		}
		from4Ref, err := programReference(callIPv4FromLXC, from4)
		_ = from4.Close()
		if err != nil {
			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
		}
		out.EgressPrograms = append(out.EgressPrograms, from4Ref)
		for _, hop := range []struct {
			index uint32
			name  string
			maps  []uint32
		}{
			{callIPv4CTEgress, "tail_ipv4_ct_egress", []uint32{callsID}},
			{callIPv4FromLXCCont, "tail_handle_ipv4_cont", []uint32{policyMapID, policyCallID}},
		} {
			program, err := lookupProgram(calls, hop.index, hop.name, hop.maps...)
			if err != nil {
				return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv4 egress policy tail-call slot %d: %w", hop.index, err)
			}
			ref, err := programReference(hop.index, program)
			_ = program.Close()
			if err != nil {
				return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
			}
			out.EgressPrograms = append(out.EgressPrograms, ref)
		}

		ingress := []policyTailCallHop{
			{callIPv4CTIngress, "tail_ipv4_ct_ingress", []uint32{callsID}},
			{callIPv4ToEndpoint, "tail_ipv4_to_endpoint", []uint32{policyMapID}},
		}
		if dualStack {
			ingress = append(ingress, policyTailCallHop{callIPv4CTIngressPolicyOnly, "tail_ipv4_ct_ingress_policy_only", []uint32{callsID}})
		} else if err := requireEmptyProgramArraySlot(calls, callIPv4CTIngressPolicyOnly); err != nil {
			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv4 policy tail-call slot %d: %w", callIPv4CTIngressPolicyOnly, err)
		}
		ingress = append(ingress, policyTailCallHop{callIPv4ToLXCPolicyOnly, "tail_ipv4_policy", []uint32{policyMapID}})
		for _, hop := range ingress {
			program, err := lookupProgram(calls, hop.index, hop.name, hop.maps...)
			if err != nil {
				return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv4 policy tail-call slot %d: %w", hop.index, err)
			}
			ref, err := programReference(hop.index, program)
			_ = program.Close()
			if err != nil {
				return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
			}
			out.IngressPrograms = append(out.IngressPrograms, ref)
		}
	}
	if identity.IPv6 {
		from6, err := lookupProgram(calls, callIPv6FromLXC, "tail_handle_ipv6", callsID)
		if err != nil {
			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv6 egress policy path: %w", err)
		}
		from6Ref, err := programReference(callIPv6FromLXC, from6)
		_ = from6.Close()
		if err != nil {
			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
		}
		out.EgressPrograms = append(out.EgressPrograms, from6Ref)
		for _, hop := range []struct {
			index uint32
			name  string
			maps  []uint32
		}{
			{callIPv6CTEgress, "tail_ipv6_ct_egress", []uint32{callsID}},
			{callIPv6FromLXCCont, "tail_handle_ipv6_cont", []uint32{policyMapID, policyCallID}},
		} {
			program, err := lookupProgram(calls, hop.index, hop.name, hop.maps...)
			if err != nil {
				return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv6 egress policy tail-call slot %d: %w", hop.index, err)
			}
			ref, err := programReference(hop.index, program)
			_ = program.Close()
			if err != nil {
				return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
			}
			out.EgressPrograms = append(out.EgressPrograms, ref)
		}

		ingress := []policyTailCallHop{
			{callIPv6CTIngress, "tail_ipv6_ct_ingress", []uint32{callsID}},
			{callIPv6ToEndpoint, "tail_ipv6_to_endpoint", []uint32{policyMapID}},
		}
		if dualStack {
			ingress = append(ingress, policyTailCallHop{callIPv6CTIngressPolicyOnly, "tail_ipv6_ct_ingress_policy_only", []uint32{callsID}})
		} else if err := requireEmptyProgramArraySlot(calls, callIPv6CTIngressPolicyOnly); err != nil {
			return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv6 policy tail-call slot %d: %w", callIPv6CTIngressPolicyOnly, err)
		}
		ingress = append(ingress, policyTailCallHop{callIPv6ToLXCPolicyOnly, "tail_ipv6_policy", []uint32{policyMapID}})
		for _, hop := range ingress {
			program, err := lookupProgram(calls, hop.index, hop.name, hop.maps...)
			if err != nil {
				return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("IPv6 policy tail-call slot %d: %w", hop.index, err)
			}
			ref, err := programReference(hop.index, program)
			_ = program.Close()
			if err != nil {
				return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
			}
			out.IngressPrograms = append(out.IngressPrograms, ref)
		}
	}
	return out, nil
}

func loadKernelMap(path string, want ebpf.MapType, wantKeySize, wantValueSize uint32) (*ebpf.Map, uint32, error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, 0, err
	}
	info, err := m.Info()
	if err != nil {
		_ = m.Close()
		return nil, 0, fmt.Errorf("read map info: %w", err)
	}
	if info.Type != want || info.KeySize != wantKeySize || info.ValueSize != wantValueSize {
		_ = m.Close()
		return nil, 0, fmt.Errorf("unexpected kernel map shape: type=%s key=%d value=%d, want type=%s key=%d value=%d", info.Type, info.KeySize, info.ValueSize, want, wantKeySize, wantValueSize)
	}
	id, ok := info.ID()
	if !ok || id == 0 {
		_ = m.Close()
		return nil, 0, fmt.Errorf("kernel does not expose a nonzero map ID")
	}
	return m, uint32(id), nil
}

func inspectPolicyTCXLink(ctx context.Context, identity endpointtypes.ZtunnelPolicyMapReachabilityIdentity, attach ebpf.AttachType, symbol string) (policyPathLink, *ebpf.ProgramInfo, error) {
	if err := ctx.Err(); err != nil {
		return policyPathLink{}, nil, err
	}
	pin := filepath.Join(bpf.CiliumPath(), "endpoints", strconv.Itoa(int(identity.EndpointID)), "links", symbol)
	pinned, err := link.LoadPinnedLink(pin, nil)
	if err := ctx.Err(); err != nil {
		if pinned != nil {
			_ = pinned.Close()
		}
		return policyPathLink{}, nil, err
	}
	if err != nil {
		return policyPathLink{}, nil, fmt.Errorf("load pinned %s TCX link: %w", symbol, err)
	}
	defer pinned.Close()
	info, err := pinned.Info()
	if err != nil {
		return policyPathLink{}, nil, fmt.Errorf("read pinned %s link info: %w", symbol, err)
	}
	tcx := info.TCX()
	if info.Type != link.TCXType || tcx == nil || int(tcx.Ifindex) != identity.IfIndex || uint32(tcx.AttachType) != uint32(attach) || info.ID == 0 || info.Program == 0 {
		return policyPathLink{}, nil, fmt.Errorf("pinned %s link does not match endpoint TCX interface/direction", symbol)
	}
	prog, err := ebpf.NewProgramFromID(info.Program)
	if err != nil {
		return policyPathLink{}, nil, fmt.Errorf("open pinned %s program: %w", symbol, err)
	}
	defer prog.Close()
	progInfo, err := prog.Info()
	if err != nil {
		return policyPathLink{}, nil, fmt.Errorf("read pinned %s program info: %w", symbol, err)
	}
	progID, ok := progInfo.ID()
	if !ok || progID != info.Program || progInfo.Type != ebpf.SchedCLS || progInfo.Tag == "" ||
		(progInfo.Name != symbol && progInfo.Name != kernelObjectName(symbol)) {
		return policyPathLink{}, nil, fmt.Errorf("pinned %s link does not point to the expected Cilium program", symbol)
	}
	query, err := link.QueryPrograms(link.QueryOptions{Target: identity.IfIndex, Attach: attach})
	if err != nil {
		return policyPathLink{}, nil, fmt.Errorf("query %s TCX attachments: %w", symbol, err)
	}
	if query == nil || query.Revision == 0 || len(query.Programs) != 1 || query.Programs[0].ID != progID {
		return policyPathLink{}, nil, fmt.Errorf("%s TCX attachment set is not the single expected Cilium program", symbol)
	}
	queryLinkID, ok := query.Programs[0].LinkID()
	if !ok || queryLinkID != info.ID {
		return policyPathLink{}, nil, fmt.Errorf("pinned %s link is not the current attachment", symbol)
	}
	return policyPathLink{ProgramID: uint32(progID), LinkID: uint32(info.ID), Revision: query.Revision}, progInfo, nil
}

func lookupProgram(programArray *ebpf.Map, index uint32, expectedName string, requiredMapIDs ...uint32) (*ebpf.Program, error) {
	var program *ebpf.Program
	if err := programArray.Lookup(&index, &program); err != nil {
		return nil, fmt.Errorf("read ProgramArray index %d: %w", index, err)
	}
	if program == nil {
		return nil, fmt.Errorf("ProgramArray index %d is empty", index)
	}
	info, err := program.Info()
	if err != nil {
		_ = program.Close()
		return nil, fmt.Errorf("read ProgramArray target info: %w", err)
	}
	id, ok := info.ID()
	if !ok || id == 0 || info.Type != ebpf.SchedCLS || info.Tag == "" ||
		(info.Name != expectedName && info.Name != kernelObjectName(expectedName)) {
		_ = program.Close()
		return nil, fmt.Errorf("ProgramArray index %d has unexpected program ID/name/type/tag", index)
	}
	if err := requireProgramMaps(info, requiredMapIDs...); err != nil {
		_ = program.Close()
		return nil, fmt.Errorf("ProgramArray index %d target map bindings: %w", index, err)
	}
	return program, nil
}

func requireEmptyProgramArraySlot(programArray *ebpf.Map, index uint32) error {
	var program *ebpf.Program
	err := programArray.Lookup(&index, &program)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read ProgramArray index %d: %w", index, err)
	}
	if program == nil {
		return nil
	}
	_ = program.Close()
	return fmt.Errorf("ProgramArray index %d is populated, but the single-stack endpoint object inlines this lookup", index)
}

func requireProgramMaps(info *ebpf.ProgramInfo, required ...uint32) error {
	ids, ok := info.MapIDs()
	if !ok || len(ids) == 0 {
		return fmt.Errorf("kernel does not expose loaded program map IDs")
	}
	for _, want := range required {
		found := false
		for _, got := range ids {
			if uint32(got) == want {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("loaded program does not reference required map ID %d", want)
		}
	}
	return nil
}

func programKernelID(program *ebpf.Program) (uint32, error) {
	info, err := program.Info()
	if err != nil {
		return 0, fmt.Errorf("read program info: %w", err)
	}
	id, ok := info.ID()
	if !ok || id == 0 {
		return 0, fmt.Errorf("kernel does not expose a nonzero program ID")
	}
	return uint32(id), nil
}

func programReference(index uint32, program *ebpf.Program) (endpointtypes.ZtunnelPolicyProgramReference, error) {
	info, err := program.Info()
	if err != nil {
		return endpointtypes.ZtunnelPolicyProgramReference{}, fmt.Errorf("read tail-call target info: %w", err)
	}
	id, ok := info.ID()
	if !ok || id == 0 || info.Tag == "" {
		return endpointtypes.ZtunnelPolicyProgramReference{}, fmt.Errorf("tail-call target lacks a kernel program ID or tag")
	}
	return endpointtypes.ZtunnelPolicyProgramReference{Index: index, ProgramID: uint32(id), Name: info.Name, Tag: info.Tag}, nil
}

var _ endpointtypes.ZtunnelPolicyMapReachabilityVerifier = (*loader)(nil)

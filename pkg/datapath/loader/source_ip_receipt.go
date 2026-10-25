// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	dpconfig "github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
)

type sourceIPReceipt struct {
	generation  uint64
	observation endpointtypes.SourceIPDatapathObservation
}

func (l *loader) beginSourceIPReceiptGeneration(id uint16) uint64 {
	l.sourceIPReceiptMu.Lock()
	defer l.sourceIPReceiptMu.Unlock()
	if l.sourceIPReceiptGenerations == nil {
		l.sourceIPReceiptGenerations = make(map[uint16]uint64)
	}
	if _, exhausted := l.sourceIPReceiptExhausted[id]; exhausted {
		delete(l.sourceIPReceipts, id)
		return 0
	}
	current := l.sourceIPReceiptGenerations[id]
	if current == ^uint64(0) {
		if l.sourceIPReceiptExhausted == nil {
			l.sourceIPReceiptExhausted = make(map[uint16]struct{})
		}
		l.sourceIPReceiptExhausted[id] = struct{}{}
		delete(l.sourceIPReceipts, id)
		return 0
	}
	next := current + 1
	l.sourceIPReceiptGenerations[id] = next
	delete(l.sourceIPReceipts, id)
	return next
}

func (l *loader) invalidateSourceIPReceipt(id uint16) {
	l.beginSourceIPReceiptGeneration(id)
}

func (l *loader) storeSourceIPReceiptIfCurrent(id uint16, generation uint64, observation endpointtypes.SourceIPDatapathObservation) bool {
	l.sourceIPReceiptMu.Lock()
	defer l.sourceIPReceiptMu.Unlock()
	if _, exhausted := l.sourceIPReceiptExhausted[id]; exhausted || generation == 0 || l.sourceIPReceiptGenerations[id] != generation {
		return false
	}
	if l.sourceIPReceipts == nil {
		l.sourceIPReceipts = make(map[uint16]sourceIPReceipt)
	}
	l.sourceIPReceipts[id] = sourceIPReceipt{generation: generation, observation: observation}
	return true
}

// publishSourceIPReceipt is called only after reloadEndpoint attached and
// committed the programs successfully. Unsupported datapath modes simply
// withhold the receipt; they do not make ordinary Cilium endpoint regeneration
// fail. Higher-level ztunnel authorization must treat an absent receipt as
// unavailable and deny publication.
func (l *loader) publishSourceIPReceipt(ctx context.Context, ep endpointtypes.Config, lnc *dpconfig.Config, generation uint64, spec *ebpf.CollectionSpec, loadedProgram *ebpf.Program) {
	if err := ctx.Err(); err != nil {
		return
	}
	if spec == nil || loadedProgram == nil || l.bpfCollectionLoader == nil || l.bpfCollectionLoader.pluginsEnabled {
		l.logger.Debug("Source IP datapath receipt withheld: successful unmodified endpoint program is unavailable")
		return
	}
	provider, ok := ep.(endpointtypes.SourceIPDatapathIdentityProvider)
	if !ok {
		return
	}
	identity := provider.SourceIPDatapathIdentity()
	if err := validateSourceIPEligibility(ep, lnc, identity); err != nil {
		l.logger.Debug("Source IP datapath receipt withheld", logfields.Error, err)
		return
	}
	cfg, ok := dpconfig.Endpoint(ep, lnc).(*dpconfig.BPFLXC)
	if !ok || cfg == nil || !cfg.EnableSIPVerification {
		l.logger.Debug("Source IP datapath receipt withheld: loaded endpoint configuration disables source IP verification")
		return
	}
	programSpec := spec.Programs[symbolFromEndpoint]
	if programSpec == nil {
		l.logger.Debug("Source IP datapath receipt withheld: successful endpoint spec lacks the Cilium ingress program")
		return
	}
	loadedInfo, err := loadedProgram.Info()
	if err != nil {
		l.logger.Debug("Source IP datapath receipt withheld: loaded program metadata unavailable", logfields.Error, err)
		return
	}
	observation, err := inspectSourceIPTCX(ctx, identity, loadedInfo)
	if err != nil {
		l.logger.Debug("Source IP datapath receipt withheld", logfields.Error, err)
		return
	}
	if err := attachSourceIPConfigMap(ctx, &observation, spec, identity, cfg); err != nil {
		l.logger.Debug("Source IP datapath receipt withheld: live BPF configuration could not be verified", logfields.Error, err)
		return
	}
	if err := ctx.Err(); err != nil {
		return
	}
	if !l.storeSourceIPReceiptIfCurrent(identity.EndpointID, generation, observation) {
		l.logger.Debug("Source IP datapath receipt discarded after endpoint generation changed",
			logfields.EndpointID, identity.EndpointID)
		return
	}
	l.logger.Debug("Recorded verified source IP guard attachment", logfields.EndpointID, identity.EndpointID)
}

func validateSourceIPIdentity(identity endpointtypes.SourceIPDatapathIdentity) error {
	if identity.EndpointID == 0 || identity.NamespaceUID == "" || identity.PodUID == "" ||
		identity.NetNSPath == "" || identity.NetNSCookie == 0 || identity.Interface == "" ||
		identity.IfIndex <= 0 || identity.ConfigHash == "" || !identity.SourceIPEnabled ||
		(identity.IPv4.IsValid() && !identity.IPv4.Is4()) || (identity.IPv6.IsValid() && !identity.IPv6.Is6()) ||
		(!identity.IPv4.IsValid() && !identity.IPv6.IsValid()) {
		return fmt.Errorf("incomplete endpoint identity")
	}
	return nil
}

func validateSourceIPEligibility(ep endpointtypes.Config, lnc *dpconfig.Config, identity endpointtypes.SourceIPDatapathIdentity) error {
	if err := validateSourceIPIdentity(identity); err != nil {
		return err
	}
	if ep.IsHost() {
		return fmt.Errorf("host endpoint")
	}
	if !identity.SourceIPEnabled || ep.GetOptions() == nil || !ep.GetOptions().IsEnabled(option.SourceIPVerification) {
		return fmt.Errorf("source IP verification option disabled")
	}
	if identity.ZtunnelRequired && !ep.GetOptions().IsEnabled(option.SourceIPVerification) {
		return fmt.Errorf("source IP verification is mandatory for required ztunnel membership")
	}
	if !option.Config.EnableTCX {
		return fmt.Errorf("TCX is disabled; legacy TC attachment is not accepted")
	}
	if lnc == nil || lnc.DatapathIsNetkit {
		return fmt.Errorf("netkit datapath is not qualified")
	}
	if option.Config.EnableEnvoyConfig || option.Config.EnableL7Proxy {
		return fmt.Errorf("L7 load-balancer paths can bypass the source IP guard")
	}
	if option.Config.EnableDatapathPlugins {
		return fmt.Errorf("datapath plugins can alter endpoint program instructions")
	}
	if option.Config.EnableIPv4Masquerade || option.Config.EnableIPv6Masquerade || option.Config.EnableBPFMasquerade {
		return fmt.Errorf("masquerade paths are not qualified for this source IP receipt")
	}
	if !ep.IPv4Address().IsValid() && !ep.IPv6Address().IsValid() {
		return fmt.Errorf("endpoint has no assigned IP address")
	}
	return nil
}

func inspectSourceIPTCX(ctx context.Context, identity endpointtypes.SourceIPDatapathIdentity, expectedProgram *ebpf.ProgramInfo) (endpointtypes.SourceIPDatapathObservation, error) {
	if err := ctx.Err(); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if err := validateSourceIPIdentity(identity); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	device, err := safenetlink.LinkByName(identity.Interface)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return endpointtypes.SourceIPDatapathObservation{}, ctxErr
	}
	if err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("lookup endpoint interface: %w", err)
	}
	if device.Type() != "veth" || device.Attrs().Index != identity.IfIndex {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("endpoint interface changed")
	}
	filters, err := safenetlink.FilterList(device, netlink.HANDLE_MIN_INGRESS)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return endpointtypes.SourceIPDatapathObservation{}, ctxErr
	}
	if err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("list legacy ingress filters: %w", err)
	}
	if len(filters) != 0 {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("legacy ingress filters are present")
	}
	pin := filepath.Join(bpf.CiliumPath(), "endpoints", fmt.Sprint(identity.EndpointID), "links", symbolFromEndpoint)
	pinned, err := link.LoadPinnedLink(pin, nil)
	if err := ctx.Err(); err != nil {
		if pinned != nil {
			_ = pinned.Close()
		}
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("load pinned TCX ingress link: %w", err)
	}
	defer pinned.Close()
	linkInfo, err := pinned.Info()
	if err := ctx.Err(); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("read pinned link info: %w", err)
	}
	tcx := linkInfo.TCX()
	if linkInfo.Type != link.TCXType || tcx == nil || int(tcx.Ifindex) != identity.IfIndex ||
		uint32(tcx.AttachType) != uint32(ebpf.AttachTCXIngress) {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("pinned link is not TCX ingress on the expected interface")
	}
	if linkInfo.ID == 0 || linkInfo.Program == 0 {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("pinned TCX link lacks kernel link or program ID")
	}
	program, err := ebpf.NewProgramFromID(linkInfo.Program)
	if err := ctx.Err(); err != nil {
		if program != nil {
			_ = program.Close()
		}
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("open pinned ingress program: %w", err)
	}
	defer program.Close()
	programInfo, err := program.Info()
	if err := ctx.Err(); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("read ingress program info: %w", err)
	}
	programID, ok := programInfo.ID()
	if !ok || programID != linkInfo.Program || programInfo.Tag == "" || !sourceIPProgramName(programInfo.Name) {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("pinned program identity does not match Cilium from-container ingress: ID=%d expectedID=%d name=%q expectedName=%q tag=%q", programID, linkInfo.Program, programInfo.Name, kernelObjectName(symbolFromEndpoint), programInfo.Tag)
	}
	if expectedProgram != nil {
		loadedID, idOK := expectedProgram.ID()
		loadedMaps, mapsOK := expectedProgram.MapIDs()
		currentMaps, currentMapsOK := programInfo.MapIDs()
		if !idOK || loadedID == 0 || loadedID != programID || expectedProgram.Type != programInfo.Type ||
			expectedProgram.Tag != programInfo.Tag || !mapsOK || !currentMapsOK || len(loadedMaps) == 0 ||
			hashProgramMapIDs(loadedMaps) != hashProgramMapIDs(currentMaps) {
			return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("attached ingress program does not match the actual successfully loaded Cilium program")
		}
	}
	before, err := link.QueryPrograms(link.QueryOptions{Target: identity.IfIndex, Attach: ebpf.AttachTCXIngress})
	if err := ctx.Err(); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("query TCX ingress programs: %w", err)
	}
	if before == nil || before.Revision == 0 || len(before.Programs) != 1 || before.Programs[0].ID != linkInfo.Program {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("TCX ingress attachment set is unsupported or contains other programs")
	}
	attachedLinkID, ok := before.Programs[0].LinkID()
	if !ok || attachedLinkID != linkInfo.ID {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("pinned link is not the current ingress attachment")
	}
	after, err := link.QueryPrograms(link.QueryOptions{Target: identity.IfIndex, Attach: ebpf.AttachTCXIngress})
	if err := ctx.Err(); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("recheck TCX ingress programs: %w", err)
	}
	if after == nil || after.Revision == 0 || after.Revision != before.Revision || len(after.Programs) != 1 ||
		after.Programs[0].ID != linkInfo.Program {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("TCX ingress attachment changed during verification")
	}
	afterLinkID, ok := after.Programs[0].LinkID()
	if !ok || afterLinkID != linkInfo.ID {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("TCX ingress link changed during verification")
	}
	if err := verifySourceIPNetNS(ctx, identity); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	mapIDs, ok := programInfo.MapIDs()
	if !ok || len(mapIDs) == 0 {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("kernel does not expose the loaded program map IDs")
	}
	return endpointtypes.SourceIPDatapathObservation{
		Identity:          identity,
		ProgramID:         uint32(programID),
		ProgramTag:        programInfo.Tag,
		LinkID:            uint32(linkInfo.ID),
		AttachSetRevision: before.Revision,
		ProgramMapIDsHash: hashProgramMapIDs(mapIDs),
	}, nil
}

func verifySourceIPNetNS(ctx context.Context, identity endpointtypes.SourceIPDatapathIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ns, err := netns.OpenPinned(identity.NetNSPath)
	if err := ctx.Err(); err != nil {
		if ns != nil {
			_ = ns.Close()
		}
		return err
	}
	if err != nil {
		return fmt.Errorf("open endpoint network namespace: %w", err)
	}
	defer ns.Close()
	kind, err := unix.IoctlRetInt(ns.FD(), unix.NS_GET_NSTYPE)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return fmt.Errorf("read endpoint network namespace type: %w", err)
	}
	if kind != unix.CLONE_NEWNET {
		return fmt.Errorf("endpoint path is not a network namespace")
	}
	var cookie uint64
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ns.Do(func() error { var err error; cookie, err = netns.GetNetNSCookie(); return err }); err != nil {
		return fmt.Errorf("read endpoint network namespace cookie: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if cookie == 0 || cookie != identity.NetNSCookie {
		return fmt.Errorf("endpoint network namespace cookie changed")
	}
	return nil
}

func expectedSourceIPConfigValues(identity endpointtypes.SourceIPDatapathIdentity, cfg *dpconfig.BPFLXC) (map[string][]byte, error) {
	if cfg == nil || !cfg.EnableSIPVerification || cfg.EndpointID != identity.EndpointID ||
		cfg.EndpointNetNSCookie != identity.NetNSCookie || cfg.InterfaceIfIndex != uint32(identity.IfIndex) {
		return nil, fmt.Errorf("loader endpoint configuration does not match the verified endpoint identity")
	}
	values := map[string][]byte{
		"__config_enable_sip_verification": {1},
		"__config_endpoint_id":             make([]byte, 2),
		"__config_endpoint_netns_cookie":   make([]byte, 8),
		"__config_interface_ifindex":       make([]byte, 4),
	}
	binary.NativeEndian.PutUint16(values["__config_endpoint_id"], cfg.EndpointID)
	binary.NativeEndian.PutUint64(values["__config_endpoint_netns_cookie"], cfg.EndpointNetNSCookie)
	binary.NativeEndian.PutUint32(values["__config_interface_ifindex"], cfg.InterfaceIfIndex)
	if identity.IPv4.IsValid() {
		want := identity.IPv4.As4()
		if !bytes.Equal(cfg.EndpointIPv4.Addr[:], want[:]) {
			return nil, fmt.Errorf("loader IPv4 configuration does not match the endpoint address")
		}
		values["__config_endpoint_ipv4"] = want[:]
	}
	if identity.IPv6.IsValid() {
		want := identity.IPv6.As16()
		if !bytes.Equal(cfg.EndpointIPv6.Addr[:], want[:]) {
			return nil, fmt.Errorf("loader IPv6 configuration does not match the endpoint address")
		}
		values["__config_endpoint_ipv6"] = want[:]
	}
	if !identity.IPv4.IsValid() && cfg.EndpointIPv4.Addr != [4]byte{} {
		return nil, fmt.Errorf("loader has an unowned IPv4 address for this endpoint incarnation")
	}
	if !identity.IPv6.IsValid() && cfg.EndpointIPv6.Addr != [16]byte{} {
		return nil, fmt.Errorf("loader has an unowned IPv6 address for this endpoint incarnation")
	}
	if !identity.IPv4.IsValid() && !identity.IPv6.IsValid() {
		return nil, fmt.Errorf("endpoint has no source address for source IP verification")
	}
	return values, nil
}

func verifySourceIPConfigVariables(variables map[string]*ebpf.VariableSpec, section string, value []byte, expected map[string][]byte) error {
	for name, want := range expected {
		variable := variables[name]
		if variable == nil || variable.SectionName != section || variable.Size() != uint32(len(want)) {
			return fmt.Errorf("required BPF configuration variable %q is unavailable or has an unexpected layout", name)
		}
		end := uint64(variable.Offset) + uint64(variable.Size())
		if end > uint64(len(value)) {
			return fmt.Errorf("BPF configuration variable %q exceeds the kernel map value", name)
		}
		if !bytes.Equal(value[variable.Offset:uint32(end)], want) {
			return fmt.Errorf("kernel BPF configuration variable %q does not match the successful loader configuration", name)
		}
	}
	return nil
}

func hashProgramMapIDs(ids []ebpf.MapID) string {
	sortedIDs := append([]ebpf.MapID(nil), ids...)
	slices.Sort(sortedIDs)
	h := sha256.New()
	var encoded [4]byte
	for _, id := range sortedIDs {
		binary.BigEndian.PutUint32(encoded[:], uint32(id))
		_, _ = h.Write(encoded[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

const (
	bpfObjectNameLen                     = 16 // Linux includes the trailing NUL in BPF_OBJ_NAME_LEN.
	maxSourceIPConfigMapValueSize uint32 = 64 << 10
)

// ProgramInfo restores the full BTF function name when available. Older
// kernels or missing BTF expose only the 15-byte UAPI name. Accept exactly
// those two spellings; kernel IDs, instruction tag and map bindings remain
// mandatory and independent of this descriptive name.
func sourceIPProgramName(name string) bool {
	return name == symbolFromEndpoint || name == kernelObjectName(symbolFromEndpoint)
}

func kernelObjectName(name string) string {
	if len(name) >= bpfObjectNameLen {
		return name[:bpfObjectNameLen-1]
	}
	return name
}

func kernelMapName(name string) string { return kernelObjectName(name) }

func validateSourceIPConfigMapValueSize(expected, actual uint32) error {
	if expected == 0 || expected > maxSourceIPConfigMapValueSize || actual != expected {
		return fmt.Errorf("source IP configuration map value size is invalid or exceeds %d bytes", maxSourceIPConfigMapValueSize)
	}
	return nil
}

func sourceIPProgramMapIDs(ctx context.Context, programID uint32) ([]ebpf.MapID, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	program, err := ebpf.NewProgramFromID(ebpf.ProgramID(programID))
	if err := ctx.Err(); err != nil {
		if program != nil {
			_ = program.Close()
		}
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("open source IP program to inspect map IDs: %w", err)
	}
	defer program.Close()
	info, err := program.Info()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, fmt.Errorf("read source IP program map IDs: %w", err)
	}
	ids, ok := info.MapIDs()
	if !ok || len(ids) == 0 {
		return nil, fmt.Errorf("kernel does not expose source IP program map IDs")
	}
	return ids, nil
}

func attachSourceIPConfigMap(ctx context.Context, observation *endpointtypes.SourceIPDatapathObservation, spec *ebpf.CollectionSpec,
	identity endpointtypes.SourceIPDatapathIdentity, cfg *dpconfig.BPFLXC) error {
	if observation == nil || spec == nil {
		return fmt.Errorf("successful endpoint spec and kernel observation are required")
	}
	const sipVariable = "__config_enable_sip_verification"
	variable := spec.Variables[sipVariable]
	if variable == nil || variable.SectionName != ".rodata.config" || variable.Size() != 1 {
		return fmt.Errorf("source IP verification constant is missing from .rodata.config")
	}
	mapSpec := spec.Maps[variable.SectionName]
	if mapSpec == nil || mapSpec.Name == "" {
		return fmt.Errorf("source IP configuration map is missing from the successful endpoint spec")
	}
	expectedMapName := kernelMapName(mapSpec.Name)
	if mapSpec.Name != variable.SectionName || mapSpec.Type != ebpf.Array || mapSpec.KeySize != 4 ||
		mapSpec.MaxEntries != 1 || mapSpec.Flags&unix.BPF_F_RDONLY_PROG == 0 {
		return fmt.Errorf("successful spec does not define the expected read-only .rodata.config array")
	}
	if err := validateSourceIPConfigMapValueSize(mapSpec.ValueSize, mapSpec.ValueSize); err != nil {
		return err
	}
	mapIDs, err := sourceIPProgramMapIDs(ctx, observation.ProgramID)
	if err != nil {
		return err
	}
	if hashProgramMapIDs(mapIDs) != observation.ProgramMapIDsHash {
		return fmt.Errorf("program map ID set changed while recording source IP configuration")
	}
	expected, err := expectedSourceIPConfigValues(identity, cfg)
	if err != nil {
		return err
	}
	var configMap *ebpf.Map
	var configMapInfo *ebpf.MapInfo
	for _, id := range mapIDs {
		if err := ctx.Err(); err != nil {
			if configMap != nil {
				_ = configMap.Close()
			}
			return err
		}
		candidate, err := ebpf.NewMapFromID(id)
		if ctxErr := ctx.Err(); ctxErr != nil {
			if candidate != nil {
				_ = candidate.Close()
			}
			if configMap != nil {
				_ = configMap.Close()
			}
			return ctxErr
		}
		if err != nil {
			return fmt.Errorf("open program map %d: %w", id, err)
		}
		info, err := candidate.Info()
		if ctxErr := ctx.Err(); ctxErr != nil {
			_ = candidate.Close()
			if configMap != nil {
				_ = configMap.Close()
			}
			return ctxErr
		}
		if err != nil {
			candidate.Close()
			return fmt.Errorf("inspect program map %d: %w", id, err)
		}
		if info.Name == expectedMapName {
			if configMap != nil {
				candidate.Close()
				configMap.Close()
				return fmt.Errorf("program references duplicate source IP configuration maps")
			}
			configMap, configMapInfo = candidate, info
		} else {
			candidate.Close()
		}
	}
	if configMap == nil || configMapInfo == nil {
		return fmt.Errorf("loaded program does not reference its expected .rodata.config map")
	}
	defer configMap.Close()
	if err := validateSourceIPConfigMapValueSize(mapSpec.ValueSize, configMapInfo.ValueSize); err != nil {
		return err
	}
	if configMapInfo.Type != ebpf.Array || configMapInfo.KeySize != 4 || configMapInfo.MaxEntries != 1 ||
		configMapInfo.Flags&unix.BPF_F_RDONLY_PROG == 0 || !configMapInfo.Frozen() {
		return fmt.Errorf("loaded .rodata.config map is not the expected frozen, read-only array")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	mapID, ok := configMapInfo.ID()
	if !ok || uint32(mapID) == 0 {
		return fmt.Errorf("kernel does not expose the configuration map ID")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data := make([]byte, int(configMapInfo.ValueSize))
	key := uint32(0)
	if err := configMap.Lookup(&key, &data); err != nil {
		return fmt.Errorf("read frozen kernel .rodata.config value: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifySourceIPConfigVariables(spec.Variables, variable.SectionName, data, expected); err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	observation.ConfigMapID = uint32(mapID)
	observation.ConfigMapName = configMapInfo.Name
	observation.ConfigMapHash = hex.EncodeToString(hash[:])
	observation.SIPConfigOffset = variable.Offset
	observation.SIPConfigSize = variable.Size()
	observation.SIPConfigEnabled = data[variable.Offset] == 1
	observation.ConfigMapReadOnly = configMapInfo.Flags&unix.BPF_F_RDONLY_PROG != 0
	observation.ConfigMapFrozen = configMapInfo.Frozen()
	if !observation.SIPConfigEnabled || !observation.ConfigMapReadOnly || !observation.ConfigMapFrozen {
		return fmt.Errorf("kernel source IP configuration is not enabled and immutable")
	}
	return nil
}

func verifyRetainedSourceIPConfigMap(ctx context.Context, current *endpointtypes.SourceIPDatapathObservation,
	retained endpointtypes.SourceIPDatapathObservation) error {
	if current == nil || retained.ConfigMapID == 0 {
		return fmt.Errorf("retained source IP configuration map identity is missing")
	}
	mapIDs, err := sourceIPProgramMapIDs(ctx, current.ProgramID)
	if err != nil {
		return err
	}
	if hashProgramMapIDs(mapIDs) != retained.ProgramMapIDsHash {
		return fmt.Errorf("kernel program map IDs changed since source IP receipt publication")
	}
	contains := false
	for _, id := range mapIDs {
		if uint32(id) == retained.ConfigMapID {
			contains = true
			break
		}
	}
	if !contains {
		return fmt.Errorf("source IP configuration map is no longer referenced by the attached program")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	configMap, err := ebpf.NewMapFromID(ebpf.MapID(retained.ConfigMapID))
	if ctxErr := ctx.Err(); ctxErr != nil {
		if configMap != nil {
			_ = configMap.Close()
		}
		return ctxErr
	}
	if err != nil {
		return fmt.Errorf("reopen retained source IP configuration map: %w", err)
	}
	defer configMap.Close()
	info, err := configMap.Info()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return fmt.Errorf("inspect retained source IP configuration map: %w", err)
	}
	if err := validateSourceIPConfigMapValueSize(info.ValueSize, info.ValueSize); err != nil {
		return err
	}
	if info.Name != retained.ConfigMapName || info.Name != ".rodata.config" || info.Type != ebpf.Array ||
		info.KeySize != 4 || info.MaxEntries != 1 || info.Flags&unix.BPF_F_RDONLY_PROG == 0 || !info.Frozen() ||
		uint64(retained.SIPConfigOffset)+uint64(retained.SIPConfigSize) > uint64(info.ValueSize) {
		return fmt.Errorf("retained source IP configuration map is no longer frozen and read-only")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data := make([]byte, int(info.ValueSize))
	key := uint32(0)
	if err := configMap.Lookup(&key, &data); err != nil {
		return fmt.Errorf("read retained kernel .rodata.config value: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != retained.ConfigMapHash || data[retained.SIPConfigOffset] != 1 {
		return fmt.Errorf("kernel source IP configuration value changed since receipt publication")
	}
	current.ConfigMapID = retained.ConfigMapID
	current.ConfigMapName = info.Name
	current.ConfigMapHash = hex.EncodeToString(hash[:])
	current.SIPConfigOffset = retained.SIPConfigOffset
	current.SIPConfigSize = retained.SIPConfigSize
	current.SIPConfigEnabled = data[retained.SIPConfigOffset] == 1
	current.ConfigMapReadOnly = info.Flags&unix.BPF_F_RDONLY_PROG != 0
	current.ConfigMapFrozen = info.Frozen()
	return nil
}

func sourceIPReceiptComplete(receipt endpointtypes.SourceIPDatapathObservation) bool {
	return receipt.Identity.EndpointID != 0 && receipt.ProgramID != 0 && receipt.ProgramTag != "" &&
		receipt.LinkID != 0 && receipt.AttachSetRevision != 0 && receipt.ProgramMapIDsHash != "" &&
		receipt.ConfigMapID != 0 && receipt.ConfigMapName == ".rodata.config" && receipt.ConfigMapHash != "" &&
		receipt.SIPConfigSize == 1 && receipt.SIPConfigEnabled && receipt.ConfigMapReadOnly && receipt.ConfigMapFrozen
}

func sourceIPAttachmentMatches(receipt endpointtypes.SourceIPDatapathObservation, expected endpointtypes.SourceIPDatapathIdentity, current endpointtypes.SourceIPDatapathObservation) bool {
	return receipt.Identity == expected && current.Identity == expected && expected.SourceIPEnabled &&
		sourceIPReceiptComplete(receipt) && current.ProgramMapIDsHash == receipt.ProgramMapIDsHash &&
		current.ProgramID == receipt.ProgramID && current.ProgramTag == receipt.ProgramTag &&
		current.LinkID == receipt.LinkID && current.AttachSetRevision == receipt.AttachSetRevision
}

func (l *loader) VerifySourceIPDatapath(ctx context.Context, expected endpointtypes.SourceIPDatapathIdentity) (endpointtypes.SourceIPDatapathObservation, error) {
	if err := ctx.Err(); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if err := validateSourceIPIdentity(expected); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	l.sourceIPReceiptMu.RLock()
	receipt, ok := l.sourceIPReceipts[expected.EndpointID]
	generation := l.sourceIPReceiptGenerations[expected.EndpointID]
	l.sourceIPReceiptMu.RUnlock()
	if !ok {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("no current source IP datapath receipt for endpoint incarnation")
	}
	if l.bpfCollectionLoader == nil || l.bpfCollectionLoader.pluginsEnabled {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("unmodified Cilium collection loader is unavailable")
	}
	current, err := inspectSourceIPTCX(ctx, expected, nil)
	if err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if !sourceIPAttachmentMatches(receipt.observation, expected, current) {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("source IP datapath attachment changed since receipt publication")
	}
	if err := verifyRetainedSourceIPConfigMap(ctx, &current, receipt.observation); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if current != receipt.observation {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("source IP BPF configuration changed since receipt publication")
	}
	l.sourceIPReceiptMu.RLock()
	stillCurrent := l.sourceIPReceiptGenerations[expected.EndpointID] == generation &&
		l.sourceIPReceipts[expected.EndpointID] == receipt
	l.sourceIPReceiptMu.RUnlock()
	if !stillCurrent {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("source IP receipt was invalidated during verification")
	}
	if err := ctx.Err(); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	return current, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

const nativeL4Magic = "CL4SNAP1"
const nativeL4EntryBytes = 20

// The complete allocation bound is checked before decoding any count or name.
const MaxNativeZtunnelL4WireBytes = maxZtunnelPolicyEntries*nativeL4EntryBytes + 128

// NativeZtunnelL4Expectation is supplied by the independently authenticated
// current source-policy envelope, never copied out of the payload being decoded.
// This is an exact binding, not a persistence/freshness or anti-replay protocol.
type NativeZtunnelL4Expectation struct {
	Owner            cmtypes.ClusterInfo
	PolicyRevision   uint64
	SelectorRevision uint64
	Digest           string
}

func validateNativeZtunnelL4Owner(owner cmtypes.ClusterInfo) error {
	if err := owner.ValidateStrict(); err != nil {
		return err
	}
	if owner.MaxConnectedClusters != 255 && owner.MaxConnectedClusters != cmtypes.ClusterIDExt511 {
		return fmt.Errorf("unsupported native identity allocation")
	}
	return nil
}

func validateNativeZtunnelL4Entry(key Key, entry MapStateEntry) error {
	if key.PortPrefixLen() > 16 ||
		key.WithPortPrefix(key.DestPort, key.PortPrefixLen()).DestPort != key.DestPort ||
		(key.Nexthdr == 0 && (key.DestPort != 0 || key.PortPrefixLen() != 0)) {
		return fmt.Errorf("noncanonical native protocol/port wildcard or prefix")
	}
	// CIDR/local-scope entries require a distinct source-address/identity
	// contract. The first workload-only transport refuses them, rather than
	// silently dropping them or treating them as workload SPIFFE identities.
	if key.Identity.HasLocalScope() {
		return fmt.Errorf("native local-scope/CIDR policy is unsupported")
	}
	if !entry.IsValid() || entry.ProxyPort != 0 ||
		(!entry.Precedence.IsDeny() && entry.Precedence != entry.Precedence.AllowPrecedence()) {
		return fmt.Errorf("unsupported invalid/Pass/L7/proxy native policy entry")
	}
	return nil
}

func compareNativeZtunnelL4Key(a, b Key) int {
	for _, order := range []int{
		cmp.Compare(a.TrafficDirection(), b.TrafficDirection()),
		cmp.Compare(a.Nexthdr, b.Nexthdr), cmp.Compare(a.DestPort, b.DestPort),
		cmp.Compare(a.PortPrefixLen(), b.PortPrefixLen()), cmp.Compare(a.Identity, b.Identity),
	} {
		if order != 0 {
			return order
		}
	}
	return 0
}

func (s *ZtunnelL4Snapshot) Owner() cmtypes.ClusterInfo {
	if s == nil {
		return cmtypes.ClusterInfo{}
	}
	return s.state.clusterInfo
}

// VerifyNativeMap checks every kernel-dumped key and value against the exact
// immutable native snapshot. It does not attest that this map is reachable
// from the current attached programs, source-IP checking, capture or TLS.
func (s *ZtunnelL4Snapshot) VerifyNativeMap(actual policyTypes.MapStateMap) error {
	if s == nil || actual == nil || len(actual) != len(s.state.entries) {
		return fmt.Errorf("native policy map is absent or has a different key set")
	}
	for key, expected := range s.state.entries {
		value, found := actual[key]
		if !found || value != expected.MapStateEntry {
			return fmt.Errorf("native policy map entry differs from current realized snapshot")
		}
		if err := validateNativeZtunnelL4Entry(key, value); err != nil {
			return err
		}
	}
	return nil
}

// Egress returns the snapshot restricted to its egress entries: the only part
// a remote destination compiles a source with. An egress lookup never reaches
// an ingress key: the traffic direction is always the first bit of the LPM
// prefix, and keys of opposite directions share no prefix
// (types.LPMKey.CommonPrefix), so every egress verdict is unchanged. Revisions are kept; the digests describe the restricted content.
func (s *ZtunnelL4Snapshot) Egress() (*ZtunnelL4Snapshot, error) {
	if s == nil {
		return nil, fmt.Errorf("native policy snapshot unavailable")
	}
	egress := newMapState(s.state.logger, MapStateSizes{}, allFeatures, s.state.clusterInfo)
	for key, entry := range s.state.entries {
		if key.TrafficDirection() == trafficdirection.Egress {
			egress.upsert(key, NewMapStateEntry(entry.MapStateEntry))
		}
	}
	return cloneZtunnelL4Snapshot(egress, s.revision, s.selectorRevision)
}

// MarshalNative exports only a previously captured native snapshot. The digest
// is an integrity/content binding, NOT a signature, source lease or grant.
// Wire values are deterministic fixed-width big-endian fields, bounded to4096
// entries. No JSON duplicate keys, permissive enum parsing or trailing payloads.
func (s *ZtunnelL4Snapshot) MarshalNative() ([]byte, string, error) {
	if s == nil || s.revision == 0 || s.selectorRevision == 0 || len(s.state.entries) > maxZtunnelPolicyEntries {
		return nil, "", fmt.Errorf("native policy snapshot unavailable or exceeds bound")
	}
	owner := s.Owner()
	if err := validateNativeZtunnelL4Owner(owner); err != nil {
		return nil, "", err
	}
	if len(owner.Name) == 0 || len(owner.Name) > 32 {
		return nil, "", fmt.Errorf("invalid native policy owner name")
	}
	keys := make([]Key, 0, len(s.state.entries))
	for key, entry := range s.state.entries {
		if err := validateNativeZtunnelL4Entry(key, entry.MapStateEntry); err != nil {
			return nil, "", err
		}
		keys = append(keys, key)
	}
	slices.SortFunc(keys, compareNativeZtunnelL4Key)
	wire := make([]byte, 0, 69+len(owner.Name)+len(keys)*nativeL4EntryBytes)
	wire = append(wire, nativeL4Magic...)
	wire = binary.BigEndian.AppendUint32(wire, owner.ID)
	wire = binary.BigEndian.AppendUint32(wire, owner.MaxConnectedClusters)
	wire = append(wire, byte(len(owner.Name)))
	wire = append(wire, owner.Name...)
	wire = binary.BigEndian.AppendUint64(wire, s.revision)
	wire = binary.BigEndian.AppendUint64(wire, uint64(s.selectorRevision))
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(keys)))
	for _, key := range keys {
		entry := s.state.entries[key]
		wire = append(wire, byte(key.TrafficDirection()), byte(key.Nexthdr), key.PortPrefixLen(), 0)
		wire = binary.BigEndian.AppendUint32(wire, uint32(key.Identity))
		wire = binary.BigEndian.AppendUint16(wire, key.DestPort)
		wire = binary.BigEndian.AppendUint16(wire, 0)
		wire = binary.BigEndian.AppendUint32(wire, uint32(entry.Precedence))
		wire = binary.BigEndian.AppendUint32(wire, entry.Cookie)
	}
	digest := sha256.Sum256(wire)
	wire = append(wire, digest[:]...)
	return wire, hex.EncodeToString(digest[:]), nil
}

// DecodeNativeZtunnelL4 restores native map lookup semantics only after exact
// expected owner, revision and digest checks. It does NOT authenticate that
// expectation. Direct-origin TLS/session/lease, membership, current selector
// state, source capture and realized SIP attestation remain separate gates.
func DecodeNativeZtunnelL4(logger *slog.Logger, expected NativeZtunnelL4Expectation, wire []byte) (*ZtunnelL4Snapshot, error) {
	if logger == nil {
		return nil, fmt.Errorf("native snapshot logger unavailable")
	}
	if err := validateNativeZtunnelL4Owner(expected.Owner); err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(expected.Digest)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != expected.Digest ||
		expected.PolicyRevision == 0 || expected.SelectorRevision == 0 {
		return nil, fmt.Errorf("independent native policy expectation incomplete")
	}
	if len(wire) < 70 || len(wire) > MaxNativeZtunnelL4WireBytes || string(wire[:8]) != nativeL4Magic {
		return nil, fmt.Errorf("invalid native policy wire size or version")
	}
	body, trailer := wire[:len(wire)-sha256.Size], wire[len(wire)-sha256.Size:]
	actual := sha256.Sum256(body)
	if !bytes.Equal(actual[:], digest) || !bytes.Equal(trailer, digest) {
		return nil, fmt.Errorf("native policy content digest mismatch")
	}
	nameLen := int(body[16])
	if nameLen == 0 || nameLen > 32 || len(body) < 37+nameLen {
		return nil, fmt.Errorf("invalid native policy owner encoding")
	}
	owner := cmtypes.ClusterInfo{ID: binary.BigEndian.Uint32(body[8:12]),
		MaxConnectedClusters: binary.BigEndian.Uint32(body[12:16]), Name: string(body[17 : 17+nameLen])}
	offset := 17 + nameLen
	revision := binary.BigEndian.Uint64(body[offset : offset+8])
	offset += 8
	selectors := binary.BigEndian.Uint64(body[offset : offset+8])
	offset += 8
	count := binary.BigEndian.Uint32(body[offset : offset+4])
	offset += 4
	if owner != expected.Owner || revision != expected.PolicyRevision || selectors != expected.SelectorRevision {
		return nil, fmt.Errorf("native owner or policy/selector revision mismatch")
	}
	if count > maxZtunnelPolicyEntries || len(body)-offset != int(count)*nativeL4EntryBytes {
		return nil, fmt.Errorf("native policy entry count or trailing bytes invalid")
	}
	state := newMapState(logger, MapStateSizes{}, allFeatures, owner)
	var previous Key
	for i := range count {
		encoded := body[offset : offset+nativeL4EntryBytes]
		offset += nativeL4EntryBytes
		direction, prefix := encoded[0], encoded[2]
		if direction > 1 || prefix > 16 || encoded[3] != 0 || binary.BigEndian.Uint16(encoded[10:12]) != 0 {
			return nil, fmt.Errorf("native policy entry direction/prefix/reserved fields invalid")
		}
		port := binary.BigEndian.Uint16(encoded[8:10])
		key := KeyForDirection(trafficdirection.TrafficDirection(direction)).
			WithProto(u8proto.U8proto(encoded[1])).WithPortPrefix(port, prefix).
			WithIdentity(identity.NumericIdentity(binary.BigEndian.Uint32(encoded[4:8])))
		if key.DestPort != port {
			return nil, fmt.Errorf("native policy port prefix has nonzero host bits")
		}
		entry := MapStateEntry{Precedence: policyTypes.Precedence(binary.BigEndian.Uint32(encoded[12:16])),
			Cookie: binary.BigEndian.Uint32(encoded[16:20])}
		if err := validateNativeZtunnelL4Entry(key, entry); err != nil {
			return nil, err
		}
		if i > 0 && compareNativeZtunnelL4Key(previous, key) >= 0 {
			return nil, fmt.Errorf("duplicate or unordered native policy key")
		}
		state.upsert(key, NewMapStateEntry(entry))
		previous = key
	}
	restored, err := cloneZtunnelL4Snapshot(state, revision, policyTypes.SelectorRevision(selectors))
	if err != nil {
		return nil, err
	}
	// Exact canonical re-encoding also refuses ambiguous wire representations.
	roundtrip, _, err := restored.MarshalNative()
	if err != nil || !bytes.Equal(roundtrip, wire) {
		return nil, fmt.Errorf("noncanonical native policy encoding")
	}
	return restored, nil
}

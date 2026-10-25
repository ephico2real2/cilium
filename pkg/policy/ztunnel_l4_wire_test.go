// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

func nativeWireSnapshot(t *testing.T) (*ZtunnelL4Snapshot, []byte, NativeZtunnelL4Expectation) {
	t.Helper()
	native := ztunnelTestPolicy(t, map[Key]MapStateEntry{
		EgressKey().WithIdentity(identity.ReservedIdentityAggregateCluster).WithTCPPortPrefix(8192, 12): policyTypes.AllowEntry(),
		EgressKey().WithIdentity(1<<16 | 1001).WithTCPPort(8193):                                        policyTypes.DenyEntry(),
		IngressKey().WithIdentity(identity.ReservedIdentityAggregateClusterMesh):                        policyTypes.AllowEntry(),
		IngressKey().WithIdentity(1<<16 | 1002).WithUDPPort(8080):                                       policyTypes.AllowEntry(),
	})
	snapshot, err := native.SnapshotZtunnelL4(7)
	require.NoError(t, err)
	wire, digest, err := snapshot.MarshalNative()
	require.NoError(t, err)
	return snapshot, wire, NativeZtunnelL4Expectation{Owner: snapshot.Owner(), PolicyRevision: snapshot.Revision(),
		SelectorRevision: snapshot.SelectorRevision(), Digest: digest}
}
func nativeRehash(wire []byte) string {
	hash := sha256.Sum256(wire[:len(wire)-sha256.Size])
	copy(wire[len(wire)-sha256.Size:], hash[:])
	return hex.EncodeToString(hash[:])
}
func TestNativeZtunnelWireRoundTripKeepsExactNativeLPMAndAggregateSemantics(t *testing.T) {
	snapshot, wire, expected := nativeWireSnapshot(t)
	restored, err := DecodeNativeZtunnelL4(hivetest.Logger(t), expected, wire)
	require.NoError(t, err)
	require.Equal(t, snapshot.Digest(), restored.Digest())
	require.Equal(t, snapshot.Owner(), restored.Owner())
	for _, id := range []identity.NumericIdentity{1<<16 | 1001, 1<<16 | 1002, 2<<16 | 1002} {
		for port := uint32(1); port <= 65535; port++ {
			for _, ingress := range []bool{false, true} {
				require.Equal(t, snapshot.permits(id, uint16(port), ingress), restored.permits(id, uint16(port), ingress),
					"id=%d port=%d ingress=%v", id, port, ingress)
			}
		}
	}
	encoded, digest, err := restored.MarshalNative()
	require.NoError(t, err)
	require.Equal(t, wire, encoded)
	require.Equal(t, expected.Digest, digest)
	require.False(t, restored.permits(1<<16|1001, 8193, false), "exact deny retains priority over aggregate allow")
	require.True(t, restored.permits(1<<16|1002, 8193, false))
	require.False(t, restored.permits(1<<16|1002, 8080, true), "UDP allow is not TCP permission")
}
func TestNativeZtunnelWireIndependentOwnerRevisionAndDigestAreMandatory(t *testing.T) {
	_, wire, expected := nativeWireSnapshot(t)
	for _, tc := range []struct {
		name   string
		mutate func(*NativeZtunnelL4Expectation)
	}{
		{"cluster-id", func(e *NativeZtunnelL4Expectation) { e.Owner.ID = 2 }},
		{"cluster-name", func(e *NativeZtunnelL4Expectation) { e.Owner.Name = "cluster-b" }},
		{"allocation", func(e *NativeZtunnelL4Expectation) { e.Owner.MaxConnectedClusters = 511 }},
		{"policy-revision", func(e *NativeZtunnelL4Expectation) { e.PolicyRevision++ }},
		{"selector-revision", func(e *NativeZtunnelL4Expectation) { e.SelectorRevision++ }},
		{"missing-floor", func(e *NativeZtunnelL4Expectation) { e.PolicyRevision = 0 }},
		{"digest", func(e *NativeZtunnelL4Expectation) { e.Digest = strings.Repeat("f", 64) }},
		{"uppercase-digest", func(e *NativeZtunnelL4Expectation) { e.Digest = strings.ToUpper(e.Digest) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := expected
			tc.mutate(&candidate)
			_, err := DecodeNativeZtunnelL4(hivetest.Logger(t), candidate, wire)
			require.Error(t, err)
		})
	}
	_, err := DecodeNativeZtunnelL4(nil, expected, wire)
	require.Error(t, err)
}
func TestNativeZtunnelWireRejectsMalformedCanonicalEncodingsEvenWithMatchingHash(t *testing.T) {
	_, wire, expected := nativeWireSnapshot(t)
	offset := 37 + int(wire[16])
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"version", func(w []byte) []byte { w[7]++; return w }},
		{"name-length", func(w []byte) []byte { w[16] = 255; return w }},
		{"entry-bound", func(w []byte) []byte {
			binary.BigEndian.PutUint32(w[offset-4:offset], maxZtunnelPolicyEntries+1)
			return w
		}},
		{"direction", func(w []byte) []byte { w[offset] = 2; return w }},
		{"prefix", func(w []byte) []byte { w[offset+2] = 17; return w }},
		{"reserved-byte", func(w []byte) []byte { w[offset+3] = 1; return w }},
		{"reserved-word", func(w []byte) []byte { w[offset+10] = 1; return w }},
		{"pass", func(w []byte) []byte { binary.BigEndian.PutUint32(w[offset+12:offset+16], 0); return w }},
		{"redirect-precedence", func(w []byte) []byte { binary.BigEndian.PutUint32(w[offset+12:offset+16], 2); return w }},
		{"cidr-local-identity", func(w []byte) []byte {
			binary.BigEndian.PutUint32(w[offset+4:offset+8], uint32(identity.IdentityScopeLocal|123))
			return w
		}},
		{"duplicate-key", func(w []byte) []byte {
			copy(w[offset+nativeL4EntryBytes:offset+2*nativeL4EntryBytes], w[offset:offset+nativeL4EntryBytes])
			return w
		}},
		{"unordered-keys", func(w []byte) []byte {
			first := slices.Clone(w[offset : offset+nativeL4EntryBytes])
			copy(w[offset:offset+nativeL4EntryBytes], w[offset+nativeL4EntryBytes:offset+2*nativeL4EntryBytes])
			copy(w[offset+nativeL4EntryBytes:offset+2*nativeL4EntryBytes], first)
			return w
		}},
		{"port-host-bits", func(w []byte) []byte {
			w[offset+1] = 6
			w[offset+2] = 12
			binary.BigEndian.PutUint16(w[offset+8:offset+10], 8193)
			return w
		}},
		{"proto-wildcard-with-port", func(w []byte) []byte {
			w[offset+1] = 0
			w[offset+2] = 16
			binary.BigEndian.PutUint16(w[offset+8:offset+10], 8080)
			return w
		}},
		{"trailing-byte", func(w []byte) []byte {
			return append(w[:len(w)-sha256.Size], append([]byte{0}, make([]byte, sha256.Size)...)...)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := tc.mutate(slices.Clone(wire))
			candidate := expected
			candidate.Digest = nativeRehash(changed)
			_, err := DecodeNativeZtunnelL4(hivetest.Logger(t), candidate, changed)
			require.Error(t, err)
		})
	}
	for length := range len(wire) {
		_, err := DecodeNativeZtunnelL4(hivetest.Logger(t), expected, wire[:length])
		require.Error(t, err, "truncation at %d", length)
	}
	tooLarge := make([]byte, MaxNativeZtunnelL4WireBytes+1)
	_, err := DecodeNativeZtunnelL4(hivetest.Logger(t), expected, tooLarge)
	require.Error(t, err)
}
func TestNativeZtunnelExactKernelMapCheckRejectsEveryDifferenceAndRecovers(t *testing.T) {
	snapshot, _, _ := nativeWireSnapshot(t)
	original := make(policyTypes.MapStateMap)
	for key, entry := range snapshot.state.entries {
		original[key] = entry.MapStateEntry
	}
	require.NoError(t, snapshot.VerifyNativeMap(original))
	key := EgressKey().WithIdentity(1<<16 | 1001).WithTCPPort(8193)
	for _, tc := range []struct {
		name   string
		mutate func(policyTypes.MapStateMap)
	}{
		{"missing-key", func(m policyTypes.MapStateMap) { delete(m, key) }},
		{"extra-key", func(m policyTypes.MapStateMap) { m[IngressKey().WithTCPPort(8443)] = policyTypes.AllowEntry() }},
		{"deny-to-allow", func(m policyTypes.MapStateMap) { m[key] = policyTypes.AllowEntry() }},
		{"precedence", func(m policyTypes.MapStateMap) {
			v := m[key]
			v.Precedence = policyTypes.LowestPriority.ToDenyPrecedence()
			m[key] = v
		}},
		{"cookie", func(m policyTypes.MapStateMap) { v := m[key]; v.Cookie++; m[key] = v }},
		{"proxy-port", func(m policyTypes.MapStateMap) { v := m[key]; v.ProxyPort = 15000; m[key] = v }},
		{"invalid", func(m policyTypes.MapStateMap) { v := m[key]; v.Invalidate(); m[key] = v }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := make(policyTypes.MapStateMap)
			maps.Copy(changed, original)
			tc.mutate(changed)
			require.Error(t, snapshot.VerifyNativeMap(changed))
			require.NoError(t, snapshot.VerifyNativeMap(original))
		})
	}
	require.Error(t, snapshot.VerifyNativeMap(nil))
}
func TestNativeZtunnelWireRemoteRoundTripFeedsExistingBothDirectionCompiler(t *testing.T) {
	info := cmtypes.ClusterInfo{ID: 1, Name: "cluster-a", MaxConnectedClusters: 255}
	destination := ztunnelTestSubject(t, 1, 1<<16|1000, "22222222-2222-4222-8222-222222222222", "10.1.0.1",
		map[Key]MapStateEntry{IngressKey().WithIdentity(2<<16 | 1000).WithTCPPort(8080): policyTypes.AllowEntry(),
			IngressKey().WithIdentity(2<<16 | 1000).WithTCPPort(31337): policyTypes.AllowEntry()})
	sourcePolicy := ztunnelTestPolicy(t, map[Key]MapStateEntry{
		EgressKey().WithIdentity(1<<16 | 1000).WithTCPPort(8080):  policyTypes.AllowEntry(),
		EgressKey().WithIdentity(1<<16 | 1000).WithTCPPort(31337): policyTypes.DenyEntry(),
	})
	sourcePolicy.policyMapState.clusterInfo = cmtypes.ClusterInfo{ID: 2, Name: "cluster-b", MaxConnectedClusters: 255}
	snapshot, err := sourcePolicy.SnapshotZtunnelL4(7)
	require.NoError(t, err)
	wire, digest, err := snapshot.MarshalNative()
	require.NoError(t, err)
	restored, err := DecodeNativeZtunnelL4(hivetest.Logger(t), NativeZtunnelL4Expectation{
		Owner: snapshot.Owner(), PolicyRevision: 7, SelectorRevision: snapshot.SelectorRevision(), Digest: digest}, wire)
	require.NoError(t, err)
	source := ZtunnelPolicySubject{ClusterID: 2, ClusterName: "cluster-b", TrustDomain: "cluster-b.mesh", EndpointID: 2,
		Namespace: "orders", NamespaceUID: "11111111-1111-4111-8111-111111111111", PodUID: "33333333-3333-4333-8333-333333333333",
		ServiceAccount: "api", NumericIdentity: 2<<16 | 1000, Addresses: destination.Addresses, Policy: restored}
	source.Addresses = slices.Clone(source.Addresses)
	source.Addresses[0] = source.Addresses[0].Next()
	plan, err := CompileZtunnelTCP(info, destination, []ZtunnelPolicySubject{source})
	require.NoError(t, err)
	require.Len(t, plan.ReviewAuthorization.Rules, 1)
	require.Equal(t, []uint32{8080}, plan.ReviewAuthorization.Rules[0].Clauses[0].Matches[0].DestinationPorts)
	require.Equal(t, "cilium_l4_review_only", plan.ReviewAuthorization.Name, "wire decoding is not live allow publication")
}
func TestNativeZtunnelWireV1GoldenEmptyDenyAndExactBound(t *testing.T) {
	native := ztunnelTestPolicy(t, nil)
	native.policyMapState.clusterInfo.Name = "a"
	snapshot, err := native.SnapshotZtunnelL4(7)
	require.NoError(t, err)
	encoded, digest, err := snapshot.MarshalNative()
	require.NoError(t, err)
	require.Equal(t, "434c34534e41503100000001000000ff016100000000000000070000000000000001000000003eb8bfd5a25742eb7c11772b48e2a9ed35fe6140b06e04bd935785ea95e73367", hex.EncodeToString(encoded))
	decoded, err := DecodeNativeZtunnelL4(hivetest.Logger(t), NativeZtunnelL4Expectation{
		Owner: snapshot.Owner(), PolicyRevision: 7, SelectorRevision: 1, Digest: digest}, encoded)
	require.NoError(t, err)
	for _, ingress := range []bool{true, false} {
		require.False(t, decoded.permits(1<<16|1000, 8080, ingress))
	}
	require.NoError(t, decoded.VerifyNativeMap(make(policyTypes.MapStateMap)))
	entries := make(map[Key]MapStateEntry)
	for i := range maxZtunnelPolicyEntries {
		entries[EgressKey().WithIdentity(identity.NumericIdentity(1<<16|uint32(1000+i))).WithTCPPort(8080)] = policyTypes.AllowEntry()
	}
	native = ztunnelTestPolicy(t, entries)
	snapshot, err = native.SnapshotZtunnelL4(7)
	require.NoError(t, err)
	encoded, digest, err = snapshot.MarshalNative()
	require.NoError(t, err)
	require.LessOrEqual(t, len(encoded), MaxNativeZtunnelL4WireBytes)
	decoded, err = DecodeNativeZtunnelL4(hivetest.Logger(t), NativeZtunnelL4Expectation{
		Owner: snapshot.Owner(), PolicyRevision: 7, SelectorRevision: snapshot.SelectorRevision(), Digest: digest}, encoded)
	require.NoError(t, err)
	require.Equal(t, snapshot.Digest(), decoded.Digest())
	native.policyMapState.upsert(EgressKey().WithIdentity(1<<16|6000).WithTCPPort(8080), NewMapStateEntry(policyTypes.AllowEntry()))
	_, err = native.SnapshotZtunnelL4(7)
	require.Error(t, err)
}
func TestNativeZtunnelCaptureRejectsUnsupportedCIDRPassAndMalformedWildcards(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   Key
		entry MapStateEntry
	}{
		{"cidr", EgressKey().WithIdentity(identity.MinLocalIdentity).WithTCPPort(80), policyTypes.AllowEntry()},
		{"pass", EgressKey().WithTCPPort(80), MapStateEntry{Precedence: 0}},
		{"redirect-residue", EgressKey().WithTCPPort(80), MapStateEntry{Precedence: 2}},
		{"proxy", EgressKey().WithTCPPort(80), policyTypes.AllowEntry().WithProxyPort(15000)},
		{"invalid", EgressKey().WithTCPPort(80), policyTypes.InvalidEntry()},
		{"proto-wildcard-port", EgressKey().WithPort(80), policyTypes.AllowEntry()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			native := ztunnelTestPolicy(t, map[Key]MapStateEntry{tc.key: tc.entry})
			snapshot, err := native.SnapshotZtunnelL4(7)
			require.Error(t, err)
			require.Nil(t, snapshot)
		})
	}
}

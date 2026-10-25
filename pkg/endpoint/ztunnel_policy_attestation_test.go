// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8stypes "k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	testcompute "github.com/cilium/cilium/pkg/testutils/compute"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

// Only DumpToMapStateMap is used. Embedding the production interface keeps the
// test focused on actual native policy computation and map-I/O faults without
// introducing a production snapshot/test-writer escape hatch.
type nativeObservationMap struct {
	policymap.PolicyMap
	entries policyTypes.MapStateMap
	calls   int
	onDump  func(int) error
}

func (m *nativeObservationMap) DumpToMapStateMap() (policyTypes.MapStateMap, error) {
	m.calls++
	if m.onDump != nil {
		if err := m.onDump(m.calls); err != nil {
			return nil, err
		}
	}
	return maps.Clone(m.entries), nil
}

func (m *nativeObservationMap) KernelMapID() (uint32, error) {
	return 0, policymap.ErrKernelMapIDUnavailable
}
func nativeObservationEndpoint(t *testing.T) (*Endpoint, *nativeObservationMap) {
	t.Helper()
	previous := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled("always")
	t.Cleanup(func() { policy.SetPolicyEnabled(previous) })
	logger := hivetest.Logger(t)
	info := cmtypes.ClusterInfo{ID: 1, Name: "cluster-a", MaxConnectedClusters: 255}
	podLabels := labels.Labels{"pod": labels.NewLabel("k8s:pod", "", "")}
	podID := identity.NewIdentity(1<<16|1000, podLabels)
	peerID := identity.NewIdentity(1<<16|1001, labels.Labels{"peer": labels.NewLabel("k8s:peer", "", "")})
	cache := identity.IdentityMap{podID.ID: podID.Labels, peerID.ID: peerID.Labels}
	allocator := testidentity.NewMockIdentityAllocator(cache)
	idManager := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, info, allocator.GetIdentityCache(), nil, nil, idManager, testpolicy.NewPolicyMetricsNoop())
	computer := testcompute.InstantiateCellForTesting(t, logger, "native-policy-observation", "Native policy map observation tests", repo, idManager)
	var wg sync.WaitGroup
	repo.GetSelectorCache().UpdateIdentities(cache, nil, &wg)
	wg.Wait()
	idManager.Add(podID)
	idManager.Add(peerID)
	f := &policyTestFixture{repo: repo, polComputer: computer, idManager: idManager, podID: podID}
	selector := computeSelectorPolicy(t, f, "native-map-observation")
	endpoint := &Endpoint{ID: 12, state: StateReady, SecurityIdentity: podID,
		K8sNamespace: "orders", K8sPodName: "api", K8sUID: "22222222-2222-4222-8222-222222222222",
		NetNsCookie: 12345, ifIndex: 10, containerNetnsPath: "/proc/fixture/ns/net", IPv4: netip.MustParseAddr("10.1.0.10")}
	endpoint.logger.Store(logger)
	container := strings.Repeat("a", 64)
	endpoint.containerID.Store(&container)
	endpoint.SetK8sNamespaceUID("11111111-1111-4111-8111-111111111111")
	endpoint.SetPod(&slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{Namespace: "orders", Name: "api", UID: k8stypes.UID(endpoint.K8sUID)},
		Spec: slim_corev1.PodSpec{ServiceAccountName: "api", NodeName: "node-a"}})
	// Distill via the real repository/selector/endpoint policy API, not an
	// imported wire map or a fabricated revision-only policy object.
	distilled := selector.DistillPolicy(logger, endpoint, nil)
	require.NoError(t, distilled.Ready())
	endpoint.desiredPolicy = distilled
	endpoint.realizedPolicy = distilled
	endpoint.policyRevision = selector.GetRevision()
	endpoint.desiredPolicyRevision = endpoint.policyRevision
	t.Cleanup(func() { distilled.Detach(logger) })
	entries := make(policyTypes.MapStateMap)
	maps.Insert(entries, distilled.Entries())
	observed := &nativeObservationMap{entries: entries}
	endpoint.policyMap = observed
	return endpoint, observed
}
func TestNativePolicyMapObservationUsesActualMapsAndReturnsDefensivePublicState(t *testing.T) {
	endpoint, observed := nativeObservationEndpoint(t)
	snapshot, err := endpoint.SnapshotZtunnelPolicyMap(t.Context())
	require.NoError(t, err)
	require.Equal(t, 2, observed.calls)
	require.Equal(t, uint64(12345), snapshot.NetNSCookie())
	require.Equal(t, "/proc/fixture/ns/net", snapshot.NetNSPath())
	require.Equal(t, uint32(10), snapshot.InterfaceIndex())
	require.Zero(t, snapshot.KernelPolicyMapID(), "test policy maps must not fabricate a kernel ID")
	_, err = snapshot.ReachabilityIdentity()
	require.Error(t, err, "in-memory policy-map snapshots cannot become kernel reachability evidence")
	require.Equal(t, "node-a", snapshot.NodeName())
	require.Len(t, snapshot.Digest(), 64)
	subject := snapshot.Subject()
	require.Equal(t, uint32(1), subject.ClusterID)
	require.Equal(t, "cluster-a", subject.ClusterName)
	require.Empty(t, subject.TrustDomain, "policy maps cannot invent issuer/domain authority")
	wire := snapshot.Wire()
	wire[0] ^= 0xff
	subject.Addresses[0] = netip.MustParseAddr("10.9.9.9")
	require.NotEqual(t, wire, snapshot.Wire())
	require.Equal(t, endpoint.IPv4, snapshot.Subject().Addresses[0])
	native, err := policy.DecodeNativeZtunnelL4(hivetest.Logger(t), policy.NativeZtunnelL4Expectation{
		Owner: snapshot.Subject().Policy.Owner(), PolicyRevision: snapshot.Subject().Policy.Revision(),
		SelectorRevision: snapshot.Subject().Policy.SelectorRevision(), Digest: snapshot.WireDigest()}, snapshot.Wire())
	require.NoError(t, err)
	require.Equal(t, snapshot.Subject().Policy.Digest(), native.Digest())
}
func TestNativePolicyMapObservationRejectsDumpFailureMismatchAndBetweenDumpMutation(t *testing.T) {
	for _, name := range []string{"first-error", "second-error", "missing-key", "extra-key", "second-mutation", "namespace-change", "pod-replacement", "cancel-after-first", "cancel-after-second"} {
		t.Run(name, func(t *testing.T) {
			endpoint, observed := nativeObservationEndpoint(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var first policyTypes.Key
			for key := range observed.entries {
				first = key
				break
			}
			require.NotEmpty(t, observed.entries)
			observed.onDump = func(call int) error {
				switch {
				case name == "first-error" && call == 1:
					return errors.New("injected first dump")
				case name == "second-error" && call == 2:
					return errors.New("injected second dump")
				case name == "missing-key":
					delete(observed.entries, first)
				case name == "extra-key":
					observed.entries[policy.IngressKey().WithTCPPort(3333)] = policyTypes.AllowEntry()
				case name == "second-mutation" && call == 2:
					entry := observed.entries[first]
					entry.Cookie++
					observed.entries[first] = entry
				case name == "namespace-change" && call == 2:
					endpoint.SetK8sNamespaceUID("33333333-3333-4333-8333-333333333333")
				case name == "pod-replacement" && call == 2:
					pod := endpoint.GetPod().DeepCopy()
					pod.UID = "44444444-4444-4444-8444-444444444444"
					endpoint.SetPod(pod)
				case name == "cancel-after-first" && call == 1:
					cancel()
				case name == "cancel-after-second" && call == 2:
					cancel()
				}
				return nil
			}
			snapshot, err := endpoint.SnapshotZtunnelPolicyMap(ctx)
			require.Error(t, err)
			require.Nil(t, snapshot)
			if strings.HasPrefix(name, "cancel-") {
				require.ErrorIs(t, err, context.Canceled)
			}
		})
	}
}
func TestNativePolicyMapObservationRejectsUnknownIncarnationAndUnrealizedState(t *testing.T) {
	for _, name := range []string{"nil-map", "restoring", "desired-differs", "stale-revision", "nil-identity", "namespace-uid", "pod-uid", "missing-cni-uid", "container", "cookie", "ifindex", "netns-path", "host-network", "secondary-interface", "local-identity"} {
		t.Run(name, func(t *testing.T) {
			endpoint, _ := nativeObservationEndpoint(t)
			switch name {
			case "nil-map":
				endpoint.policyMap = nil
			case "restoring":
				endpoint.state = StateRestoring
			case "desired-differs":
				endpoint.desiredPolicy = &policy.EndpointPolicy{}
			case "stale-revision":
				endpoint.desiredPolicyRevision++
			case "nil-identity":
				endpoint.SecurityIdentity = nil
			case "namespace-uid":
				endpoint.SetK8sNamespaceUID("")
			case "pod-uid":
				endpoint.K8sUID = "33333333-3333-4333-8333-333333333333"
			case "missing-cni-uid":
				endpoint.K8sUID = ""
			case "container":
				endpoint.containerID.Store(nil)
			case "cookie":
				endpoint.NetNsCookie = 0
			case "ifindex":
				endpoint.ifIndex = 0
			case "netns-path":
				endpoint.containerNetnsPath = "relative/netns"
			case "host-network":
				pod := endpoint.GetPod().DeepCopy()
				pod.Spec.HostNetwork = true
				endpoint.SetPod(pod)
			case "secondary-interface":
				endpoint.isSecondaryInterface = true
			case "local-identity":
				endpoint.SecurityIdentity = identity.NewIdentity(identity.MinLocalIdentity, labels.Labels{})
			}
			snapshot, err := endpoint.SnapshotZtunnelPolicyMap(t.Context())
			require.Error(t, err)
			require.Nil(t, snapshot)
		})
	}
}
func TestNativePolicyMapObservationBusyIsNonblockingAndRecoveryReobserves(t *testing.T) {
	endpoint, observed := nativeObservationEndpoint(t)
	// Model an actual concurrent regeneration/update. Acquiring the same lock
	// twice in this goroutine is invalid under the debug-lock tracker.
	checkBusy := func(acquire, release func()) {
		t.Helper()
		held, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() {
			acquire()
			close(held)
			<-finish
			release()
			close(done)
		}()
		<-held
		defer func() { close(finish); <-done }()
		_, err := endpoint.SnapshotZtunnelPolicyMap(t.Context())
		require.ErrorIs(t, err, ErrZtunnelPolicyMapBusy)
	}
	checkBusy(endpoint.buildMutex.Lock, endpoint.buildMutex.Unlock)
	checkBusy(endpoint.mutex.Lock, endpoint.mutex.Unlock)
	before, err := endpoint.SnapshotZtunnelPolicyMap(t.Context())
	require.NoError(t, err)
	var key policyTypes.Key
	for candidate := range observed.entries {
		key = candidate
		break
	}
	original := observed.entries[key]
	changed := original
	changed.Cookie++
	observed.entries[key] = changed
	denied, err := endpoint.SnapshotZtunnelPolicyMap(t.Context())
	require.Error(t, err)
	require.Nil(t, denied)
	observed.entries[key] = original
	after, err := endpoint.SnapshotZtunnelPolicyMap(t.Context())
	require.NoError(t, err)
	require.Equal(t, before.Digest(), after.Digest(), "observation is stable content, not a renewable security lease")
}

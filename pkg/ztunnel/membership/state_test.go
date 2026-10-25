// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package membership

import (
	"errors"
	"testing"
	"time"
)

func TestPublicationSeparatesRequiredCapturedAndActive(t *testing.T) {
	registry := NewRegistry(17)
	ref := requireMembership(t, registry, "namespace-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	p, ok := registry.Publication(ref)
	if !ok || p.Version != 1 || p.State != PublicationRequired || p.Epoch != ref.Epoch || p.Generation != 0 {
		t.Fatalf("initial publication = %+v, want incomplete Required intent", p)
	}

	generation, ok := registry.BeginZDS(ref)
	if !ok {
		t.Fatal("BeginZDS rejected current membership")
	}
	p, ok = registry.Publication(ref)
	if !ok || p.State != PublicationRequired || p.Generation != generation {
		t.Fatalf("in-flight publication = %+v, want Required generation %d", p, generation)
	}
	if !registry.MarkCaptured(ref, generation) || !registry.AcknowledgeZDS(ref, generation) {
		t.Fatal("fresh capture/ZDS evidence was rejected")
	}
	p, ok = registry.Publication(ref)
	if !ok || p.State != PublicationCaptured || p.Generation != generation {
		t.Fatalf("captured publication = %+v, want Captured generation %d", p, generation)
	}
	establishAddressAndPolicy(t, registry, ref)
	state, found := registry.Get(ref)
	if !found || !state.Active() {
		t.Fatal("full source/ADS/policy state was not Active")
	}
	p, ok = registry.Publication(ref)
	if !ok || p.State != PublicationCaptured {
		t.Fatalf("source publication must never claim remote Active: %+v", p)
	}
	if _, ok := registry.BeginDrain(ref); !ok {
		t.Fatal("BeginDrain rejected captured membership")
	}
	p, ok = registry.Publication(ref)
	state, found = registry.Get(ref)
	if !ok || !found || p.State != PublicationDraining || state.Active() || state.ReadyForAddress() {
		t.Fatalf("draining publication = %+v, want Draining", p)
	}
}

func requireMembership(t *testing.T, registry *Registry, namespaceUID, podUID string, endpointID uint16, netns string) Reference {
	t.Helper()
	ref, err := registry.Require(namespaceUID, podUID, endpointID, netns)
	if err != nil {
		t.Fatalf("Require() error = %v", err)
	}
	return ref
}

func establishCaptureAndZDS(t *testing.T, registry *Registry, ref Reference) uint64 {
	t.Helper()
	generation, ok := registry.BeginZDS(ref)
	if !ok {
		t.Fatal("BeginZDS() rejected current membership")
	}
	if registry.AcknowledgeZDS(ref, generation) {
		t.Fatal("ZDS ACK advanced before capture was confirmed")
	}
	if !registry.MarkCaptured(ref, generation) {
		t.Fatal("MarkCaptured() rejected current membership")
	}
	if !registry.AcknowledgeZDS(ref, generation) {
		t.Fatal("AcknowledgeZDS() rejected matching generation")
	}
	return generation
}

func establishAddressAndPolicy(t *testing.T, registry *Registry, ref Reference) uint64 {
	t.Helper()
	generation := registry.BeginADSGeneration()
	if _, ok := registry.PublishAddress(ref, generation+100); ok {
		t.Fatal("PublishAddress() accepted a stale ADS generation")
	}
	addressVersion, ok := registry.PublishAddress(ref, generation)
	if !ok {
		t.Fatal("PublishAddress() rejected current, ZDS-acknowledged membership")
	}
	if registry.AcknowledgeAddress(ref, generation, addressVersion+1) {
		t.Fatal("AcknowledgeAddress() accepted a non-current resource version")
	}
	if !registry.AcknowledgeAddress(ref, generation, addressVersion) {
		t.Fatal("AcknowledgeAddress() rejected matching generation and resource version")
	}
	evidence := validPolicyEvidence(ref, addressVersion)
	if _, ok := registry.PublishPolicy(ref, generation, evidence); !ok {
		t.Fatal("PublishPolicy() rejected current address-acknowledged membership")
	}
	state, ok := registry.Get(ref)
	if !ok {
		t.Fatal("Get() lost current membership")
	}
	if !registry.AcknowledgePolicy(ref, generation, state.PolicyVersion) {
		t.Fatal("AcknowledgePolicy() rejected matching generation and resource version")
	}
	return generation
}

func validPolicyEvidence(ref Reference, addressVersion uint64) PolicyEvidence {
	return PolicyEvidence{
		WorkloadUID: ref.Key.PodUID, AddressVersion: addressVersion, Revision: "sha256:policy-revision",
		BoundToWorkload: true, RequiresAuthenticatedPeer: true, DenyByDefault: true,
	}
}

func TestActiveRequiresCaptureZDSAddressAndPolicyEvidence(t *testing.T) {
	registry := NewRegistry(17)
	ref := requireMembership(t, registry, "ns-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	if state, ok := registry.Get(ref); !ok || state.Active() {
		t.Fatalf("new membership must be present but inactive: state=%+v present=%v", state, ok)
	}

	establishCaptureAndZDS(t, registry, ref)
	state, _ := registry.Get(ref)
	if !state.ReadyForAddress() || state.Active() {
		t.Fatalf("ZDS readiness must not imply workload protection: %+v", state)
	}
	adsGeneration := registry.BeginADSGeneration()
	addressVersion, ok := registry.PublishAddress(ref, adsGeneration)
	if !ok {
		t.Fatal("PublishAddress() rejected ready membership")
	}
	if !registry.AcknowledgeAddress(ref, adsGeneration, addressVersion) {
		t.Fatal("AcknowledgeAddress() rejected matching token")
	}
	state, _ = registry.Get(ref)
	if state.Active() {
		t.Fatal("address ACK must not imply effective policy ACK")
	}
	state, _ = registry.Get(ref)
	policyVersion, ok := registry.PublishPolicy(ref, adsGeneration, validPolicyEvidence(ref, state.AddressVersion))
	if !ok || registry.AcknowledgePolicy(ref, adsGeneration, policyVersion+1) {
		t.Fatal("policy ACK accepted before the exact policy version was published")
	}
	if !registry.AcknowledgePolicy(ref, adsGeneration, policyVersion) {
		t.Fatal("AcknowledgePolicy() rejected matching token")
	}
	state, _ = registry.Get(ref)
	if !state.Active() {
		t.Fatalf("all current prerequisites were acknowledged; expected Active: %+v", state)
	}
}

func TestNewAddressInvalidatesPolicyEvidence(t *testing.T) {
	registry := NewRegistry(17)
	ref := requireMembership(t, registry, "ns-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	establishCaptureAndZDS(t, registry, ref)
	generation := establishAddressAndPolicy(t, registry, ref)

	old, _ := registry.Get(ref)
	newAddressVersion, ok := registry.PublishAddress(ref, generation)
	if !ok || newAddressVersion == old.AddressVersion {
		t.Fatal("publishing a replacement address must create a new resource version")
	}
	state, _ := registry.Get(ref)
	if state.Active() || state.PolicyVersion != 0 || state.PolicyAcked {
		t.Fatalf("new address must revoke prior policy evidence: %+v", state)
	}
	if registry.AcknowledgePolicy(ref, generation, old.PolicyVersion) {
		t.Fatal("stale policy ACK advanced membership after address replacement")
	}
	if !registry.AcknowledgeAddress(ref, generation, newAddressVersion) {
		t.Fatal("current address ACK rejected")
	}
	policyVersion, ok := registry.PublishPolicy(ref, generation, validPolicyEvidence(ref, newAddressVersion))
	if !ok || !registry.AcknowledgePolicy(ref, generation, policyVersion) {
		t.Fatal("fresh policy evidence failed after replacement address was acknowledged")
	}
}

func TestNewZDSGenerationInvalidatesDownstreamEvidence(t *testing.T) {
	registry := NewRegistry(17)
	ref := requireMembership(t, registry, "ns-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	oldZDSGeneration := establishCaptureAndZDS(t, registry, ref)
	oldADSGeneration := registry.BeginADSGeneration()
	addressVersion, ok := registry.PublishAddress(ref, oldADSGeneration)
	if !ok || !registry.AcknowledgeAddress(ref, oldADSGeneration, addressVersion) {
		t.Fatal("old address resource failed to ACK")
	}
	oldState, _ := registry.Get(ref)
	policyVersion, ok := registry.PublishPolicy(ref, oldADSGeneration, validPolicyEvidence(ref, oldState.AddressVersion))
	if !ok || !registry.AcknowledgePolicy(ref, oldADSGeneration, policyVersion) {
		t.Fatal("old policy resource failed to ACK")
	}

	newGeneration, ok := registry.BeginZDS(ref)
	if !ok || newGeneration == oldZDSGeneration {
		t.Fatal("BeginZDS() did not create a new generation")
	}
	state, _ := registry.Get(ref)
	if state.Active() || state.Captured || state.ZDSAcked || state.AddressVersion != 0 || state.PolicyVersion != 0 {
		t.Fatalf("new ZDS generation must clear all old evidence: %+v", state)
	}
	if registry.AcknowledgeZDS(ref, oldZDSGeneration) {
		t.Fatal("late ZDS ACK advanced the new generation")
	}
	if _, ok := registry.PublishAddress(ref, oldADSGeneration); ok {
		t.Fatal("address published before the new ZDS enrollment was acknowledged")
	}
	if !registry.MarkCaptured(ref, newGeneration) || !registry.AcknowledgeZDS(ref, newGeneration) {
		t.Fatal("new ZDS generation could not re-establish capture and ACK")
	}
	if _, ok := registry.PublishAddress(ref, oldADSGeneration); !ok {
		t.Fatal("current ADS stream could not republish address after fresh ZDS ACK")
	}
}

func TestADSReconnectFencesOldACKsAndRequiresFreshResources(t *testing.T) {
	registry := NewRegistry(17)
	ref := requireMembership(t, registry, "ns-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	establishCaptureAndZDS(t, registry, ref)
	oldGeneration := registry.BeginADSGeneration()
	oldAddress, ok := registry.PublishAddress(ref, oldGeneration)
	if !ok || !registry.AcknowledgeAddress(ref, oldGeneration, oldAddress) {
		t.Fatal("initial address resource failed to ACK")
	}
	state, _ := registry.Get(ref)
	oldPolicy, ok := registry.PublishPolicy(ref, oldGeneration, validPolicyEvidence(ref, state.AddressVersion))
	if !ok || !registry.AcknowledgePolicy(ref, oldGeneration, oldPolicy) {
		t.Fatal("initial policy resource failed to ACK")
	}

	newGeneration := registry.BeginADSGeneration()
	if newGeneration == oldGeneration {
		t.Fatal("ADS reconnect reused a stream generation")
	}
	if registry.AcknowledgeAddress(ref, oldGeneration, oldAddress) || registry.AcknowledgePolicy(ref, oldGeneration, oldPolicy) {
		t.Fatal("old stream ACK advanced current membership")
	}
	state, _ = registry.Get(ref)
	if state.Active() || state.AddressVersion != 0 || state.PolicyVersion != 0 {
		t.Fatalf("ADS reconnect must invalidate all downstream evidence: %+v", state)
	}
	addressVersion, ok := registry.PublishAddress(ref, newGeneration)
	if !ok || !registry.AcknowledgeAddress(ref, newGeneration, addressVersion) {
		t.Fatal("fresh stream address failed to ACK")
	}
	state, _ = registry.Get(ref)
	policyVersion, ok := registry.PublishPolicy(ref, newGeneration, validPolicyEvidence(ref, state.AddressVersion))
	if !ok || !registry.AcknowledgePolicy(ref, newGeneration, policyVersion) {
		t.Fatal("fresh stream policy failed to ACK")
	}
	state, _ = registry.Get(ref)
	if !state.Active() {
		t.Fatalf("fresh evidence should restore active state: %+v", state)
	}
}

func TestEndpointReplacementAndDrainFenceOldIncarnation(t *testing.T) {
	registry := NewRegistry(17)
	oldRef := requireMembership(t, registry, "ns-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	oldZDSGeneration := establishCaptureAndZDS(t, registry, oldRef)
	oldADSGeneration := establishAddressAndPolicy(t, registry, oldRef)

	if _, err := registry.Require("ns-uid", "pod-uid", 43, "/var/run/netns/pod-43"); err == nil {
		t.Fatal("replacement endpoint bypassed draining the previous incarnation")
	}
	if current, _, ok := registry.CurrentForPodUID("pod-uid"); !ok || current != oldRef {
		t.Fatalf("rejected replacement changed current endpoint: %+v present=%v", current, ok)
	}
	drainGeneration, ok := registry.BeginDrain(oldRef)
	if !ok || registry.CompleteDrain(oldRef, drainGeneration+1) {
		t.Fatal("drain completion accepted a stale generation")
	}
	oldState, _ := registry.Get(oldRef)
	if registry.AcknowledgeAddress(oldRef, oldADSGeneration, oldState.AddressVersion) {
		t.Fatal("late Address ACK advanced a draining endpoint")
	}
	if _, err := registry.Require("ns-uid", "pod-uid", 43, "/var/run/netns/pod-43"); err == nil {
		t.Fatal("replacement endpoint bypassed explicit flow-drain completion")
	}
	if !registry.CompleteDrain(oldRef, drainGeneration) || !registry.Retire(oldRef) {
		t.Fatal("completed old endpoint drain could not be retired")
	}
	newRef := requireMembership(t, registry, "ns-uid", "pod-uid", 43, "/var/run/netns/pod-43")
	if newRef.Incarnation == oldRef.Incarnation {
		t.Fatal("endpoint replacement reused the old incarnation")
	}
	if registry.AcknowledgeZDS(oldRef, oldZDSGeneration) {
		t.Fatal("old endpoint ACK advanced its replacement")
	}
	if registry.AcknowledgeAddress(oldRef, oldADSGeneration, 1) {
		t.Fatal("late address ACK advanced a retired endpoint")
	}
	newState, ok := registry.Get(newRef)
	if !ok || newState.Active() || newState.Captured || newState.ZDSAcked {
		t.Fatalf("replacement endpoint inherited protection evidence: %+v present=%v", newState, ok)
	}
	if _, err := registry.Require("ns-uid", "pod-uid", 42, "/var/run/netns/pod-42"); err == nil {
		t.Fatal("delayed add for the old endpoint replaced the current endpoint")
	}
	if current, _, ok := registry.CurrentForPodUID("pod-uid"); !ok || current != newRef {
		t.Fatalf("stale add changed current endpoint: %+v present=%v", current, ok)
	}
	if registry.Retire(newRef) {
		t.Fatal("Retire() accepted a non-draining endpoint")
	}
	newDrainGeneration, ok := registry.BeginDrain(newRef)
	if !ok {
		t.Fatal("BeginDrain() rejected current endpoint")
	}
	if state, _ := registry.Get(newRef); state.Active() {
		t.Fatal("draining endpoint remained active")
	}
	if _, err := registry.Require("ns-uid", "pod-uid", 43, "/var/run/netns/pod-43"); err == nil {
		t.Fatal("draining endpoint was silently reactivated")
	}
	pending := registry.PendingDrain()
	if len(pending) != 1 || pending[0].Incarnation != newRef.Incarnation {
		t.Fatalf("PendingDrain() returned unexpected entries: %+v", pending)
	}
	if registry.CompleteDrain(newRef, newDrainGeneration+1) || registry.Retire(newRef) {
		t.Fatal("stale drain completion or retirement was accepted")
	}
	if !registry.CompleteDrain(newRef, newDrainGeneration) || !registry.Retire(newRef) {
		t.Fatal("Retire() rejected current endpoint after confirmed flow drain")
	}
	if _, _, ok := registry.CurrentForPodUID("pod-uid"); ok {
		t.Fatal("retired Pod remained in the current index")
	}
	if pending := registry.PendingDrain(); len(pending) != 0 {
		t.Fatalf("retired endpoints remain pending: %+v", pending)
	}
}

func TestNamespaceUIDChangeAndRegistryClusterIdentity(t *testing.T) {
	registryA := NewRegistry(17)
	refA := requireMembership(t, registryA, "ns-old", "pod-uid", 42, "/var/run/netns/pod-42")
	if _, err := registryA.Require("ns-new", "pod-uid", 42, "/var/run/netns/pod-42"); err == nil {
		t.Fatal("recreated namespace inherited the previous namespace's active membership")
	}
	drainGeneration, ok := registryA.BeginDrain(refA)
	if !ok || !registryA.CompleteDrain(refA, drainGeneration) || !registryA.Retire(refA) {
		t.Fatal("old namespace membership could not be drained and retired")
	}
	refRecreated := requireMembership(t, registryA, "ns-new", "pod-uid", 42, "/var/run/netns/pod-42")
	if refRecreated.Incarnation == refA.Incarnation || refRecreated.Key.NamespaceUID != "ns-new" {
		t.Fatalf("namespace recreation inherited identity: old=%+v new=%+v", refA, refRecreated)
	}

	registryB := NewRegistry(18)
	refB := requireMembership(t, registryB, "ns-new", "pod-uid", 42, "/var/run/netns/pod-42")
	if refB.Key.ClusterID == refRecreated.Key.ClusterID || refB.Key.PodUID != refRecreated.Key.PodUID {
		t.Fatalf("cluster identity was not part of the membership key: A=%+v B=%+v", refRecreated.Key, refB.Key)
	}
}

func TestCaptureInvalidationRevokesAllDownstreamEvidence(t *testing.T) {
	registry := NewRegistry(17)
	ref := requireMembership(t, registry, "ns-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	oldZDSGeneration := establishCaptureAndZDS(t, registry, ref)
	oldADSGeneration := establishAddressAndPolicy(t, registry, ref)
	oldState, _ := registry.Get(ref)
	if !oldState.Active() {
		t.Fatalf("test setup failed to establish active state: %+v", oldState)
	}
	if !registry.InvalidateCapture(ref) {
		t.Fatal("InvalidateCapture() rejected current membership")
	}
	state, _ := registry.Get(ref)
	if state.Active() || state.Captured || state.ZDSAcked || state.AddressAcked || state.PolicyAcked || state.ZDSGeneration != 0 {
		t.Fatalf("capture invalidation retained downstream protection evidence: %+v", state)
	}
	if registry.AcknowledgeZDS(ref, oldZDSGeneration) || registry.MarkCaptured(ref, oldZDSGeneration) {
		t.Fatal("old ZDS generation restored capture after invalidation")
	}
	newZDSGeneration := establishCaptureAndZDS(t, registry, ref)
	if newZDSGeneration == oldZDSGeneration {
		t.Fatal("capture recovery reused the old ZDS generation")
	}
	if _, ok := registry.PublishAddress(ref, oldADSGeneration); !ok {
		t.Fatal("current ADS stream should accept a fresh Address after new capture and ZDS ACK")
	}
}

func TestDelayedCaptureCompletionCannotAdvanceNewZDSEpoch(t *testing.T) {
	registry := NewRegistry(17)
	ref := requireMembership(t, registry, "ns-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	oldGeneration, ok := registry.BeginZDS(ref)
	if !ok {
		t.Fatal("first BeginZDS() rejected membership")
	}
	newGeneration, ok := registry.BeginZDS(ref)
	if !ok || newGeneration == oldGeneration {
		t.Fatal("second BeginZDS() did not create a new epoch")
	}
	if registry.MarkCaptured(ref, oldGeneration) || registry.AcknowledgeZDS(ref, newGeneration) {
		t.Fatal("delayed capture completion satisfied the new ZDS epoch")
	}
	if !registry.MarkCaptured(ref, newGeneration) || !registry.AcknowledgeZDS(ref, newGeneration) {
		t.Fatal("matching capture completion and ZDS ACK were rejected")
	}
}

func TestPolicyEvidenceMustMatchAddressAndFailClosedWorkload(t *testing.T) {
	registry := NewRegistry(17)
	ref := requireMembership(t, registry, "ns-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	establishCaptureAndZDS(t, registry, ref)
	adsGeneration := registry.BeginADSGeneration()
	addressVersion, ok := registry.PublishAddress(ref, adsGeneration)
	if !ok || !registry.AcknowledgeAddress(ref, adsGeneration, addressVersion) {
		t.Fatal("address setup failed")
	}
	valid := validPolicyEvidence(ref, addressVersion)
	cases := []struct {
		name   string
		mutate func(*PolicyEvidence)
	}{
		{name: "wrong workload UID", mutate: func(e *PolicyEvidence) { e.WorkloadUID = "other-pod" }},
		{name: "stale address version", mutate: func(e *PolicyEvidence) { e.AddressVersion++ }},
		{name: "missing policy revision", mutate: func(e *PolicyEvidence) { e.Revision = "" }},
		{name: "not workload bound", mutate: func(e *PolicyEvidence) { e.BoundToWorkload = false }},
		{name: "does not require authenticated peer", mutate: func(e *PolicyEvidence) { e.RequiresAuthenticatedPeer = false }},
		{name: "does not deny by default", mutate: func(e *PolicyEvidence) { e.DenyByDefault = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evidence := valid
			tc.mutate(&evidence)
			if _, ok := registry.PublishPolicy(ref, adsGeneration, evidence); ok {
				t.Fatal("unsafe policy evidence was accepted")
			}
			state, _ := registry.Get(ref)
			if state.Active() {
				t.Fatal("invalid policy evidence made workload Active")
			}
		})
	}

	policyV1, ok := registry.PublishPolicy(ref, adsGeneration, valid)
	if !ok {
		t.Fatal("valid workload-bound policy evidence was rejected")
	}
	newAddressVersion, ok := registry.PublishAddress(ref, adsGeneration)
	if !ok || !registry.AcknowledgeAddress(ref, adsGeneration, newAddressVersion) {
		t.Fatal("replacement address setup failed")
	}
	if _, ok := registry.PublishPolicy(ref, adsGeneration, valid); ok {
		t.Fatal("stale policy compiler result was bound to a newer Address version")
	}
	if registry.AcknowledgePolicy(ref, adsGeneration, policyV1) {
		t.Fatal("stale policy ACK advanced the newer Address version")
	}
	state, _ := registry.Get(ref)
	if state.Active() {
		t.Fatal("new Address became Active with stale policy evidence")
	}
}

func TestRequireRejectsIncompleteIdentityAndIsIdempotent(t *testing.T) {
	registry := NewRegistry(17)
	for _, input := range [][3]string{{"", "pod", "/ns"}, {"ns", "", "/ns"}, {"ns", "pod", " "}} {
		if _, err := registry.Require(input[0], input[1], 42, input[2]); err == nil {
			t.Fatalf("Require(%q, %q, %q) accepted incomplete identity", input[0], input[1], input[2])
		}
	}
	first := requireMembership(t, registry, "ns-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	second := requireMembership(t, registry, "ns-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	if first != second {
		t.Fatalf("same endpoint requirement was not idempotent: first=%+v second=%+v", first, second)
	}
}

func TestRegistryRestartRejectsPriorExecutionAcknowledgments(t *testing.T) {
	old := NewRegistry(17)
	oldRef := requireMembership(t, old, "ns-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	oldZDS := establishCaptureAndZDS(t, old, oldRef)
	oldADS := establishAddressAndPolicy(t, old, oldRef)
	previous, _ := old.Get(oldRef)

	current := NewRegistry(17)
	ref := requireMembership(t, current, "ns-uid", "pod-uid", 42, "/var/run/netns/pod-42")
	if ref == oldRef {
		t.Fatal("registry restart reused the previous execution's membership reference")
	}
	if _, ok := current.Get(oldRef); ok {
		t.Fatal("prior execution reference resolved in the new registry")
	}
	zds, ok := current.BeginZDS(ref)
	if !ok || !current.MarkCaptured(ref, zds) {
		t.Fatal("fresh capture could not be established")
	}
	if zds != oldZDS {
		t.Fatal("test must exercise colliding per-execution ZDS counters")
	}
	if current.AcknowledgeZDS(oldRef, oldZDS) {
		t.Fatal("prior execution ZDS ACK was accepted")
	}
	if !current.AcknowledgeZDS(ref, zds) {
		t.Fatal("fresh ZDS ACK was rejected")
	}
	ads := current.BeginADSGeneration()
	address, ok := current.PublishAddress(ref, ads)
	if !ok || ads != oldADS || address != previous.AddressVersion {
		t.Fatal("test must exercise colliding ADS generations and Address versions")
	}
	if current.AcknowledgeAddress(oldRef, oldADS, previous.AddressVersion) {
		t.Fatal("prior execution Address ACK was accepted")
	}
	if !current.AcknowledgeAddress(ref, ads, address) {
		t.Fatal("fresh Address ACK was rejected")
	}
	policy, ok := current.PublishPolicy(ref, ads, validPolicyEvidence(ref, address))
	if !ok || policy != previous.PolicyVersion {
		t.Fatal("test must exercise colliding policy versions")
	}
	if current.AcknowledgePolicy(oldRef, oldADS, previous.PolicyVersion) {
		t.Fatal("prior execution policy ACK was accepted")
	}
	if !current.AcknowledgePolicy(ref, ads, policy) {
		t.Fatal("fresh policy ACK was rejected")
	}
	if _, ok := current.BeginDrain(oldRef); ok {
		t.Fatal("prior execution reference drained the current workload")
	}
	state, _ := current.Get(ref)
	if !state.Active() {
		t.Fatal("fresh evidence did not restore active membership")
	}
}

func TestPublicationRevisionFencesDelayedFailureAndNeverWraps(t *testing.T) {
	registry := NewRegistry(1)
	ref := requireMembership(t, registry, "ns", "pod", 7, "/netns/pod")
	first := establishCaptureAndZDS(t, registry, ref)
	captured, ok := registry.Publication(ref)
	if !ok || captured.Revision == 0 || captured.State != PublicationCaptured {
		t.Fatal("missing revisioned captured publication")
	}
	next, ok := registry.BeginZDS(ref)
	if !ok || next == first {
		t.Fatal("missing fresh generation")
	}
	if registry.InvalidateCaptureGeneration(ref, first) {
		t.Fatal("old attempt revoked a newer generation")
	}
	if !registry.MarkCaptured(ref, next) || !registry.AcknowledgeZDS(ref, next) {
		t.Fatal("new generation should recover")
	}
	recovered, _ := registry.Publication(ref)
	if recovered.Revision <= captured.Revision {
		t.Fatal("publication revision did not advance")
	}
	if !registry.InvalidateCaptureGeneration(ref, next) {
		t.Fatal("matching failed attempt must revoke")
	}
	revoked, _ := registry.Publication(ref)
	if revoked.Revision <= recovered.Revision || revoked.State != PublicationRequired {
		t.Fatal("revocation must advance source order")
	}
	registry.mu.Lock()
	registry.nextPublicationRevision = ^uint64(0) - 1
	registry.mu.Unlock()
	generation, _ := registry.BeginZDS(ref)
	if registry.MarkCaptured(ref, generation) {
		t.Fatal("exhausted publication counter must remain closed")
	}
	exhausted, _ := registry.Publication(ref)
	if exhausted.Revision != ^uint64(0) || exhausted.State == PublicationCaptured {
		t.Fatal("source order wrapped or permitted capture")
	}
}

func TestSourceSnapshotIsOneOrderedImmutableRegistryRevision(t *testing.T) {
	registry := NewRegistry(1)
	a := requireMembership(t, registry, "ns", "pod-a", 7, "/ns/a")
	b := requireMembership(t, registry, "ns", "pod-b", 8, "/ns/b")
	establishCaptureAndZDS(t, registry, a)
	before := registry.SourceSnapshot()
	if before.Epoch == "" || before.Revision == 0 || len(before.Entries) != 2 || before.Entries[0].Reference != a || before.Entries[1].Reference != b {
		t.Fatal("missing complete ordered source snapshot")
	}
	if !registry.InvalidateCapture(a) {
		t.Fatal("capture invalidation failed")
	}
	after := registry.SourceSnapshot()
	if after.Revision <= before.Revision || after.Entries[0].Publication.State != PublicationRequired {
		t.Fatal("new snapshot lost revocation/order")
	}
	if before.Entries[0].Publication.State != PublicationCaptured {
		t.Fatal("immutable snapshot was mutated by a later update")
	}
	for _, entry := range after.Entries {
		if entry.Publication.Revision > after.Revision || entry.Publication.Epoch != after.Epoch {
			t.Fatal("mixed registry snapshot order/epoch")
		}
	}
}

func TestPublishIfSourceSnapshotCurrentRejectsStaleWithoutBlockingMutation(t *testing.T) {
	registry := NewRegistry(1)
	ref := requireMembership(t, registry, "ns", "pod", 7, "/netns/pod")
	establishCaptureAndZDS(t, registry, ref)
	stale := registry.SourceSnapshot()
	if _, ok := registry.BeginDrain(ref); !ok {
		t.Fatal("BeginDrain failed")
	}

	called := false
	err := registry.PublishIfSourceSnapshotCurrent(stale, func() error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrSourcePublicationStale) || called {
		t.Fatalf("stale source snapshot callback called=%v, err=%v", called, err)
	}

	current := registry.SourceSnapshot()
	started := make(chan struct{})
	release := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- registry.PublishIfSourceSnapshotCurrent(current, func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	mutationDone := make(chan struct{})
	go func() {
		_, _ = registry.Require("ns", "pod-b", 8, "/netns/pod-b")
		close(mutationDone)
	}()
	select {
	case <-mutationDone:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("external source write blocked native registry mutation")
	}
	close(release)
	if err := <-writeDone; !errors.Is(err, ErrSourcePublicationStale) {
		t.Fatalf("concurrent source change was not detected after write: %v", err)
	}
}

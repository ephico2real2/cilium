// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package membership tracks the independent prerequisites for protecting a
// workload with ztunnel. State is process-local and must be rebuilt from live
// Kubernetes intent and restored Cilium endpoints after restart. ACK bits are
// never persisted or restored.
package membership

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/cilium/cilium/pkg/lock"
)

// Key identifies one Kubernetes Pod incarnation within a Cilium cluster.
// NamespaceUID prevents a deleted and recreated namespace from inheriting
// membership, while PodUID prevents name or address reuse from inheriting it.
type Key struct {
	ClusterID    uint32
	NamespaceUID string
	PodUID       string
}

// Reference fences asynchronous acknowledgments to one CNI endpoint
// incarnation. A late ACK for a retired endpoint cannot advance its successor.
type Reference struct {
	Key         Key
	Incarnation uint64
	// Epoch fences all acknowledgments to this registry execution. Counters
	// may restart at one; evidence from an earlier execution must not match.
	Epoch string
}

// State keeps intent and evidence separate. Active is derived only after every
// prerequisite is current and acknowledged.
type State struct {
	Key         Key
	Incarnation uint64
	EndpointID  uint16
	NetnsPath   string

	Required       bool
	Captured       bool
	Draining       bool
	DrainCompleted bool

	ZDSGeneration uint64
	ZDSAcked      bool

	ADSGeneration  uint64
	AddressVersion uint64
	AddressAcked   bool

	PolicyVersion                   uint64
	PolicyAddressVersion            uint64
	PolicyAcked                     bool
	PolicyRevision                  string
	PolicyBoundToWorkload           bool
	PolicyRequiresAuthenticatedPeer bool
	PolicyDenyByDefault             bool

	DrainGeneration uint64
}

// Active reports whether all independently delivered and acknowledged
// protection prerequisites are satisfied. An ACK for one protocol layer can
// never stand in for another.
func (s State) Active() bool {
	return s.Required && s.Captured && !s.Draining &&
		s.ZDSGeneration != 0 && s.ZDSAcked &&
		s.ADSGeneration != 0 && s.AddressVersion != 0 && s.AddressAcked &&
		s.PolicyVersion != 0 && s.PolicyAddressVersion == s.AddressVersion && s.PolicyAcked &&
		s.PolicyRevision != "" && s.PolicyBoundToWorkload &&
		s.PolicyRequiresAuthenticatedPeer && s.PolicyDenyByDefault
}

// ReadyForAddress reports whether capture and ZDS enrollment are established
// for this incarnation. It is intentionally weaker than Active.
func (s State) ReadyForAddress() bool {
	return s.Required && s.Captured && !s.Draining &&
		s.ZDSGeneration != 0 && s.ZDSAcked
}

// Registry is an in-process reconciled view. Its contents are intentionally
// ephemeral; callers must reconstruct them from live sources after restart.
type Registry struct {
	mu lock.RWMutex

	clusterID           uint32
	epoch               string
	nextIncarnation     uint64
	nextZDSGeneration   uint64
	nextADSGeneration   uint64
	nextDrainGeneration uint64
	nextVersion         uint64

	states   map[Reference]State
	byPodUID map[string]Reference
}

func NewRegistry(clusterID uint32) *Registry {
	return &Registry{
		clusterID: clusterID,
		epoch:     uuid.NewString(),
		states:    make(map[Reference]State),
		byPodUID:  make(map[string]Reference),
	}
}

// Require records current enforcement intent after the caller has validated
// the live Namespace, Pod, and current endpoint. Repeated calls for the same
// CNI endpoint are idempotent. A replacement is rejected until the old
// incarnation is drained and retired, preventing delayed add events from
// replacing a newer endpoint.
func (r *Registry) Require(namespaceUID, podUID string, endpointID uint16, netnsPath string) (Reference, error) {
	if strings.TrimSpace(namespaceUID) == "" || strings.TrimSpace(podUID) == "" || strings.TrimSpace(netnsPath) == "" {
		return Reference{}, fmt.Errorf("required membership needs namespace UID, Pod UID, and network namespace")
	}

	key := Key{ClusterID: r.clusterID, NamespaceUID: namespaceUID, PodUID: podUID}
	r.mu.Lock()
	defer r.mu.Unlock()
	if previousRef, ok := r.byPodUID[podUID]; ok {
		if existing, exists := r.states[previousRef]; exists {
			if previousRef.Key != key || existing.EndpointID != endpointID || existing.NetnsPath != netnsPath {
				return Reference{}, fmt.Errorf("Pod already has endpoint incarnation %d; drain and retire it before replacement", previousRef.Incarnation)
			}
			if existing.Draining {
				return Reference{}, fmt.Errorf("draining Pod membership cannot be reused")
			}
			existing.Required = true
			r.states[previousRef] = existing
			return previousRef, nil
		}
	}

	r.nextIncarnation++
	ref := Reference{Key: key, Incarnation: r.nextIncarnation, Epoch: r.epoch}
	state := State{
		Key: key, Incarnation: ref.Incarnation, EndpointID: endpointID,
		NetnsPath: netnsPath, Required: true,
	}
	r.states[ref] = state
	r.byPodUID[podUID] = ref
	return ref, nil
}

// BeginZDS starts a fresh ZDS enrollment generation and invalidates old capture
// and ZDS ACK evidence before the caller reasserts capture and sends ADD.
func (r *Registry) BeginZDS(ref Reference) (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.currentLocked(ref)
	if !ok || !state.Required || state.Draining {
		return 0, false
	}
	r.nextZDSGeneration++
	state.ZDSGeneration = r.nextZDSGeneration
	state.ZDSAcked = false
	state.Captured = false
	state.AddressVersion = 0
	state.AddressAcked = false
	state.PolicyVersion = 0
	state.PolicyAddressVersion = 0
	state.PolicyAcked = false
	state.PolicyRevision = ""
	state.PolicyBoundToWorkload = false
	state.PolicyRequiresAuthenticatedPeer = false
	state.PolicyDenyByDefault = false
	r.states[ref] = state
	return state.ZDSGeneration, true
}

// MarkCaptured records that the caller successfully reasserted the capture
// rules in this endpoint's network namespace.
func (r *Registry) MarkCaptured(ref Reference, generation uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.currentLocked(ref)
	if !ok || !state.Required || state.Draining || generation == 0 || state.ZDSGeneration != generation {
		return false
	}
	state.Captured = true
	r.states[ref] = state
	return true
}

// InvalidateCapture revokes all downstream evidence when the caller detects
// missing or drifted capture rules. A new ZDS generation and fresh capture
// confirmation are required before Address can be published again.
func (r *Registry) InvalidateCapture(ref Reference) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.currentLocked(ref)
	if !ok || state.Draining {
		return false
	}
	state.Captured = false
	state.ZDSGeneration = 0
	state.ZDSAcked = false
	state.AddressVersion = 0
	state.AddressAcked = false
	state.PolicyVersion = 0
	state.PolicyAddressVersion = 0
	state.PolicyAcked = false
	state.PolicyRevision = ""
	state.PolicyBoundToWorkload = false
	state.PolicyRequiresAuthenticatedPeer = false
	state.PolicyDenyByDefault = false
	r.states[ref] = state
	return true
}

func (r *Registry) AcknowledgeZDS(ref Reference, generation uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.currentLocked(ref)
	if !ok || !state.Required || !state.Captured || state.Draining || generation == 0 || state.ZDSGeneration != generation {
		return false
	}
	state.ZDSAcked = true
	r.states[ref] = state
	return true
}

// BeginADSGeneration invalidates Address and policy acknowledgments from any
// previous ztunnel stream. The returned generation identifies the new stream.
func (r *Registry) BeginADSGeneration() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextADSGeneration++
	for ref, state := range r.states {
		state.ADSGeneration = r.nextADSGeneration
		state.AddressVersion = 0
		state.AddressAcked = false
		state.PolicyVersion = 0
		state.PolicyAddressVersion = 0
		state.PolicyAcked = false
		state.PolicyRevision = ""
		state.PolicyBoundToWorkload = false
		state.PolicyRequiresAuthenticatedPeer = false
		state.PolicyDenyByDefault = false
		r.states[ref] = state
	}
	return r.nextADSGeneration
}

// PublishAddress records the exact workload resource version sent on the
// current ADS stream and returns an ACK token. It does not imply acceptance.
func (r *Registry) PublishAddress(ref Reference, generation uint64) (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.currentLocked(ref)
	if !ok || !state.ReadyForAddress() || generation == 0 || state.ADSGeneration != generation {
		return 0, false
	}
	r.nextVersion++
	state.AddressVersion = r.nextVersion
	state.AddressAcked = false
	state.PolicyVersion = 0
	state.PolicyAddressVersion = 0
	state.PolicyAcked = false
	state.PolicyRevision = ""
	state.PolicyBoundToWorkload = false
	state.PolicyRequiresAuthenticatedPeer = false
	state.PolicyDenyByDefault = false
	r.states[ref] = state
	return state.AddressVersion, true
}

func (r *Registry) AcknowledgeAddress(ref Reference, generation, version uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.currentLocked(ref)
	if !ok || !state.ReadyForAddress() || generation == 0 || version == 0 ||
		state.ADSGeneration != generation || state.AddressVersion != version {
		return false
	}
	state.AddressAcked = true
	r.states[ref] = state
	return true
}

// PolicyEvidence binds effective policy provenance to the exact workload
// Address version. Only a real policy compiler/ACK adapter may construct this
// from validated fail-closed policy output; the state model cannot verify that
// provenance by itself.
type PolicyEvidence struct {
	WorkloadUID               string
	AddressVersion            uint64
	Revision                  string
	BoundToWorkload           bool
	RequiresAuthenticatedPeer bool
	DenyByDefault             bool
}

// PublishPolicy records an effective policy resource version. The caller must
// invoke it only for a policy compiled and bound to this workload, not for a
// global authentication-only rule or a transport-level ACK.
func (r *Registry) PublishPolicy(ref Reference, generation uint64, evidence PolicyEvidence) (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.currentLocked(ref)
	if !ok || !state.ReadyForAddress() || !state.AddressAcked || generation == 0 || state.ADSGeneration != generation ||
		evidence.WorkloadUID == "" || evidence.WorkloadUID != ref.Key.PodUID || evidence.AddressVersion == 0 ||
		evidence.AddressVersion != state.AddressVersion || evidence.Revision == "" || !evidence.BoundToWorkload ||
		!evidence.RequiresAuthenticatedPeer || !evidence.DenyByDefault {
		return 0, false
	}
	r.nextVersion++
	state.PolicyVersion = r.nextVersion
	state.PolicyAddressVersion = evidence.AddressVersion
	state.PolicyAcked = false
	state.PolicyRevision = evidence.Revision
	state.PolicyBoundToWorkload = evidence.BoundToWorkload
	state.PolicyRequiresAuthenticatedPeer = evidence.RequiresAuthenticatedPeer
	state.PolicyDenyByDefault = evidence.DenyByDefault
	r.states[ref] = state
	return state.PolicyVersion, true
}

func (r *Registry) AcknowledgePolicy(ref Reference, generation, version uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.currentLocked(ref)
	if !ok || !state.ReadyForAddress() || !state.AddressAcked || generation == 0 || version == 0 ||
		state.ADSGeneration != generation || state.PolicyVersion != version ||
		state.PolicyAddressVersion != state.AddressVersion || state.PolicyRevision == "" ||
		!state.PolicyBoundToWorkload || !state.PolicyRequiresAuthenticatedPeer || !state.PolicyDenyByDefault {
		return false
	}
	state.PolicyAcked = true
	r.states[ref] = state
	return true
}

func (r *Registry) BeginDrain(ref Reference) (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.currentLocked(ref)
	if !ok {
		return 0, false
	}
	if state.Draining {
		return state.DrainGeneration, state.DrainGeneration != 0
	}
	r.nextDrainGeneration++
	state.Draining = true
	state.DrainCompleted = false
	state.DrainGeneration = r.nextDrainGeneration
	state.AddressAcked = false
	state.PolicyAcked = false
	r.states[ref] = state
	return state.DrainGeneration, true
}

// CompleteDrain records the positive result of the caller's endpoint-scoped
// proxy-flow drain. It must only be called after the active-connection tracker
// confirms no connection remains for this exact incarnation.
func (r *Registry) CompleteDrain(ref Reference, generation uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.currentLocked(ref)
	if !ok || !state.Draining || generation == 0 || generation != state.DrainGeneration {
		return false
	}
	state.DrainCompleted = true
	r.states[ref] = state
	return true
}

// PendingDrain returns a snapshot of endpoint incarnations that have been
// fenced from new connections and still need the caller's flow drain to finish.
func (r *Registry) PendingDrain() []State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	states := make([]State, 0)
	for _, state := range r.states {
		if state.Draining {
			states = append(states, state)
		}
	}
	sort.Slice(states, func(i, j int) bool {
		return states[i].Incarnation < states[j].Incarnation
	})
	return states
}

// Retire deletes only the exact draining incarnation named by ref. The caller
// may retire it only after the proxy confirms that its tracked connections are
// closed; this registry does not infer or perform flow draining itself.
func (r *Registry) Retire(ref Reference) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.currentLocked(ref)
	if !ok || !state.Draining || !state.DrainCompleted {
		return false
	}
	delete(r.states, ref)
	if r.byPodUID[ref.Key.PodUID] == ref {
		delete(r.byPodUID, ref.Key.PodUID)
	}
	return true
}

func (r *Registry) Get(ref Reference) (State, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	state, ok := r.currentLocked(ref)
	return state, ok
}

func (r *Registry) CurrentForPodUID(podUID string) (Reference, State, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ref, ok := r.byPodUID[podUID]
	if !ok {
		return Reference{}, State{}, false
	}
	state, ok := r.states[ref]
	if !ok {
		return Reference{}, State{}, false
	}
	return ref, state, true
}

func (r *Registry) currentLocked(ref Reference) (State, bool) {
	state, ok := r.states[ref]
	return state, ok && ref.Epoch != "" && ref.Epoch == r.epoch &&
		ref.Incarnation != 0 && state.Incarnation == ref.Incarnation
}

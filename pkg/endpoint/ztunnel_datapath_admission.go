// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
)

// Datapath admission for a Required endpoint has exactly two modes:
//
//   - quarantined: every packet is dropped in both directions;
//   - mesh-only: new flows to and from workload identities must use
//     authenticated HBONE (TCP/15008). Native policy still applies.
//
// A Required endpoint is never in ordinary forwarding. Required remains sticky;
// only quarantine changes. Release requires a receipt that the endpoint itself
// verifies against its current incarnation, captured membership, realized
// native policy and a datapath program installed by this agent process. Any
// membership or incarnation change re-quarantines at once with a direct
// cilium_lxc write. Admission state is process-local and never restored.

// logZtunnelStage names the admission stage in structured logs.
const logZtunnelStage = "stage"

var (
	ErrZtunnelNotRequired       = errors.New("endpoint has no Required ztunnel obligation")
	ErrZtunnelAdmissionMismatch = errors.New("ztunnel admission receipt does not match the current endpoint")
)

// ZtunnelAdmissionReceipt is the native evidence that releases a Required
// endpoint from quarantine into mesh-only forwarding. An ACK, label or TLS
// handshake alone is not a receipt.
type ZtunnelAdmissionReceipt struct {
	// Exact endpoint and sandbox incarnation.
	Binding ZtunnelPolicyBinding
	// Captured membership for that incarnation (ZDS ACK of this generation).
	Membership ZtunnelMembership
	// Realized native policy that the published authorization was compiled from.
	PolicyRevision uint64
	PolicyDigest   string
	// Native authorization resource version delivered to the local ztunnel.
	// Recorded for correlation; it is not an ACK-derived protection claim.
	AuthorizationVersion uint64
}

func validCapturedMembership(m ZtunnelMembership, namespaceUID string) bool {
	return m.Version == 1 && m.State == ZtunnelMembershipCaptured && m.Revision != 0 &&
		m.Epoch != "" && m.Generation != 0 && m.NamespaceUID != "" && m.NamespaceUID == namespaceUID
}

// ztunnelQuarantinedAtomic is the lock-free part of the fail-closed datapath
// predicate. It reads atomics only, so endpoint-map writers can call it after
// the endpoint lock is released. A released endpoint whose captured membership
// changed is quarantined again.
func (e *Endpoint) ztunnelQuarantinedAtomic() bool {
	if e.ztunnelDatapathQuarantined.Load() {
		return true
	}
	if !e.ztunnelRequiresSourceIPLocked() { // atomics only
		return false
	}
	r := e.ztunnelAdmission.Load()
	if r == nil {
		return true
	}
	m, ok := e.GetZtunnelMembership()
	return !ok || m != r.Membership || !validCapturedMembership(m, r.Binding.NamespaceUID)
}

// ztunnelQuarantinedLocked adds the exact incarnation check. Endpoint mutex
// must be held. Incarnation changes also arrive with a new membership
// generation, which withdraws admission through the atomic path.
func (e *Endpoint) ztunnelQuarantinedLocked() bool {
	if e.ztunnelQuarantinedAtomic() {
		return true
	}
	r := e.ztunnelAdmission.Load()
	return r != nil && r.Binding != e.ztunnelPolicyBindingLocked()
}

// IsZtunnelQuarantined reports the separate datapath hold state. Required
// SourceIPVerification intent is exposed by SourceIPDatapathIdentity and is
// deliberately not used as the packet-drop predicate.
func (e *Endpoint) IsZtunnelQuarantined() bool {
	return e.ztunnelQuarantinedAtomic()
}

// IsZtunnelMeshOnly reports the sticky Required obligation as the datapath
// mesh-only bit. It applies whenever quarantine is released.
func (e *Endpoint) IsZtunnelMeshOnly() bool {
	return e.ztunnelRequiresSourceIPLocked()
}

// ReleaseZtunnelQuarantine moves a Required endpoint from quarantine into
// mesh-only forwarding after verifying the receipt. Every mismatch returns an
// error and leaves the endpoint quarantined. The caller owns the endpoint
// lifecycle and must then regenerate its datapath (RegenerateWithDatapath);
// until that regeneration the load-time quarantine default keeps every packet
// dropped, so a missing regeneration can only fail closed.
func (e *Endpoint) ReleaseZtunnelQuarantine(receipt ZtunnelAdmissionReceipt) error {
	if err := e.lockAlive(); err != nil {
		return err
	}
	err := e.verifyZtunnelReceiptLocked(receipt)
	if err == nil {
		copy := receipt
		e.ztunnelAdmission.Store(&copy)
		e.ztunnelDatapathQuarantined.Store(false)
	}
	e.unlock()
	if err != nil {
		e.getLogger().Warn("Refusing ztunnel quarantine release",
			logfields.Event, "ztunnel-datapath-admission",
			logZtunnelStage, "quarantine-release",
			logfields.PodUID, receipt.Binding.PodUID,
			logfields.Error, err)
		return err
	}
	e.getLogger().Info("Released ztunnel quarantine into mesh-only forwarding",
		logfields.Event, "ztunnel-datapath-admission",
		logZtunnelStage, "quarantine-release",
		logfields.PodUID, receipt.Binding.PodUID,
		logfields.PolicyRevision, receipt.PolicyRevision,
		"membershipGeneration", receipt.Membership.Generation,
		"authorizationVersion", receipt.AuthorizationVersion)
	return nil
}

// ZtunnelReleaseRegeneration is the regeneration a caller must request after
// a successful ReleaseZtunnelQuarantine.
func ZtunnelReleaseRegeneration() *regeneration.ExternalRegenerationMetadata {
	return &regeneration.ExternalRegenerationMetadata{
		Reason:            regeneration.ReasonEndpointUpdate,
		Message:           "ztunnel quarantine released into mesh-only forwarding",
		RegenerationLevel: regeneration.RegenerateWithDatapath,
	}
}

func (e *Endpoint) verifyZtunnelReceiptLocked(r ZtunnelAdmissionReceipt) error {
	if !e.ztunnelRequiresSourceIPLocked() {
		return ErrZtunnelNotRequired
	}
	if e.Options == nil || !e.Options.IsEnabled(option.SourceIPVerification) {
		return fmt.Errorf("%w: source IP verification is disabled", ErrZtunnelAdmissionMismatch)
	}
	// Old bytecode ignores the admission bits. Only a program installed by
	// this agent process can enforce mesh-only forwarding.
	select {
	case <-e.hasBPFProgram:
	default:
		return fmt.Errorf("%w: no datapath program installed by this agent process", ErrZtunnelAdmissionMismatch)
	}
	current := e.ztunnelPolicyBindingLocked()
	if !current.RequiredObserved || r.Binding != current || current.PodUID == "" ||
		current.NamespaceUID == "" || current.NetNSCookie == 0 || current.EndpointID == 0 {
		return fmt.Errorf("%w: endpoint incarnation differs", ErrZtunnelAdmissionMismatch)
	}
	m, ok := e.GetZtunnelMembership()
	if !ok || m != r.Membership || !validCapturedMembership(m, current.NamespaceUID) {
		return fmt.Errorf("%w: membership is not the exact captured generation", ErrZtunnelAdmissionMismatch)
	}
	if e.ztunnelPolicyDrain != nil {
		select {
		case <-e.ztunnelPolicyDrain.drain.Done():
			if e.ztunnelPolicyDrain.drain.Err() != nil {
				return fmt.Errorf("%w: native policy drain failed", ErrZtunnelAdmissionMismatch)
			}
		default:
			return fmt.Errorf("%w: native policy drain is pending", ErrZtunnelAdmissionMismatch)
		}
	}
	if e.realizedPolicy == nil || e.realizedPolicy != e.desiredPolicy || e.policyRevision == 0 ||
		e.policyRevision != e.desiredPolicyRevision || e.policyRevision != r.PolicyRevision {
		return fmt.Errorf("%w: native policy is not realized at the receipt revision", ErrZtunnelAdmissionMismatch)
	}
	snapshot, err := e.realizedPolicy.SnapshotZtunnelL4(e.policyRevision)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrZtunnelAdmissionMismatch, err)
	}
	if r.PolicyDigest == "" || snapshot.Digest() != r.PolicyDigest {
		return fmt.Errorf("%w: native policy digest differs", ErrZtunnelAdmissionMismatch)
	}
	if r.AuthorizationVersion == 0 {
		return fmt.Errorf("%w: no native authorization version was delivered", ErrZtunnelAdmissionMismatch)
	}
	return nil
}

// WithdrawZtunnelAdmission quarantines the endpoint immediately. It is safe to
// call while holding another subsystem's mutex: it uses atomics and one
// cilium_lxc write of the last realized frontend.
func (e *Endpoint) WithdrawZtunnelAdmission(reason string) {
	e.ztunnelAdmission.Store(nil)
	if e.ztunnelDatapathQuarantined.Swap(true) {
		return
	}
	e.rewriteZtunnelDatapathFlags(reason)
}

// rewriteZtunnelDatapathFlags writes the last realized endpoint entry again.
// Its quarantine predicate reads the live state, so it can only become stricter
// than the cached value.
func (e *Endpoint) rewriteZtunnelDatapathFlags(reason string) {
	frontend := e.ztunnelLxcFrontend.Load()
	if frontend == nil || e.lxcMap == nil {
		return
	}
	if err := e.lxcMap.WriteEndpoint(*frontend); err != nil {
		// The load-time default and next regeneration remain quarantined; this
		// failure must not be read as a release.
		e.getLogger().Error("Failed to write ztunnel quarantine to endpoint map",
			logfields.Event, "ztunnel-datapath-admission",
			logZtunnelStage, "quarantine-withdraw",
			logfields.Reason, reason,
			logfields.Error, err)
		return
	}
	e.getLogger().Info("Quarantined ztunnel endpoint",
		logfields.Event, "ztunnel-datapath-admission",
		logZtunnelStage, "quarantine-withdraw",
		logfields.Reason, reason)
}

// recordZtunnelLxcFrontend retains the frontend last written to cilium_lxc so a
// withdrawal can rewrite it without the endpoint lock.
func (e *Endpoint) recordZtunnelLxcFrontend(f lxcmap.EndpointFrontend) {
	e.ztunnelLxcFrontend.Store(&f)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
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
	// A release never interleaves with a withdrawal's flag sampling, kernel
	// update and acknowledgement.
	e.ztunnelDatapathWriteMu.Lock()
	err := e.verifyZtunnelReceiptLocked(receipt)
	if err == nil {
		copy := receipt
		e.ztunnelAdmission.Store(&copy)
		// A new release interval: its withdrawal needs its own map write.
		e.ztunnelReleaseSeq.Add(1)
		e.ztunnelDatapathQuarantined.Store(false)
	}
	e.ztunnelDatapathWriteMu.Unlock()
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
	// The datapath admits a Required program only through its own
	// endpoint-map entry, which needs a configured endpoint address.
	if !ztunnelAddressConfigured(e.IPv4) && !ztunnelAddressConfigured(e.IPv6) {
		return fmt.Errorf("%w: endpoint has no configured address", ErrZtunnelAdmissionMismatch)
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

// ztunnelAddressConfigured reports a usable endpoint address: an unspecified
// address compiles to the same bits as no address.
func ztunnelAddressConfigured(addr netip.Addr) bool {
	return addr.IsValid() && !addr.IsUnspecified()
}

var ztunnelQuarantineRecoveryControllerGroup = controller.NewGroup("ztunnel-quarantine-recovery")

func ztunnelQuarantineRecoveryControllerName(id uint16) string {
	return fmt.Sprintf("ztunnel-quarantine-recovery (%d)", id)
}

// ztunnelQuarantineAcked reports that no entry released by this agent process
// is outstanding: cilium_lxc accepted the withdrawal of the current release
// interval (or nothing was ever released).
func (e *Endpoint) ztunnelQuarantineAcked() bool {
	return e.ztunnelQuarantineAckedSeq.Load() == e.ztunnelReleaseSeq.Load()
}

// WithdrawZtunnelAdmission quarantines the endpoint. It is safe to call while
// holding the endpoint mutex or another subsystem's mutex: it uses atomics and
// one cilium_lxc write of the last realized frontend, which carries the
// quarantine bit because its flags read the live state.
//
// Protection boundary: a program released earlier keeps forwarding TCP/15008
// until cilium_lxc accepts this write or a regeneration loads a program
// compiled with ztunnel_quarantined=true. If the write fails, a recovery
// controller (no caller locks) queues that regeneration once and retries the
// write with bounded backoff, and every repeated withdrawal retries it too. If
// every kernel write keeps failing, the released program keeps forwarding:
// that failure mode is not fail-closed.
func (e *Endpoint) WithdrawZtunnelAdmission(reason string) {
	e.ztunnelDatapathWriteMu.Lock()
	e.ztunnelAdmission.Store(nil)
	if e.ztunnelDatapathQuarantined.Swap(true) && e.ztunnelQuarantineAcked() {
		e.ztunnelDatapathWriteMu.Unlock()
		return
	}
	written := e.writeZtunnelQuarantine(reason)
	e.ztunnelDatapathWriteMu.Unlock()
	if !written {
		// After unlocking: the controller manager is never entered with the
		// publication mutex held.
		e.startZtunnelQuarantineRecovery(reason)
	}
}

// writeZtunnelQuarantine writes the last realized endpoint entry again and
// reports whether no released entry of the current interval remains.
// ztunnelDatapathWriteMu must be held through the write and acknowledgement.
func (e *Endpoint) writeZtunnelQuarantine(reason string) bool {
	seq := e.ztunnelReleaseSeq.Load()
	if e.ztunnelLxcRetired {
		// The entries were deleted; a Required program without its own
		// entry is quarantined, and the deleted entry is never rewritten.
		e.ztunnelQuarantineAckedSeq.Store(seq)
		return true
	}
	frontend := e.ztunnelLxcFrontend.Load()
	if frontend == nil || e.lxcMap == nil {
		// This agent process realized no entry; the next regeneration writes
		// a quarantined entry and compiles the quarantine default.
		e.ztunnelQuarantineAckedSeq.Store(seq)
		return true
	}
	if err := e.lxcMap.WriteEndpoint(*frontend); err != nil {
		e.getLogger().Error("Failed to write ztunnel quarantine to endpoint map",
			logfields.Event, "ztunnel-datapath-admission",
			logZtunnelStage, "quarantine-withdraw",
			logfields.Reason, reason,
			logfields.Error, err)
		return false
	}
	// Releases are excluded while the publication mutex is held, so the
	// state and sequence sampled above are still current.
	e.ztunnelQuarantineAckedSeq.Store(seq)
	e.getLogger().Info("Quarantined ztunnel endpoint",
		logfields.Event, "ztunnel-datapath-admission",
		logZtunnelStage, "quarantine-withdraw",
		logfields.Reason, reason)
	return true
}

// ztunnelQuarantineRegeneration recompiles the datapath with the quarantine
// default, independently of the failed endpoint-map write.
func ztunnelQuarantineRegeneration(reason string) *regeneration.ExternalRegenerationMetadata {
	return &regeneration.ExternalRegenerationMetadata{
		Reason:            regeneration.ReasonEndpointUpdate,
		Message:           "ztunnel quarantine endpoint-map write failed: " + reason,
		RegenerationLevel: regeneration.RegenerateWithDatapath,
	}
}

// startZtunnelQuarantineRecovery starts (or restarts) the endpoint's recovery
// controller. Only the controller manager mutex is taken here; the controller
// runs on its own goroutine, is bound to the endpoint's alive context and is
// removed with the endpoint's other controllers.
func (e *Endpoint) startZtunnelQuarantineRecovery(reason string) {
	if e.controllers == nil {
		e.getLogger().Error("Cannot start ztunnel quarantine recovery without an endpoint controller manager",
			logfields.Event, "ztunnel-datapath-admission",
			logZtunnelStage, "quarantine-recovery",
			logfields.Reason, reason)
		return
	}
	regenerationQueued := false
	e.UpdateController(ztunnelQuarantineRecoveryControllerName(e.GetID16()), controller.ControllerParams{
		Group:                  ztunnelQuarantineRecoveryControllerGroup,
		ErrorRetryBaseDuration: 200 * time.Millisecond,
		MaxRetryInterval:       5 * time.Second,
		DoFunc: func(ctx context.Context) error {
			return e.recoverZtunnelQuarantine(ctx, reason, &regenerationQueued)
		},
	})
}

// recoverZtunnelQuarantine is one recovery attempt. It queues one datapath
// regeneration, then retries the endpoint-map write under the endpoint lock,
// so a deleted endpoint's entry is never rewritten and an entry recorded for
// another incarnation is never written. An error makes the controller retry.
func (e *Endpoint) recoverZtunnelQuarantine(ctx context.Context, reason string, regenerationQueued *bool) error {
	if !e.ztunnelDatapathQuarantined.Load() || e.ztunnelQuarantineAcked() {
		return nil
	}
	if !*regenerationQueued {
		e.getLogger().Warn("Queueing ztunnel quarantine datapath regeneration",
			logfields.Event, "ztunnel-datapath-admission",
			logZtunnelStage, "quarantine-recovery",
			logfields.Reason, reason)
		e.RegenerateIfAlive(ztunnelQuarantineRegeneration(reason))
		*regenerationQueued = true
	}
	if err := e.lockAlive(); err != nil {
		return controller.NewExitReason("endpoint is being deleted")
	}
	defer e.unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	e.ztunnelDatapathWriteMu.Lock()
	defer e.ztunnelDatapathWriteMu.Unlock()
	// Release, withdrawal and every map publication are excluded here.
	if !e.ztunnelDatapathQuarantined.Load() || e.ztunnelQuarantineAcked() {
		return nil
	}
	frontend := e.ztunnelLxcFrontend.Load()
	if frontend != nil {
		if cache, ok := (*frontend).(*epInfoCache); ok &&
			(cache.id != uint64(e.ID) || cache.netNsCookie != e.NetNsCookie || cache.k8sPodUID != e.GetK8sPodUID()) {
			return fmt.Errorf("realized endpoint entry belongs to another incarnation; waiting for regeneration")
		}
	}
	if !e.writeZtunnelQuarantine(reason) {
		return fmt.Errorf("ztunnel quarantine endpoint-map write failed")
	}
	if e.ztunnelDatapathQuarantined.Load() {
		e.getLogger().Info("Recovered ztunnel quarantine in endpoint map",
			logfields.Event, "ztunnel-datapath-admission",
			logZtunnelStage, "quarantine-recovery",
			logfields.Reason, reason)
	}
	return nil
}

// recordZtunnelLxcFrontend retains the frontend last written to cilium_lxc so a
// withdrawal can rewrite it without the endpoint lock. Production callers hold
// ztunnelDatapathWriteMu (writeZtunnelLxcFrontend).
func (e *Endpoint) recordZtunnelLxcFrontend(f lxcmap.EndpointFrontend) {
	e.ztunnelLxcFrontend.Store(&f)
}

// writeZtunnelLxcFrontend is the regeneration publication of the endpoint's
// cilium_lxc entries. The flag sampling inside WriteEndpoint, the kernel
// update and recording the frontend share the withdrawal critical section:
// either the withdrawal follows this write, or this write samples the
// withdrawal's quarantine. After deletion it writes nothing.
func (e *Endpoint) writeZtunnelLxcFrontend(f lxcmap.EndpointFrontend) error {
	e.ztunnelDatapathWriteMu.Lock()
	defer e.ztunnelDatapathWriteMu.Unlock()
	if e.ztunnelLxcRetired {
		return ErrNotAlive
	}
	if err := e.lxcMap.WriteEndpoint(f); err != nil {
		return err
	}
	e.recordZtunnelLxcFrontend(f)
	if e.ztunnelDatapathQuarantined.Load() {
		// Sampled under this mutex: the written entry carries the quarantine.
		e.ztunnelQuarantineAckedSeq.Store(e.ztunnelReleaseSeq.Load())
	}
	return nil
}

// deleteZtunnelLxcEntries deletes the endpoint's cilium_lxc entries and
// retires its publications, so no delayed withdrawal or regeneration of this
// endpoint object writes them again. Called with the endpoint mutex held.
func (e *Endpoint) deleteZtunnelLxcEntries() []error {
	e.ztunnelDatapathWriteMu.Lock()
	defer e.ztunnelDatapathWriteMu.Unlock()
	e.ztunnelLxcRetired = true
	return e.lxcMap.DeleteElement(e.getLogger(), e)
}

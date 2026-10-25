// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"fmt"

	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/option"
)

func (e *Endpoint) sourceIPDatapathIdentityLocked() endpointtypes.SourceIPDatapathIdentity {
	return endpointtypes.SourceIPDatapathIdentity{
		EndpointID:      e.ID,
		NamespaceUID:    e.GetK8sNamespaceUID(),
		PodUID:          e.GetK8sPodUID(),
		NetNSPath:       e.GetContainerNetnsPath(),
		NetNSCookie:     e.GetEndpointNetNsCookie(),
		Interface:       e.ifName,
		IfIndex:         e.ifIndex,
		ConfigHash:      e.bpfHeaderfileHash,
		IPv4:            e.IPv4,
		IPv6:            e.IPv6,
		SourceIPEnabled: e.Options != nil && e.Options.IsEnabled(option.SourceIPVerification),
		ZtunnelRequired: e.ztunnelRequiresSourceIPLocked(),
	}
}

// SourceIPDatapathObservation takes a non-blocking, coherent endpoint snapshot
// and asks the Linux loader to verify the retained receipt against the live TCX
// attachment. Call this after SnapshotZtunnelPolicy has released its locks; the
// caller must join both observations by exact endpoint UID/netns/config fields
// and must not turn this guard receipt into capture or Protected proof.
func (e *Endpoint) SourceIPDatapathObservation(ctx context.Context) (endpointtypes.SourceIPDatapathObservation, error) {
	if err := ctx.Err(); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if !e.buildMutex.TryLock() {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("endpoint datapath build is in progress")
	}
	if !e.mutex.TryRLock() {
		e.buildMutex.UnlockIgnoreTime()
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("endpoint update is in progress")
	}
	if e.state != StateReady {
		e.mutex.RUnlock()
		e.buildMutex.UnlockIgnoreTime()
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("endpoint is not ready")
	}
	identity := e.sourceIPDatapathIdentityLocked()
	if !identity.SourceIPEnabled {
		e.mutex.RUnlock()
		e.buildMutex.UnlockIgnoreTime()
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("source IP verification is not enabled")
	}
	verifier, ok := e.loader.(endpointtypes.SourceIPDatapathVerifier)
	e.mutex.RUnlock()
	// TryLock does not initialize lockdebug's duration tracker. Release it with
	// UnlockIgnoreTime, and before any kernel query so a slow syscall cannot
	// stall endpoint regeneration. The immutable identity is rechecked below.
	e.buildMutex.UnlockIgnoreTime()
	if !ok {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("datapath loader cannot verify source IP attachment")
	}
	observation, err := verifier.VerifySourceIPDatapath(ctx, identity)
	if err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if err := ctx.Err(); err != nil {
		return endpointtypes.SourceIPDatapathObservation{}, err
	}
	if !e.mutex.TryRLock() {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("endpoint changed during source IP attachment verification")
	}
	defer e.mutex.RUnlock()
	if e.state != StateReady || e.sourceIPDatapathIdentityLocked() != identity || observation.Identity != identity {
		return endpointtypes.SourceIPDatapathObservation{}, fmt.Errorf("endpoint incarnation changed during source IP attachment verification")
	}
	return observation, nil
}

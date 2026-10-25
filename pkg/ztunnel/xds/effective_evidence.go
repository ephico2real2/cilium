// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"slices"
	"strconv"

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/google/uuid"
)

// recordAddressEvidence binds a fresh Address version of every captured local
// workload in a successfully sent response to that response's nonce. The
// version is acknowledged only by ztunnel's ACK of exactly that nonce.
func (sp *StreamProcessor) recordAddressEvidence(response *v3.DeltaDiscoveryResponse) {
	if sp.policyOwner == nil || sp.adsGeneration == 0 || response == nil {
		return
	}
	if sp.localResources == nil {
		sp.localResources = make(map[string]*v3.Resource)
	}
	if sp.addressEvidence == nil {
		sp.addressEvidence = make(map[string][]addressEvidence)
	}
	for _, name := range response.RemovedResources {
		delete(sp.localResources, name)
	}
	for _, resource := range response.Resources {
		if resource == nil || isRemoteResource(resource.Name) {
			continue
		}
		sp.localResources[resource.Name] = resource
		ref, state, ok := sp.policyOwner.registry.CurrentForPodUID(resource.Name)
		if !ok || !state.ReadyForAddress() {
			continue
		}
		if version, ok := sp.policyOwner.registry.PublishAddress(ref, sp.adsGeneration); ok {
			sp.addressEvidence[response.Nonce] = append(sp.addressEvidence[response.Nonce], addressEvidence{ref: ref, version: version})
		}
	}
}

// acknowledgeAddressEvidence records ztunnel's ACK of one Address response.
func (sp *StreamProcessor) acknowledgeAddressEvidence(nonce string) {
	if sp.policyOwner == nil {
		return
	}
	evidence, ok := sp.addressEvidence[nonce]
	if !ok {
		return
	}
	delete(sp.addressEvidence, nonce)
	for _, e := range evidence {
		sp.policyOwner.registry.AcknowledgeAddress(e.ref, sp.adsGeneration, e.version)
	}
	sp.policyOwner.kick()
}

// refreshAddressEvidence re-sends, unchanged, every local workload whose
// capture generation was renewed after its Address was acknowledged on this
// stream, so the new generation is bound to an acknowledged Address too.
func (sp *StreamProcessor) refreshAddressEvidence() error {
	if sp.policyOwner == nil || sp.adsGeneration == 0 {
		return nil
	}
	var names []string
	for name := range sp.localResources {
		_, state, ok := sp.policyOwner.registry.CurrentForPodUID(name)
		if ok && state.ReadyForAddress() && state.ADSGeneration == sp.adsGeneration && state.AddressVersion == 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	response := &v3.DeltaDiscoveryResponse{TypeUrl: xdsTypeURLAddress, Nonce: uuid.New().String()}
	for _, name := range names {
		response.Resources = append(response.Resources, sp.localResources[name])
	}
	if err := sp.sendAddressMessage(response, "xds-address-evidence"); err != nil {
		return err
	}
	sp.recordAddressEvidence(response)
	return nil
}

// recordAuthorizationSend notes the cache version of an Authorization
// response before it is sent, so its ACK can be attributed to this stream.
func (sp *StreamProcessor) recordAuthorizationSend(response *v3.DeltaDiscoveryResponse) {
	if sp.policyOwner == nil || response == nil {
		return
	}
	version, err := strconv.ParseUint(response.SystemVersionInfo, 10, 64)
	if err != nil || version == 0 || response.Nonce == "" {
		return
	}
	sp.authMu.Lock()
	defer sp.authMu.Unlock()
	if sp.authSent == nil {
		sp.authSent = make(map[string]uint64)
	}
	sp.authSent[response.Nonce] = version
}

// observeAuthorizationRequest records an ACK (not a NACK) of an Authorization
// response sent on this stream.
func (sp *StreamProcessor) observeAuthorizationRequest(request *v3.DeltaDiscoveryRequest) {
	if sp.policyOwner == nil || request == nil || request.ResponseNonce == "" {
		return
	}
	sp.authMu.Lock()
	version, ok := sp.authSent[request.ResponseNonce]
	delete(sp.authSent, request.ResponseNonce)
	if ok && request.ErrorDetail == nil && version > sp.authAcked {
		sp.authAcked = version
	}
	sp.authMu.Unlock()
	sp.reportAuthorizationAck()
}

func (sp *StreamProcessor) reportAuthorizationAck() {
	sp.authMu.Lock()
	acked := sp.authAcked
	sp.authMu.Unlock()
	if sp.adsGeneration != 0 && acked != 0 {
		sp.policyOwner.observeAuthorizationAck(sp.adsGeneration, acked)
	}
}

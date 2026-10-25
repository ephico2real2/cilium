// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"fmt"

	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
)

// ZtunnelPolicyMapReachabilityObservation joins a coherent native policy-map
// snapshot with a fresh kernel read of the current Cilium ProgramArray/TCX
// path, then verifies the endpoint incarnation did not change during that
// read. It proves map reachability only; it does not prove packet capture,
// complete policy enforcement, workload TLS, or authorization freshness.
func (e *Endpoint) ZtunnelPolicyMapReachabilityObservation(ctx context.Context) (endpointtypes.ZtunnelPolicyMapReachabilityObservation, error) {
	first, err := e.SnapshotZtunnelPolicyMap(ctx)
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}
	identity, err := first.ReachabilityIdentity()
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}
	verifier, ok := e.loader.(endpointtypes.ZtunnelPolicyMapReachabilityVerifier)
	if !ok {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("datapath loader cannot inspect native policy-map reachability")
	}
	receipt, err := verifier.VerifyZtunnelPolicyMapReachability(ctx, identity)
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}
	if err := ctx.Err(); err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}
	second, err := e.SnapshotZtunnelPolicyMap(ctx)
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}
	current, err := second.ReachabilityIdentity()
	if err != nil {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, err
	}
	if current != identity || first.Digest() != second.Digest() || receipt.Identity != identity {
		return endpointtypes.ZtunnelPolicyMapReachabilityObservation{}, fmt.Errorf("endpoint or native policy changed during kernel policy-map reachability inspection")
	}
	return receipt, nil
}

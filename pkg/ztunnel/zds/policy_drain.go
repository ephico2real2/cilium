// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package zds

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
)

type LivePolicyDrainCleaner interface {
	DrainLiveEndpointForPolicyContext(context.Context, *endpoint.Endpoint, membership.Reference, uint64) (*DrainReceipt, error)
}

// ConfirmPolicyQuarantine consumes a real typed drain receipt without retiring
// Required intent, forgetting ADD ownership, removing capture, or reopening the
// live incarnation. The deletion path can later retire this same exact owner.
func (r *DrainReceipt) ConfirmPolicyQuarantine(registry *membership.Registry, expected membership.Reference, generation uint64) error {
	if r == nil || registry == nil || r.ref != expected || r.generation != generation {
		return fmt.Errorf("policy quarantine requires exact original-ADD drain receipt")
	}
	state, ok := registry.Get(expected)
	if !ok || !state.Draining || state.DrainGeneration != generation {
		return fmt.Errorf("policy quarantine membership changed before receipt commit")
	}
	if !registry.CompleteDrain(expected, generation) {
		return fmt.Errorf("policy quarantine receipt was superseded")
	}
	return nil
}

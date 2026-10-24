// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"fmt"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/ztunnel/pb/security"
)

// The empty namespace indexes a GLOBAL policy in the pinned proxy. The reserved
// name cannot collide with a Kubernetes policy name because it contains '_'.
const requireMTLSPolicyName = "cilium_require_mtls"

// authenticatedOnlyPolicy denies connections without an authenticated peer.
// The plaintext listener supplies no identity; HBONE supplies the TLS peer's
// verified identity. The rule intentionally has no application-port predicate.
// Authentication does not grant permission to bypass other authorization rules.
func authenticatedOnlyPolicy() *security.Authorization {
	return &security.Authorization{
		Name:   requireMTLSPolicyName,
		Scope:  security.Scope_GLOBAL,
		Action: security.Action_DENY,
		Rules: []*security.Rule{{Clauses: []*security.Clause{{Matches: []*security.Match{{
			NotPrincipals: []*security.StringMatch{{MatchType: &security.StringMatch_Presence{Presence: &emptypb.Empty{}}}},
		}}}}}},
	}
}

// Publish before accepting an ADS connection. This establishes desired state,
// not packet admission: the pinned proxy can still allow traffic if this policy
// is absent during startup. Persistent fail-closed capture remains a separate
// requirement before this experimental option can establish protection.
func (x *Server) configureAuthenticationPolicy() error {
	if !x.requireMTLS {
		return nil
	}
	policy := authenticatedOnlyPolicy()
	name := policy.Namespace + "/" + policy.Name
	if _, _, err := x.authorizations.Apply(map[string]*security.Authorization{name: policy}, nil); err != nil {
		return fmt.Errorf("publish ztunnel authenticated-only policy: %w", err)
	}
	x.log.Info("Published authenticated-only ztunnel policy",
		logfields.Event, "mtls-policy-published",
		logfields.Resource, name,
	)
	return nil
}

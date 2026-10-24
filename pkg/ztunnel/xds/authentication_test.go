// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/ztunnel/pb/security"
)

func TestAuthenticatedOnlyPolicyWireContract(t *testing.T) {
	policy := authenticatedOnlyPolicy()
	encoded, err := proto.Marshal(policy)
	require.NoError(t, err)
	var decoded security.Authorization
	require.NoError(t, proto.Unmarshal(encoded, &decoded))
	require.Equal(t, security.Scope_GLOBAL, decoded.Scope)
	require.Empty(t, decoded.Namespace)
	require.Equal(t, security.Action_DENY, decoded.Action)
	require.False(t, decoded.DryRun)
	require.Len(t, decoded.Rules, 1)
	require.Len(t, decoded.Rules[0].Clauses, 1)
	require.Len(t, decoded.Rules[0].Clauses[0].Matches, 1)
	match := decoded.Rules[0].Clauses[0].Matches[0]
	require.Len(t, match.NotPrincipals, 1)
	require.IsType(t, &security.StringMatch_Presence{}, match.NotPrincipals[0].MatchType)
	require.NotNil(t, match.NotPrincipals[0].GetPresence())
	require.Empty(t, match.Principals)
	require.Empty(t, match.DestinationPorts)
	require.Empty(t, match.NotDestinationPorts)
}

func TestRequireMTLSPolicyDeliveredOverADS(t *testing.T) {
	s, conn := testAuthorizationServer(t)
	s.requireMTLS = true
	require.NoError(t, s.configureAuthenticationPolicy())

	peer := newAuthorizationPeer(t, conn)
	peer.send(t, subscribeAuthorization())
	resp := peer.receive(t)
	require.Equal(t, xdsTypeURLAuthorization, resp.TypeUrl)
	require.Len(t, resp.Resources, 1)
	resource := resp.Resources[0]
	require.Equal(t, "/"+requireMTLSPolicyName, resource.Name)
	require.NotEmpty(t, resource.Version)
	var policy security.Authorization
	require.NoError(t, resource.Resource.UnmarshalTo(&policy))
	require.True(t, proto.Equal(authenticatedOnlyPolicy(), &policy))
	peer.ack(t, resp)

	// Reconfiguration of identical intent must not produce a new policy version.
	require.NoError(t, s.configureAuthenticationPolicy())
	peer.noResponse(t)
}

func TestRequireMTLSDisabledPublishesNoAuthenticationPolicy(t *testing.T) {
	s, conn := testAuthorizationServer(t)
	require.NoError(t, s.configureAuthenticationPolicy())
	peer := newAuthorizationPeer(t, conn)
	peer.send(t, subscribeAuthorization())
	resp := peer.receive(t)
	require.Empty(t, resp.Resources)
}

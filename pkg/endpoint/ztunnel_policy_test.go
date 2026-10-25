// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestZtunnelNativeEndpointSnapshotUnavailableAndDisconnecting(t *testing.T) {
	for _, state := range []State{StateReady, StateRestoring, StateWaitingForIdentity} {
		e := &Endpoint{state: state}
		subject, err := e.SnapshotZtunnelPolicy()
		require.Error(t, err)
		require.Nil(t, subject.Policy)
	}
	e := &Endpoint{state: StateDisconnecting}
	_, err := e.SnapshotZtunnelPolicy()
	require.ErrorIs(t, err, ErrNotAlive)
}

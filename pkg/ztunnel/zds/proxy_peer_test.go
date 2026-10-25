// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Authority is root in the agent's user namespace. A proxy in its own PID
// namespace is reported with PID 0 when the agent does not share the node's
// PID namespace; it is still the proxy, so it is accepted.
func TestAuthorizeProxyPeerUsesRootCredentialsNotPID(t *testing.T) {
	require.NoError(t, authorizeProxyPeer(&unix.Ucred{Uid: 0, Gid: 0, Pid: 4242}))
	require.NoError(t, authorizeProxyPeer(&unix.Ucred{Uid: 0, Gid: 0, Pid: 0}), "a proxy outside the agent's PID namespace")
	require.Error(t, authorizeProxyPeer(&unix.Ucred{Uid: 1000, Pid: 4242}), "a non-root peer")
	require.Error(t, authorizeProxyPeer(&unix.Ucred{Uid: 65534, Pid: 0}), "an unmapped user namespace root")
	require.Error(t, authorizeProxyPeer(nil))
}

// The kernel credentials of a real connected peer reach the rule.
func TestRequireRootProxyPeerReadsKernelCredentials(t *testing.T) {
	zc, _ := zdsSocketPair(t)
	if os.Geteuid() == 0 {
		require.NoError(t, requireRootProxyPeer(zc))
	} else {
		require.Error(t, requireRootProxyPeer(zc), "a non-root test process is not a root proxy")
	}
}

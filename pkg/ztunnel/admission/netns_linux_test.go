// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateNetworkNamespaceRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary-file")
	require.NoError(t, os.WriteFile(path, []byte("not a namespace"), 0600))
	require.Error(t, validateNetworkNamespace(path))
}

func TestValidateNetworkNamespaceAcceptsCurrentNetworkNamespace(t *testing.T) {
	require.NoError(t, validateNetworkNamespace("/proc/self/ns/net"))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"log/slog"
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/lock"
)

func TestMain(m *testing.M) {
	// The timeout fixture exercises lockdebug's long-held-lock diagnostic.
	// Set its process-wide logger before tests/goroutines can use that path.
	lock.SetLogger(slog.Default())
	os.Exit(m.Run())
}

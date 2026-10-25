// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/metrics"
)

func TestMain(m *testing.M) {
	// Legacy construction replaces package globals. Do it before any test
	// starts asynchronous allocator/watch workers, never during cleanup.
	metrics.NewLegacyMetrics().EndpointStateCount.SetEnabled(true)
	os.Exit(m.Run())
}

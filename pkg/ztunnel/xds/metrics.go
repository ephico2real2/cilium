// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// subsystem is the metrics subsystem for ztunnel XDS
	subsystem = "ztunnel_xds"

	// Label names
	labelStatus = "status"
)

// Metrics holds XDS-related metrics for ztunnel workload discovery
type Metrics struct {
	// EnrollmentFailures tracks workload enrollment failures to Z-tunnel via XDS
	// Status values include send_failed, nack_received, invalid_workload_snapshot,
	// and invalid_workload_event.
	EnrollmentFailures metric.Vec[metric.Counter]
	// AuthorizationEvents counts protocol events, not policy enforcement.
	AuthorizationEvents metric.Vec[metric.Counter]
}

// Enable enables XDS metrics for Prometheus scraping.
func (m *Metrics) Enable() {
	if m == nil {
		return
	}
	m.EnrollmentFailures.SetEnabled(true)
	m.AuthorizationEvents.SetEnabled(true)
}

// NewMetrics creates a new Metrics instance for XDS enrollment failures
func NewMetrics() *Metrics {
	return &Metrics{
		AuthorizationEvents: metric.NewCounterVec(metric.CounterOpts{
			Disabled: true, Namespace: metrics.Namespace, Subsystem: subsystem,
			Name: "authorization_events_total",
			Help: "Authorization xDS protocol events by status (ack, nack, cancel, send_failed); not enforcement evidence",
		}, []string{labelStatus}),
		EnrollmentFailures: metric.NewCounterVec(
			metric.CounterOpts{
				Disabled:  true,
				Namespace: metrics.Namespace,
				Subsystem: subsystem,
				Name:      "enrollment_failures_total",
				Help:      "Total number of workload enrollment failures to ztunnel via XDS by status",
			},
			[]string{labelStatus},
		),
	}
}

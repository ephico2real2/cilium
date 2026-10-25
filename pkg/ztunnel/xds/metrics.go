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
	// RemoteProjectionEvents counts remote workload projection changes on
	// ztunnel streams by event.
	RemoteProjectionEvents metric.Vec[metric.Counter]
	// RemoteWorkloads is the number of remote workloads last published by a
	// stream, by peer cluster. Absent before the first projection.
	RemoteWorkloads metric.Vec[metric.Gauge]
	// EffectivePolicyEvents counts effective policy publication and
	// quarantine release events by event.
	EffectivePolicyEvents metric.Vec[metric.Counter]
	// EffectivePolicySources is the number of callers the last reconcile
	// admitted into effective plans, by origin (node, cluster, peer).
	EffectivePolicySources metric.Vec[metric.Gauge]
}

// Enable enables XDS metrics for Prometheus scraping.
func (m *Metrics) Enable() {
	if m == nil {
		return
	}
	m.EnrollmentFailures.SetEnabled(true)
	m.AuthorizationEvents.SetEnabled(true)
	m.RemoteProjectionEvents.SetEnabled(true)
	m.RemoteWorkloads.SetEnabled(true)
	m.EffectivePolicyEvents.SetEnabled(true)
	m.EffectivePolicySources.SetEnabled(true)
}

// NewMetrics creates a new Metrics instance for XDS enrollment failures
func NewMetrics() *Metrics {
	return &Metrics{
		EffectivePolicyEvents: metric.NewCounterVec(metric.CounterOpts{
			Disabled: true, Namespace: metrics.Namespace, Subsystem: subsystem,
			Name: "effective_policy_events_total",
			Help: "Effective ztunnel policy events (published, acknowledged, compile_failed, released, release_refused); acknowledgments are ztunnel ACKs on the current stream, not traffic evidence",
		}, []string{"event"}),
		EffectivePolicySources: metric.NewGaugeVec(metric.GaugeOpts{
			Disabled: true, Namespace: metrics.Namespace, Subsystem: subsystem,
			Name: "effective_policy_sources",
			Help: "Callers admitted into effective ztunnel plans by the last reconcile, by origin (node: this node's captured workloads; cluster: this cluster's other nodes; peer: ClusterMesh peers); admission, not traffic evidence",
		}, []string{"origin"}),
		RemoteProjectionEvents: metric.NewCounterVec(metric.CounterOpts{
			Disabled: true, Namespace: metrics.Namespace, Subsystem: subsystem,
			Name: "remote_projection_events_total",
			Help: "Remote workload projection events on ztunnel xDS streams (projected, withdrawn, withdrawn_local_collision, stream_reset_for_recovery); discovery only, not authorization",
		}, []string{"event"}),
		RemoteWorkloads: metric.NewGaugeVec(metric.GaugeOpts{
			Disabled: true, Namespace: metrics.Namespace, Subsystem: subsystem,
			Name: "remote_workloads",
			Help: "Remote workloads last published to ztunnel by peer cluster; zero after withdrawal",
		}, []string{"peer_cluster"}),
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

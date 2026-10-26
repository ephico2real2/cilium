// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/ztunnel/config"
)

func TestDirectResolverDNS(t *testing.T) {
	resolvers := config.Config{DNSResolverLabels: []string{"k8s:io.kubernetes.pod.namespace=kube-system", "k8s:k8s-app=kube-dns"}}
	socketLB := kpr.KPRConfig{EnableSocketLB: true}
	for _, tc := range []struct {
		name   string
		cfg    config.Config
		kpr    kpr.KPRConfig
		daemon func(*option.DaemonConfig)
		want   bool
		reason string
	}{
		{name: "socket-LB in every Pod", cfg: resolvers, kpr: socketLB, want: true, reason: "port on the wire"},
		{name: "no resolvers", cfg: config.Config{}, kpr: socketLB, reason: "no approved DNS resolver"},
		{name: "socket-LB off", cfg: resolvers, reason: "socket-LB is disabled"},
		{name: "host-namespace socket-LB", cfg: resolvers, kpr: socketLB,
			daemon: func(c *option.DaemonConfig) { c.UnsafeDaemonConfigOption.BPFSocketLBHostnsOnly = true },
			reason: "host-namespace only"},
		{name: "L7 load balancing", cfg: resolvers, kpr: socketLB,
			daemon: func(c *option.DaemonConfig) { c.EnableEnvoyConfig = true }, reason: "enable-envoy-config"},
		{name: "SCTP", cfg: resolvers, kpr: socketLB,
			daemon: func(c *option.DaemonConfig) { c.EnableSCTP = true }, reason: "SCTP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dc := &option.DaemonConfig{}
			if tc.daemon != nil {
				tc.daemon(dc)
			}
			got, reason := directResolverDNS(tc.cfg, tc.kpr, dc)
			require.Equal(t, tc.want, got)
			require.Contains(t, reason, tc.reason)
		})
	}
	got, _ := directResolverDNS(resolvers, socketLB, nil)
	require.False(t, got, "no daemon configuration must not enable the bypass")
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package common

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/ipcache"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestResolveEndpointRemoteWorkloads(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(netip.Addr) (getters.EndpointInfo, bool) {
			return nil, false
		},
	}

	t.Run("with workloads", func(t *testing.T) {
		ipGetter := &testutils.FakeIPGetter{
			OnGetK8sMetadata: func(netip.Addr) *ipcache.K8sMetadata {
				return &ipcache.K8sMetadata{
					Namespace: "shop-ns",
					PodName:   "shop-abc",
					Workloads: []ciliumv2.EndpointWorkload{
						{Kind: "Deployment", Name: "shop"},
					},
				}
			},
			OnLookupSecIDByIP: func(netip.Addr) (ipcache.Identity, bool) {
				return ipcache.Identity{}, false
			},
		}
		r := NewEndpointResolver(hivetest.Logger(t), endpointGetter, &testutils.NoopIdentityGetter, ipGetter)
		ep := r.ResolveEndpoint(ip, 0, DatapathContext{})
		require.Equal(t, []*pb.Workload{{Kind: "Deployment", Name: "shop"}}, ep.Workloads)
		require.Equal(t, "shop-ns", ep.Namespace)
		require.Equal(t, "shop-abc", ep.PodName)
	})

	t.Run("without workloads", func(t *testing.T) {
		ipGetter := &testutils.FakeIPGetter{
			OnGetK8sMetadata: func(netip.Addr) *ipcache.K8sMetadata {
				return &ipcache.K8sMetadata{
					Namespace: "shop-ns",
					PodName:   "shop-abc",
				}
			},
			OnLookupSecIDByIP: func(netip.Addr) (ipcache.Identity, bool) {
				return ipcache.Identity{}, false
			},
		}
		r := NewEndpointResolver(hivetest.Logger(t), endpointGetter, &testutils.NoopIdentityGetter, ipGetter)
		ep := r.ResolveEndpoint(ip, 0, DatapathContext{})
		require.Nil(t, ep.Workloads)
	})
}

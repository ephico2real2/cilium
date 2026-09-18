// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/ipcache"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	fakeTimestamp = "2006-01-02T15:04:05.999999999Z"
	fakeNodeInfo  = accesslog.NodeAddressInfo{
		IPv4: "192.168.1.100",
		IPv6: " fd01::a",
	}
	fakeSourceEndpoint = accesslog.EndpointInfo{
		ID:       1234,
		IPv4:     "10.16.32.10",
		IPv6:     "f00d::a10:0:0:abcd",
		Identity: 9876,
		Labels:   labels.ParseLabelArray("k1=v1", "k2=v2"),
	}
	fakeDestinationEndpoint = accesslog.EndpointInfo{
		ID:       4321,
		IPv4:     "10.16.32.20",
		IPv6:     "f00d::a10:0:0:1234",
		Port:     80,
		Identity: 6789,
		Labels:   labels.ParseLabelArray("k3=v3", "k4=v4"),
	}
)

func BenchmarkL7Decode(b *testing.B) {
	requestPath, err := url.Parse("http://myhost/some/path")
	require.NoError(b, err)
	lr := &accesslog.LogRecord{
		Type:                accesslog.TypeResponse,
		Timestamp:           fakeTimestamp,
		NodeAddressInfo:     fakeNodeInfo,
		ObservationPoint:    accesslog.Ingress,
		SourceEndpoint:      fakeDestinationEndpoint,
		DestinationEndpoint: fakeSourceEndpoint,
		IPVersion:           accesslog.VersionIPv4,
		Verdict:             accesslog.VerdictForwarded,
		TransportProtocol:   accesslog.TransportProtocol(u8proto.TCP),
		ServiceInfo:         nil,
		DropReason:          nil,
		HTTP: &accesslog.LogRecordHTTP{
			Code:     404,
			Method:   "POST",
			URL:      requestPath,
			Protocol: "HTTP/1.1",
			Headers: http.Header{
				"Host":        {"myhost"},
				"Traceparent": {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
			},
		},
	}
	lr.SourceEndpoint.Port = 80
	lr.DestinationEndpoint.Port = 56789

	dnsGetter := &testutils.NoopDNSGetter
	ipGetter := &testutils.NoopIPGetter
	serviceGetter := &testutils.NoopServiceGetter
	endpointGetter := &testutils.NoopEndpointGetter

	parser, err := New(hivetest.Logger(b), dnsGetter, ipGetter, serviceGetter, endpointGetter)
	require.NoError(b, err)

	f := &flowpb.Flow{}
	b.ReportAllocs()

	for b.Loop() {
		_ = parser.Decode(lr, f)
	}
}

func Test_decodeVerdict(t *testing.T) {
	assert.Equal(t, flowpb.Verdict_FORWARDED, decodeVerdict(accesslog.VerdictForwarded))
	assert.Equal(t, flowpb.Verdict_DROPPED, decodeVerdict(accesslog.VerdictDenied))
	assert.Equal(t, flowpb.Verdict_ERROR, decodeVerdict(accesslog.VerdictError))
	assert.Equal(t, flowpb.Verdict_REDIRECTED, decodeVerdict(accesslog.VerdictRedirected))
	assert.Equal(t, flowpb.Verdict_VERDICT_UNKNOWN, decodeVerdict("bad"))
}

func Test_decodeEndpoint(t *testing.T) {
	epi := accesslog.EndpointInfo{
		ID:       1234,
		Identity: 9876,
		Labels: labels.ParseLabelArray(
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.kubernetes.pod.namespace=kube-system",
			"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=kube-system",
			"k8s:k8s-app=hubble-ui",
			"k8s:app.kubernetes.io/name=hubble-ui",
			"k8s:app.kubernetes.io/part-of=cilium",
		),
	}
	expected := &flowpb.Endpoint{
		ID:          1234,
		Identity:    9876,
		ClusterName: "default",
		Namespace:   "kube-system",
		Labels: []string{
			"k8s:app.kubernetes.io/name=hubble-ui",
			"k8s:app.kubernetes.io/part-of=cilium",
			"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=kube-system",
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.kubernetes.pod.namespace=kube-system",
			"k8s:k8s-app=hubble-ui",
		},
		PodName: "hubble-ui",
	}
	ep := decodeEndpoint(epi, "kube-system", "hubble-ui")
	assert.Equal(t, expected, ep)
}

func TestDecodeL7Workloads(t *testing.T) {
	requestPath, err := url.Parse("http://myhost/some/path")
	require.NoError(t, err)
	lr := &accesslog.LogRecord{
		Type:                accesslog.TypeRequest,
		Timestamp:           fakeTimestamp,
		NodeAddressInfo:     fakeNodeInfo,
		ObservationPoint:    accesslog.Ingress,
		SourceEndpoint:      fakeSourceEndpoint,
		DestinationEndpoint: fakeDestinationEndpoint,
		IPVersion:           accesslog.VersionIPv4,
		Verdict:             accesslog.VerdictForwarded,
		TransportProtocol:   accesslog.TransportProtocol(u8proto.TCP),
		HTTP: &accesslog.LogRecordHTTP{
			Code:     0,
			Method:   "GET",
			URL:      requestPath,
			Protocol: "HTTP/1.1",
		},
	}

	t.Run("remote from ipcache", func(t *testing.T) {
		ipGetter := &testutils.FakeIPGetter{
			OnGetK8sMetadata: func(ip netip.Addr) *ipcache.K8sMetadata {
				if ip == netip.MustParseAddr(fakeDestinationEndpoint.IPv4) {
					return &ipcache.K8sMetadata{
						Namespace: "shop-ns",
						PodName:   "shop-abc",
						Workloads: []ciliumv2.EndpointWorkload{
							{Kind: "Deployment", Name: "shop"},
						},
					}
				}
				return nil
			},
		}
		endpointGetter := &testutils.FakeEndpointGetter{
			OnGetEndpointInfo: func(netip.Addr) (getters.EndpointInfo, bool) {
				return nil, false
			},
		}

		parser, err := New(hivetest.Logger(t), &testutils.NoopDNSGetter, ipGetter, &testutils.NoopServiceGetter, endpointGetter)
		require.NoError(t, err)

		f := &flowpb.Flow{}
		err = parser.Decode(lr, f)
		require.NoError(t, err)
		assert.Equal(t, []*flowpb.Workload{{Kind: "Deployment", Name: "shop"}}, f.Destination.Workloads)
	})

	t.Run("local pod overrides", func(t *testing.T) {
		controller := true
		ipGetter := &testutils.FakeIPGetter{
			OnGetK8sMetadata: func(ip netip.Addr) *ipcache.K8sMetadata {
				if ip == netip.MustParseAddr(fakeDestinationEndpoint.IPv4) {
					return &ipcache.K8sMetadata{
						Namespace: "shop-ns",
						PodName:   "shop-abc12-xyz",
						Workloads: []ciliumv2.EndpointWorkload{
							{Kind: "Deployment", Name: "stale"},
						},
					}
				}
				return nil
			},
		}
		endpointGetter := &testutils.FakeEndpointGetter{
			OnGetEndpointInfo: func(ip netip.Addr) (getters.EndpointInfo, bool) {
				if ip == netip.MustParseAddr(fakeDestinationEndpoint.IPv4) {
					return &testutils.FakeEndpointInfo{
						ID: fakeDestinationEndpoint.ID,
						Pod: &slim_corev1.Pod{
							ObjectMeta: slim_metav1.ObjectMeta{
								Name:         "shop-abc12-xyz",
								GenerateName: "shop-abc12-",
								Labels:       map[string]string{"pod-template-hash": "abc12"},
								OwnerReferences: []slim_metav1.OwnerReference{{
									Controller: &controller,
									Kind:       "ReplicaSet",
									Name:       "shop-abc12",
								}},
							},
						},
					}, true
				}
				return nil, false
			},
		}

		parser, err := New(hivetest.Logger(t), &testutils.NoopDNSGetter, ipGetter, &testutils.NoopServiceGetter, endpointGetter)
		require.NoError(t, err)

		f := &flowpb.Flow{}
		err = parser.Decode(lr, f)
		require.NoError(t, err)
		assert.Equal(t, []*flowpb.Workload{{Kind: "Deployment", Name: "shop"}}, f.Destination.Workloads)
	})

	// a local pod with no owner reports no workload, even when the ipcache metadata carries a stale one: the local
	// endpoint is the authority (before the metadata was consulted this was nil, and it must stay nil)
	t.Run("local ownerless pod clears stale metadata", func(t *testing.T) {
		ipGetter := &testutils.FakeIPGetter{
			OnGetK8sMetadata: func(ip netip.Addr) *ipcache.K8sMetadata {
				if ip == netip.MustParseAddr(fakeDestinationEndpoint.IPv4) {
					return &ipcache.K8sMetadata{
						Namespace: "shop-ns",
						PodName:   "bare-pod",
						Workloads: []ciliumv2.EndpointWorkload{{Kind: "Deployment", Name: "stale"}},
					}
				}
				return nil
			},
		}
		endpointGetter := &testutils.FakeEndpointGetter{
			OnGetEndpointInfo: func(ip netip.Addr) (getters.EndpointInfo, bool) {
				if ip == netip.MustParseAddr(fakeDestinationEndpoint.IPv4) {
					return &testutils.FakeEndpointInfo{
						ID:  fakeDestinationEndpoint.ID,
						Pod: &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{Name: "bare-pod"}},
					}, true
				}
				return nil, false
			},
		}

		parser, err := New(hivetest.Logger(t), &testutils.NoopDNSGetter, ipGetter, &testutils.NoopServiceGetter, endpointGetter)
		require.NoError(t, err)

		f := &flowpb.Flow{}
		err = parser.Decode(lr, f)
		require.NoError(t, err)
		assert.Nil(t, f.Destination.Workloads)
	})
}

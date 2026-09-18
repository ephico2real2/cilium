// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ipsecfake "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/source"
	wgfake "github.com/cilium/cilium/pkg/wireguard/fake"
)

type recordingIPCache struct {
	lastMeta *ipcache.K8sMetadata
}

func (r *recordingIPCache) Upsert(_ string, _ net.IP, _ uint8, k8sMeta *ipcache.K8sMetadata, _ ipcache.Identity) (bool, error) {
	r.lastMeta = k8sMeta
	return false, nil
}

func (r *recordingIPCache) LookupByIP(string) (ipcache.Identity, bool) {
	return ipcache.Identity{}, false
}

func (r *recordingIPCache) Delete(string, source.Source) bool { return false }

func (r *recordingIPCache) UpsertMetadata(cmtypes.PrefixCluster, source.Source, ipcacheTypes.ResourceID, ...ipcache.IPMetadata) {
}

func (r *recordingIPCache) RemoveLabelsExcluded(labels.Labels, map[cmtypes.PrefixCluster]struct{}, ipcacheTypes.ResourceID) {
}

func (r *recordingIPCache) DeleteOnMetadataMatch(string, source.Source, string, string) bool {
	return false
}

type nopPolicyManager struct{}

func (nopPolicyManager) TriggerPolicyUpdates(string) {}

func TestEndpointUpdatedPropagatesWorkloadsToIPCache(t *testing.T) {
	rec := &recordingIPCache{}
	k := &K8sCiliumEndpointsWatcher{
		logger:         hivetest.Logger(t),
		ipcache:        rec,
		policyManager:  nopPolicyManager{},
		wgConfig:       wgfake.Config{},
		ipsecConfig:    ipsecfake.Config{},
		localNodeStore: node.NewTestLocalNodeStore(node.LocalNode{}),
	}

	ep := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "shop-abc-123",
			Namespace: "default",
		},
		Identity: &v2.EndpointIdentity{ID: 1234},
		Networking: &v2.EndpointNetworking{
			NodeIP:     "192.168.0.1",
			Addressing: []*v2.AddressPair{{IPV4: "10.0.0.1"}},
		},
		Workloads: []v2.EndpointWorkload{{Kind: "Deployment", Name: "shop"}},
	}
	k.endpointUpdated(nil, ep)

	require.NotNil(t, rec.lastMeta)
	require.Equal(t, []v2.EndpointWorkload{{Kind: "Deployment", Name: "shop"}}, rec.lastMeta.Workloads)
	require.Equal(t, "default", rec.lastMeta.Namespace)
	require.Equal(t, "shop-abc-123", rec.lastMeta.PodName)
}

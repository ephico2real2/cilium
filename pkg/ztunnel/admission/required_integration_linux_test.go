// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package admission

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/endpoint"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/time"
)

func realJournalRecorder(t *testing.T, s *IntentStore) *fakeRequiredRecorder {
	t.Helper()
	return &fakeRequiredRecorder{
		lookup: func(ctx context.Context, uid string) (string, bool, error) {
			records, err := s.List()
			if err != nil {
				return "", false, err
			}
			for _, record := range records {
				if record.PodUID == uid {
					return record.NamespaceUID, true, nil
				}
			}
			return "", false, nil
		},
		record: func(ctx context.Context, ep *endpoint.Endpoint, namespaceUID string, pod *slimv1.Pod) (func() error, func(), error) {
			identity := RequiredIdentity{ClusterID: 17, NodeName: pod.Spec.NodeName, Namespace: pod.Namespace, NamespaceUID: namespaceUID, PodName: pod.Name, PodUID: string(pod.UID), ServiceAccount: pod.Spec.ServiceAccountName, EndpointID: ep.GetID16(), ContainerID: "test-real-journal-sandbox", NetnsPath: ep.GetContainerNetnsPath(), NetnsDevice: 4, NetnsInode: 12345, NetnsCookie: 98765}
			_, err := s.PersistRequired(identity)
			if err != nil {
				return nil, nil, err
			}
			return func() error { return nil }, func() {}, nil
		},
	}
}
func openAdmissionJournal(t *testing.T) (*IntentStore, string) {
	t.Helper()
	base := t.TempDir()
	s, err := OpenIntentStore(base)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s, base
}

func TestAdmissionCancellationAfterRealIntentCommitDoesNotEnrollOrErase(t *testing.T) {
	g, _, ep := cniGateFixture(t)
	store, base := openAdmissionJournal(t)
	recorder := realJournalRecorder(t, store)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	record := recorder.record
	recorder.record = func(ctx context.Context, ep *endpoint.Endpoint, uid string, pod *slimv1.Pod) (func() error, func(), error) {
		check, release, err := record(ctx, ep, uid, pod)
		if err == nil {
			cancel()
		}
		return check, release, err
	}
	g.recorder = recorder
	var enrolled atomic.Int32
	g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error { enrolled.Add(1); return nil }
	require.ErrorIs(t, g.WaitForEndpoint(ctx, ep), context.Canceled)
	require.Zero(t, enrolled.Load())
	require.NoError(t, store.Close())
	reopened, err := OpenIntentStore(base)
	require.NoError(t, err)
	defer reopened.Close()
	records, err := reopened.List()
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, ep.K8sUID, records[0].PodUID)
	require.Equal(t, "namespace-generation", records[0].NamespaceUID)
}

func TestAdmissionRealPersistenceFailureBlocksEnrollmentThenRecovers(t *testing.T) {
	g, _, ep := cniGateFixture(t)
	store, _ := openAdmissionJournal(t)
	g.recorder = realJournalRecorder(t, store)
	g.budget = 25 * time.Millisecond
	injected := errors.New("injected disk fsync failure")
	original := store.ops.syncFile
	store.ops.syncFile = func(*os.File) error { return injected }
	var enrolled atomic.Int32
	g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error { enrolled.Add(1); return nil }
	require.ErrorIs(t, g.WaitForEndpoint(t.Context(), ep), injected)
	require.Zero(t, enrolled.Load())
	records, err := store.List()
	require.NoError(t, err)
	require.Empty(t, records)
	store.ops.syncFile = original
	require.NoError(t, g.WaitForEndpoint(t.Context(), ep))
	require.EqualValues(t, 1, enrolled.Load())
	records, err = store.List()
	require.NoError(t, err)
	require.Len(t, records, 1)
}

func TestAdmissionRestartDoesNotForgetRequiredWhenLabelRemoved(t *testing.T) {
	first, _, ep := cniGateFixture(t)
	store, base := openAdmissionJournal(t)
	first.recorder = realJournalRecorder(t, store)
	require.NoError(t, first.WaitForEndpoint(t.Context(), ep))
	require.NoError(t, store.Close())
	reopened, err := OpenIntentStore(base)
	require.NoError(t, err)
	defer reopened.Close()
	second, client, same := cniGateFixture(t)
	second.recorder = realJournalRecorder(t, reopened)
	namespace, err := client.CoreV1().Namespaces().Get(t.Context(), same.GetK8sNamespace(), metav1.GetOptions{})
	require.NoError(t, err)
	delete(namespace.Labels, "io.cilium/mtls-enabled")
	_, err = client.CoreV1().Namespaces().Update(t.Context(), namespace, metav1.UpdateOptions{})
	require.NoError(t, err)
	var enrolled atomic.Int32
	second.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error { enrolled.Add(1); return nil }
	require.ErrorContains(t, second.WaitForEndpoint(t.Context(), same), "enrollment intent changed")
	require.Zero(t, enrolled.Load())
	records, err := reopened.List()
	require.NoError(t, err)
	require.Len(t, records, 1)
}

func TestAdmissionRestartRejectsNamespaceRecreationForRetainedPodUID(t *testing.T) {
	first, _, ep := cniGateFixture(t)
	store, base := openAdmissionJournal(t)
	first.recorder = realJournalRecorder(t, store)
	require.NoError(t, first.WaitForEndpoint(t.Context(), ep))
	store.Close()
	reopened, err := OpenIntentStore(base)
	require.NoError(t, err)
	defer reopened.Close()
	second, client, same := cniGateFixture(t)
	second.recorder = realJournalRecorder(t, reopened)
	ns, err := client.CoreV1().Namespaces().Get(t.Context(), same.GetK8sNamespace(), metav1.GetOptions{})
	require.NoError(t, err)
	ns.UID = "replacement-namespace"
	_, err = client.CoreV1().Namespaces().Update(t.Context(), ns, metav1.UpdateOptions{})
	require.NoError(t, err)
	var enrolled atomic.Int32
	second.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error { enrolled.Add(1); return nil }
	require.ErrorContains(t, second.WaitForEndpoint(t.Context(), same), "namespace was recreated")
	require.Zero(t, enrolled.Load())
}

func TestAdmissionPostCommitSandboxChangeIsDeniedWithoutErasingIntent(t *testing.T) {
	g, _, ep := cniGateFixture(t)
	store, _ := openAdmissionJournal(t)
	recorder := realJournalRecorder(t, store)
	persist := recorder.record
	var checks atomic.Int32
	recorder.record = func(ctx context.Context, ep *endpoint.Endpoint, uid string, pod *slimv1.Pod) (func() error, func(), error) {
		_, release, err := persist(ctx, ep, uid, pod)
		return func() error {
			if checks.Add(1) >= 2 {
				return errors.New("injected sandbox replacement")
			}
			return nil
		}, release, err
	}
	g.recorder = recorder
	require.ErrorContains(t, g.WaitForEndpoint(t.Context(), ep), "sandbox replacement")
	records, err := store.List()
	require.NoError(t, err)
	require.Len(t, records, 1)
}

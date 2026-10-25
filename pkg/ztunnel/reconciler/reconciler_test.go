// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	testendpointmanager "github.com/cilium/cilium/pkg/testutils/endpointmanager"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/table"
	"github.com/cilium/cilium/pkg/ztunnel/xds"
	"github.com/cilium/cilium/pkg/ztunnel/zds"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MockEndpointEnroller is a mock implementation of zds.EndpointEnroller.
// It tracks enrollment operations for testing purposes.
type MockEndpointEnroller struct {
	enrolledEndpoints map[uint16]*endpoint.Endpoint
	disenrolledIDs    []uint16
	enrollErr         error
	disenrollErr      error
	deletedEndpoints  []*endpoint.Endpoint
}

// NewMockEndpointEnroller creates a new mock endpoint enroller.
func NewMockEndpointEnroller() *MockEndpointEnroller {
	return &MockEndpointEnroller{
		enrolledEndpoints: make(map[uint16]*endpoint.Endpoint),
		disenrolledIDs:    []uint16{},
	}
}

// EnrollEndpoint enrolls an endpoint to ztunnel.
func (m *MockEndpointEnroller) EnrollEndpoint(ep *endpoint.Endpoint) error {
	if m.enrollErr != nil {
		return m.enrollErr
	}
	m.enrolledEndpoints[ep.ID] = ep
	return nil
}

// DisenrollEndpoint disenrolls an endpoint from ztunnel.
func (m *MockEndpointEnroller) DisenrollEndpoint(ep *endpoint.Endpoint) error {
	if m.disenrollErr != nil {
		return m.disenrollErr
	}
	delete(m.enrolledEndpoints, ep.ID)
	m.disenrolledIDs = append(m.disenrolledIDs, ep.ID)
	return nil
}

func (m *MockEndpointEnroller) CleanupDeletedEndpointContext(_ context.Context, ep *endpoint.Endpoint) error {
	m.deletedEndpoints = append(m.deletedEndpoints, ep)
	return m.disenrollErr
}

// SeedInitialSnapshot sends an initial snapshot of endpoints to ztunnel.
func (m *MockEndpointEnroller) SeedInitialSnapshot(endpoints ...*endpoint.Endpoint) {
	for _, ep := range endpoints {
		m.enrolledEndpoints[ep.ID] = ep
	}
}

// MockRestorer is a mock implementation of endpointstate.Restorer.
type MockRestorer struct {
	waitErr error
}

func (m *MockRestorer) WaitForEndpointRestore(ctx context.Context) error {
	return m.waitErr
}

func (m *MockRestorer) WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error {
	return m.waitErr
}

func (m *MockRestorer) WaitForInitialPolicy(ctx context.Context) error {
	return m.waitErr
}

var _ endpointstate.Restorer = &MockRestorer{}

// MockCiliumEndpointResource is a mock implementation of resource.Resource[*types.CiliumEndpoint].
type MockCiliumEndpointResource struct {
	store    *MockCiliumEndpointStore
	storeErr error
}

func (m *MockCiliumEndpointResource) Store(ctx context.Context) (resource.Store[*types.CiliumEndpoint], error) {
	if m.storeErr != nil {
		return nil, m.storeErr
	}
	return m.store, nil
}

func (m *MockCiliumEndpointResource) Observe(ctx context.Context, next func(resource.Event[*types.CiliumEndpoint]), complete func(error)) {
	panic("MockCiliumEndpointResource.Observe not implemented")
}

func (m *MockCiliumEndpointResource) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[*types.CiliumEndpoint] {
	panic("MockCiliumEndpointResource.Events not implemented")
}

// MockCiliumEndpointStore is a mock implementation of resource.Store[*types.CiliumEndpoint].
type MockCiliumEndpointStore struct {
	endpoints map[string]*types.CiliumEndpoint
}

func (m *MockCiliumEndpointStore) List() []*types.CiliumEndpoint {
	panic("MockCiliumEndpointStore.List not implemented")
}

func (m *MockCiliumEndpointStore) Get(obj *types.CiliumEndpoint) (*types.CiliumEndpoint, bool, error) {
	panic("MockCiliumEndpointStore.Get not implemented")
}

func (m *MockCiliumEndpointStore) GetByKey(key resource.Key) (*types.CiliumEndpoint, bool, error) {
	panic("MockCiliumEndpointStore.GetByKey not implemented")
}

func (m *MockCiliumEndpointStore) ByIndex(index string, key string) ([]*types.CiliumEndpoint, error) {
	var result []*types.CiliumEndpoint
	for _, ep := range m.endpoints {
		if ep.Namespace == key {
			result = append(result, ep)
		}
	}
	return result, nil
}

func (m *MockCiliumEndpointStore) IndexKeys(indexName, indexedValue string) ([]string, error) {
	panic("MockCiliumEndpointStore.IndexKeys not implemented")
}

func (m *MockCiliumEndpointStore) IterKeys() resource.KeyIter {
	panic("MockCiliumEndpointStore.IterKeys not implemented")
}

func (m *MockCiliumEndpointStore) CacheStore() cache.Store {
	panic("MockCiliumEndpointStore.CacheStore not implemented")
}

// MockCiliumEndpointSliceResource is a mock implementation of resource.Resource[*v2alpha1.CiliumEndpointSlice].
type MockCiliumEndpointSliceResource struct {
	store    *MockCiliumEndpointSliceStore
	storeErr error
}

func (m *MockCiliumEndpointSliceResource) Store(ctx context.Context) (resource.Store[*v2alpha1.CiliumEndpointSlice], error) {
	if m.storeErr != nil {
		return nil, m.storeErr
	}
	return m.store, nil
}

func (m *MockCiliumEndpointSliceResource) Observe(ctx context.Context, next func(resource.Event[*v2alpha1.CiliumEndpointSlice]), complete func(error)) {
	panic("MockCiliumEndpointSliceResource.Observe not implemented")
}

func (m *MockCiliumEndpointSliceResource) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[*v2alpha1.CiliumEndpointSlice] {
	panic("MockCiliumEndpointSliceResource.Events not implemented")
}

// MockCiliumEndpointSliceStore is a mock implementation of resource.Store[*v2alpha1.CiliumEndpointSlice].
type MockCiliumEndpointSliceStore struct {
	slices map[string]*v2alpha1.CiliumEndpointSlice
}

func (m *MockCiliumEndpointSliceStore) List() []*v2alpha1.CiliumEndpointSlice {
	panic("MockCiliumEndpointSliceStore.List not implemented")
}

func (m *MockCiliumEndpointSliceStore) Get(key *v2alpha1.CiliumEndpointSlice) (*v2alpha1.CiliumEndpointSlice, bool, error) {
	panic("MockCiliumEndpointSliceStore.Get not implemented")
}

func (m *MockCiliumEndpointSliceStore) GetByKey(key resource.Key) (*v2alpha1.CiliumEndpointSlice, bool, error) {
	panic("MockCiliumEndpointStore.GetByKey not implemented")
}

func (m *MockCiliumEndpointSliceStore) ByIndex(index string, key string) ([]*v2alpha1.CiliumEndpointSlice, error) {
	var result []*v2alpha1.CiliumEndpointSlice
	for _, s := range m.slices {
		if s.Namespace == key {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *MockCiliumEndpointSliceStore) IndexKeys(indexName, indexedValue string) ([]string, error) {
	panic("MockCiliumEndpointStore.IndexKeys not implemented")
}

func (m *MockCiliumEndpointSliceStore) IterKeys() resource.KeyIter {
	panic("MockCiliumEndpointStore.IterKeys not implemented")
}

func (m *MockCiliumEndpointSliceStore) CacheStore() cache.Store {
	panic("MockCiliumEndpointSliceStore.CacheStore not implemented")
}

var _ resource.Store[*types.CiliumEndpoint] = &MockCiliumEndpointStore{}
var _ resource.Store[*v2alpha1.CiliumEndpointSlice] = &MockCiliumEndpointSliceStore{}

// createTestEndpoint creates a test endpoint with the given parameters.
func createTestEndpoint(id uint16, namespace, podName, netnsPath string) *endpoint.Endpoint {
	return createTestEndpointWithLabels(id, namespace, podName, netnsPath, nil)
}

// createTestEndpointWithLabels creates a test endpoint with the given parameters and labels.
func createTestEndpointWithLabels(id uint16, namespace, podName, netnsPath string, lbls labels.Labels) *endpoint.Endpoint {
	ep := &endpoint.Endpoint{
		ID:           id,
		K8sNamespace: namespace,
		K8sPodName:   podName,
		K8sUID:       "test-pod-uid-" + namespace + "/" + podName,
	}
	ep.SetContainerNetnsPath(netnsPath)
	if lbls != nil {
		ep.SecurityIdentity = identity.NewIdentity(identity.NumericIdentity(id), lbls)
	}
	return ep
}

// requiredTestEndpoint is a Required endpoint as the agent creates it: source
// IP verification is enabled, so captured membership can be published.
func requiredTestEndpoint(id uint16, namespace, podName, netnsPath string) *endpoint.Endpoint {
	ep := createTestEndpointWithLabels(id, namespace, podName, netnsPath, labels.Labels{})
	lib := option.GetEndpointMutableOptionLibrary()
	ep.Options = option.NewIntOptions(&lib)
	ep.Options.SetBool(option.SourceIPVerification, true)
	return ep
}

// setupTest creates a test environment with mock dependencies and returns
// the database, table, mocks, and reconciler instance.
func setupTest(t *testing.T) (*statedb.DB, statedb.RWTable[*table.EnrolledNamespace], *testendpointmanager.MockEndpointManager, *MockEndpointEnroller, *EnrollmentReconciler, chan *xds.EndpointEvent) {
	db := statedb.New()
	tbl, err := table.NewEnrolledNamespacesTable(db)
	require.NoError(t, err)

	logger := hivetest.Logger(t)

	mockEpMgr := testendpointmanager.NewMockEndpointManager()
	mockEnroller := NewMockEndpointEnroller()
	endpointEventCh := make(chan *xds.EndpointEvent, 100)

	mockCEPResource := &MockCiliumEndpointResource{
		store: &MockCiliumEndpointStore{
			endpoints: make(map[string]*types.CiliumEndpoint),
		},
	}

	mockCESResource := &MockCiliumEndpointSliceResource{
		store: &MockCiliumEndpointSliceStore{
			slices: make(map[string]*v2alpha1.CiliumEndpointSlice),
		},
	}

	// Create a promise that resolves immediately with a mock restorer.
	restorer, restorerPromise := promise.New[endpointstate.Restorer]()
	restorer.Resolve(&MockRestorer{})

	// hivetest.Lifecycle automatically calls Start() when Append() is invoked,
	// and queues Stop() for test cleanup.
	lc := hivetest.Lifecycle(t)

	ops, err := NewEnrollmentReconciler(params{
		Config:                      config.Config{EnableZTunnel: true},
		DB:                          db,
		EnrolledNamespaceTable:      tbl,
		Logger:                      logger,
		Lifecycle:                   lc,
		EndpointManager:             mockEpMgr,
		EndpointEnroller:            mockEnroller,
		EndpointDeletionCleaner:     mockEnroller,
		RestorerPromise:             restorerPromise,
		EndpointEventChannel:        endpointEventCh,
		CiliumEndpointResource:      mockCEPResource,
		CiliumEndpointSliceResource: mockCESResource,
		Membership:                  membership.NewRegistry(1),
	})
	require.NoError(t, err)

	reconcilerOps := ops.(*EnrollmentReconciler)

	return db, tbl, mockEpMgr, mockEnroller, reconcilerOps, endpointEventCh
}

// drainEndpointEvents drains the endpoint event channel and verifies the expected
// count and event type.
func drainEndpointEvents(t *testing.T, ch <-chan *xds.EndpointEvent, expectedCount int, expectedType xds.EndpointEventType) {
	t.Helper()
	var events []*xds.EndpointEvent
	require.Eventually(t, func() bool {
		for {
			select {
			case event := <-ch:
				events = append(events, event)
			default:
				return len(events) >= expectedCount
			}
		}
	}, time.Second, 10*time.Millisecond, "expected %d endpoint events, got %d", expectedCount, len(events))

	require.Len(t, events, expectedCount, "unexpected number of endpoint events")
	for _, event := range events {
		assert.Equal(t, expectedType, event.Type)
	}
}

// TestEnrollmentReconciler_Update tests the Update operation of the reconciler,
// which enrolls all endpoints in a namespace when that namespace is enrolled.
func TestEnrollmentReconciler_Update(t *testing.T) {
	tests := []struct {
		name                      string
		namespace                 string
		endpoints                 []*endpoint.Endpoint
		enableCiliumEndpointSlice bool
		ciliumEndpoints           map[string]*types.CiliumEndpoint
		ciliumEndpointSlices      map[string]*v2alpha1.CiliumEndpointSlice
		enrollErr                 error
		expectedEnrolled          int
		expectedEndpointEvents    int
		expectedError             bool
	}{
		{
			name:      "enroll endpoints in namespace",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpoint(2, "test-ns", "pod-2", "/var/run/netns/test2"),
			},
			expectedEnrolled:       2,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:      "skip endpoints without netns path",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpoint(2, "test-ns", "pod-2", ""),
			},
			expectedEnrolled:       1,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:      "skip ztunnel endpoints",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpointWithLabels(2, "test-ns", "ztunnel-cilium-abc", "/var/run/netns/test2", labels.Labels{
					"k8s:app": labels.NewLabel("app", "ztunnel-cilium", labels.LabelSourceK8s),
				}),
			},
			expectedEnrolled:       1,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:      "enrollment error",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			enrollErr:              errors.New("enrollment failed"),
			expectedEnrolled:       0,
			expectedEndpointEvents: 0,
			expectedError:          true,
		},
		{
			name:             "no endpoints in namespace",
			namespace:        "empty-ns",
			endpoints:        []*endpoint.Endpoint{},
			expectedEnrolled: 0,
			expectedError:    false,
		},
		{
			name:                      "enroll with CiliumEndpoint resources",
			namespace:                 "test-ns",
			enableCiliumEndpointSlice: false,
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			ciliumEndpoints: map[string]*types.CiliumEndpoint{
				"test-ns/cep-1": {
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "cep-1",
						Namespace: "test-ns",
					},
				},
				"test-ns/cep-2": {
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "cep-2",
						Namespace: "test-ns",
					},
				},
			},
			expectedEnrolled:       1,
			expectedEndpointEvents: 2,
			expectedError:          false,
		},
		{
			name:                      "enroll with CiliumEndpointSlice resources",
			namespace:                 "test-ns",
			enableCiliumEndpointSlice: true,
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			ciliumEndpointSlices: map[string]*v2alpha1.CiliumEndpointSlice{
				"test-ns/ces-1": {
					ObjectMeta: v1.ObjectMeta{
						Name: "ces-1",
					},
					Namespace: "test-ns",
					Endpoints: []v2alpha1.CoreCiliumEndpoint{
						{
							Name: "pod-1",
						},
						{
							Name: "pod-2",
						},
					},
				},
			},
			expectedEnrolled:       1,
			expectedEndpointEvents: 2,
			expectedError:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore the original option value
			originalEnableCES := option.Config.EnableCiliumEndpointSlice
			defer func() {
				option.Config.EnableCiliumEndpointSlice = originalEnableCES
			}()
			option.Config.EnableCiliumEndpointSlice = tt.enableCiliumEndpointSlice
			db, _, mockEpMgr, mockEnroller, ops, endpointEventCh := setupTest(t)

			// Setup CiliumEndpoint or CiliumEndpointSlice resources
			if tt.ciliumEndpoints != nil {
				mockCEPStore := ops.ciliumEndpointResource.(*MockCiliumEndpointResource).store
				mockCEPStore.endpoints = tt.ciliumEndpoints
			}
			if tt.ciliumEndpointSlices != nil {
				mockCESStore := ops.ciliumEndpointSliceResource.(*MockCiliumEndpointSliceResource).store
				mockCESStore.slices = tt.ciliumEndpointSlices
			}

			mockEpMgr.Endpoints = tt.endpoints
			mockEnroller.enrollErr = tt.enrollErr

			ns := &table.EnrolledNamespace{
				Name:   tt.namespace,
				UID:    "test-namespace-" + tt.namespace,
				Status: reconciler.StatusPending(),
			}

			err := ops.Update(context.Background(), db.ReadTxn(), 1, ns)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Len(t, mockEnroller.enrolledEndpoints, tt.expectedEnrolled)
			drainEndpointEvents(t, endpointEventCh, tt.expectedEndpointEvents, xds.CREATE)
		})
	}
}

// TestEnrollmentReconciler_Delete tests the Delete operation of the reconciler,
// which disenrolls all endpoints in a namespace when that namespace is unenrolled.
func TestEnrollmentReconciler_Delete(t *testing.T) {
	tests := []struct {
		name                      string
		namespace                 string
		endpoints                 []*endpoint.Endpoint
		enableCiliumEndpointSlice bool
		ciliumEndpoints           map[string]*types.CiliumEndpoint
		ciliumEndpointSlices      map[string]*v2alpha1.CiliumEndpointSlice
		disenrollErr              error
		expectedDisenrolled       int
		expectedEndpointEvents    int
		expectedError             bool
	}{
		{
			name:      "disenroll endpoints in namespace",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpoint(2, "test-ns", "pod-2", "/var/run/netns/test2"),
			},
			expectedDisenrolled:    2,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:      "skip endpoints without netns path",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpoint(2, "test-ns", "pod-2", ""),
			},
			expectedDisenrolled:    1,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:      "skip ztunnel endpoints",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpointWithLabels(2, "test-ns", "ztunnel-cilium-xyz", "/var/run/netns/test2", labels.Labels{
					"k8s:app": labels.NewLabel("app", "ztunnel-cilium", labels.LabelSourceK8s),
				}),
			},
			expectedDisenrolled:    1,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:      "disenrollment error",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			disenrollErr:           errors.New("disenrollment failed"),
			expectedDisenrolled:    0,
			expectedEndpointEvents: 0,
			expectedError:          true,
		},
		{
			name:                      "disenroll with CiliumEndpoint resources",
			namespace:                 "test-ns",
			enableCiliumEndpointSlice: false,
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			ciliumEndpoints: map[string]*types.CiliumEndpoint{
				"test-ns/cep-1": {
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "cep-1",
						Namespace: "test-ns",
					},
				},
			},
			expectedDisenrolled:    1,
			expectedEndpointEvents: 1,
			expectedError:          false,
		},
		{
			name:                      "disenroll with CiliumEndpointSlice resources",
			namespace:                 "test-ns",
			enableCiliumEndpointSlice: true,
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			ciliumEndpointSlices: map[string]*v2alpha1.CiliumEndpointSlice{
				"test-ns/ces-1": {
					ObjectMeta: v1.ObjectMeta{
						Name: "ces-1",
					},
					Namespace: "test-ns",
					Endpoints: []v2alpha1.CoreCiliumEndpoint{
						{Name: "pod-1"},
						{Name: "pod-2"},
					},
				},
			},
			expectedDisenrolled:    1,
			expectedEndpointEvents: 2,
			expectedError:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore the original option value
			originalEnableCES := option.Config.EnableCiliumEndpointSlice
			defer func() {
				option.Config.EnableCiliumEndpointSlice = originalEnableCES
			}()
			option.Config.EnableCiliumEndpointSlice = tt.enableCiliumEndpointSlice
			db, _, mockEpMgr, mockEnroller, ops, endpointEventCh := setupTest(t)

			mockEpMgr.Endpoints = tt.endpoints
			mockEnroller.disenrollErr = tt.disenrollErr

			// Setup CiliumEndpoint or CiliumEndpointSlice resources
			if tt.ciliumEndpoints != nil {
				mockCEPStore := ops.ciliumEndpointResource.(*MockCiliumEndpointResource).store
				mockCEPStore.endpoints = tt.ciliumEndpoints
			}
			if tt.ciliumEndpointSlices != nil {
				mockCESStore := ops.ciliumEndpointSliceResource.(*MockCiliumEndpointSliceResource).store
				mockCESStore.slices = tt.ciliumEndpointSlices
			}

			ns := &table.EnrolledNamespace{
				Name:   tt.namespace,
				UID:    "test-namespace-" + tt.namespace,
				Status: reconciler.StatusPending(),
			}

			err := ops.Delete(context.Background(), db.ReadTxn(), 1, ns)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, mockEnroller.disenrolledIDs, tt.expectedDisenrolled)
			}

			drainEndpointEvents(t, endpointEventCh, tt.expectedEndpointEvents, xds.REMOVED)
		})
	}
}

// TestEnrollmentReconciler_EndpointCreated tests the EndpointCreated event handler,
// which enrolls newly created endpoints if their namespace is enrolled.
func TestEnrollmentReconciler_EndpointCreated(t *testing.T) {
	tests := []struct {
		name             string
		endpoint         *endpoint.Endpoint
		enrolledNs       []string
		enrollErr        error
		strictAdmission  bool
		expectedEnrolled bool
	}{
		{
			name:             "enroll endpoint in enrolled namespace",
			endpoint:         createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			enrolledNs:       []string{"test-ns"},
			expectedEnrolled: true,
		},
		{
			name:             "strict creation is owned by the synchronous API gate",
			endpoint:         createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			enrolledNs:       []string{"test-ns"},
			strictAdmission:  true,
			expectedEnrolled: false,
		},
		{
			name:             "skip endpoint in unenrolled namespace",
			endpoint:         createTestEndpoint(1, "other-ns", "pod-1", "/var/run/netns/test1"),
			enrolledNs:       []string{"test-ns"},
			expectedEnrolled: false,
		},
		{
			name:             "skip endpoint without netns path",
			endpoint:         createTestEndpoint(1, "test-ns", "pod-1", ""),
			enrolledNs:       []string{"test-ns"},
			expectedEnrolled: false,
		},
		{
			name: "skip ztunnel endpoint",
			endpoint: createTestEndpointWithLabels(1, "test-ns", "ztunnel-cilium-abc", "/var/run/netns/test1", labels.Labels{
				"k8s:app": labels.NewLabel("app", "ztunnel-cilium", labels.LabelSourceK8s),
			}),
			enrolledNs:       []string{"test-ns"},
			expectedEnrolled: false,
		},
		{
			name:             "skip endpoint without namespace",
			endpoint:         createTestEndpoint(1, "", "pod-1", "/var/run/netns/test1"),
			enrolledNs:       []string{"test-ns"},
			expectedEnrolled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, tbl, _, mockEnroller, ops, _ := setupTest(t)

			mockEnroller.enrollErr = tt.enrollErr
			ops.strictCreationAdmission = tt.strictAdmission

			// Initialize table and add enrolled namespaces.
			txn := db.WriteTxn(tbl)
			complete := tbl.RegisterInitializer(txn, "test")
			for _, ns := range tt.enrolledNs {
				tbl.Insert(txn, &table.EnrolledNamespace{
					Name:   ns,
					UID:    "test-namespace-" + ns,
					Status: reconciler.StatusPending(),
				})
			}
			complete(txn)
			txn.Commit()

			// Clear any enrollments from initialization.
			mockEnroller.enrolledEndpoints = make(map[uint16]*endpoint.Endpoint)

			// Trigger endpoint created event.
			ops.EndpointCreated(tt.endpoint)

			// EndpointCreated is synchronous, but we add a small delay for safety.
			time.Sleep(50 * time.Millisecond)

			if tt.expectedEnrolled {
				assert.Contains(t, mockEnroller.enrolledEndpoints, tt.endpoint.ID)
			} else {
				assert.NotContains(t, mockEnroller.enrolledEndpoints, tt.endpoint.ID)
			}
		})
	}
}

// TestEnrollmentReconciler_EndpointDeleted tests the EndpointDeleted event handler,
// which disenrolls deleted endpoints if their namespace is enrolled.
func TestEnrollmentReconciler_EndpointDeleted(t *testing.T) {
	tests := []struct {
		name                string
		endpoint            *endpoint.Endpoint
		enrolledNs          []string
		expectedDisenrolled bool
	}{
		{
			name:                "disenroll endpoint in enrolled namespace",
			endpoint:            createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			enrolledNs:          []string{"test-ns"},
			expectedDisenrolled: true,
		},
		{
			name:                "skip endpoint in unenrolled namespace",
			endpoint:            createTestEndpoint(1, "other-ns", "pod-1", "/var/run/netns/test1"),
			enrolledNs:          []string{"test-ns"},
			expectedDisenrolled: false,
		},
		{
			name:                "skip endpoint without netns path",
			endpoint:            createTestEndpoint(1, "test-ns", "pod-1", ""),
			enrolledNs:          []string{"test-ns"},
			expectedDisenrolled: false,
		},
		{
			name: "skip ztunnel endpoint",
			endpoint: createTestEndpointWithLabels(1, "test-ns", "ztunnel-cilium-xyz", "/var/run/netns/test1", labels.Labels{
				"k8s:app": labels.NewLabel("app", "ztunnel-cilium", labels.LabelSourceK8s),
			}),
			enrolledNs:          []string{"test-ns"},
			expectedDisenrolled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, tbl, _, mockEnroller, ops, _ := setupTest(t)

			// Initialize table and add enrolled namespaces.
			txn := db.WriteTxn(tbl)
			complete := tbl.RegisterInitializer(txn, "test")
			for _, ns := range tt.enrolledNs {
				tbl.Insert(txn, &table.EnrolledNamespace{
					Name:   ns,
					UID:    "test-namespace-" + ns,
					Status: reconciler.StatusPending(),
				})
			}
			complete(txn)
			txn.Commit()

			// Clear disenrollment tracking.
			mockEnroller.disenrolledIDs = []uint16{}

			// Trigger endpoint deleted event.
			ops.EndpointDeleted(tt.endpoint, endpoint.DeleteConfig{})

			// EndpointDeleted is synchronous, but we add a small delay for safety.
			time.Sleep(50 * time.Millisecond)

			if tt.expectedDisenrolled {
				assert.Contains(t, mockEnroller.disenrolledIDs, tt.endpoint.ID)
			} else {
				assert.NotContains(t, mockEnroller.disenrolledIDs, tt.endpoint.ID)
			}
		})
	}
}

func TestStrictEnrollmentRequiresDeletionCleaner(t *testing.T) {
	ops, err := NewEnrollmentReconciler(params{Config: config.Config{EnableZTunnel: true, RequireMTLS: true}})
	require.ErrorContains(t, err, "requires deleted-endpoint cleanup")
	require.Nil(t, ops)
}

func TestStrictDeletionUsesCleanerWithoutNamespaceOrProxyLabelExemption(t *testing.T) {
	_, _, _, mockEnroller, ops, _ := setupTest(t)
	ops.strictCreationAdmission = true
	ep := createTestEndpointWithLabels(77, "namespace-no-longer-enrolled", "old-pod", "/missing-deleted-netns", labels.Labels{
		"k8s:app": labels.NewLabel("app", "ztunnel-cilium", labels.LabelSourceK8s),
	})
	ep.K8sUID = "immutable-deleted-uid"
	ops.EndpointDeleted(ep, endpoint.DeleteConfig{})
	require.Equal(t, []*endpoint.Endpoint{ep}, mockEnroller.deletedEndpoints)
	require.Empty(t, mockEnroller.disenrolledIDs, "Strict deletion must not remove capture through legacy unenrollment")
}

func TestStrictEndpointDeleteRevokesPublishedMembershipBeforeCleanup(t *testing.T) {
	_, _, _, _, ops, _ := setupTest(t)
	ops.strictCreationAdmission = true
	ep := requiredTestEndpoint(78, "orders", "api", "/runtime/netns/api")
	ep.K8sUID = "pod-incarnation-a"
	ref, err := ops.membership.Require("namespace-incarnation-a", ep.K8sUID, ep.GetID16(), ep.GetContainerNetnsPath())
	require.NoError(t, err)
	generation, ok := ops.membership.BeginZDS(ref)
	require.True(t, ok)
	require.True(t, ops.membership.MarkCaptured(ref, generation))
	require.True(t, ops.membership.AcknowledgeZDS(ref, generation))
	require.True(t, ep.SetZtunnelMembership(endpoint.ZtunnelMembership{
		Version: 1, Revision: 1, Epoch: ref.Epoch, Generation: generation,
		State: endpoint.ZtunnelMembershipCaptured, NamespaceUID: ref.Key.NamespaceUID,
	}), "the fixture publishes captured membership")

	ops.EndpointDeleted(ep, endpoint.DeleteConfig{})

	state, ok := ops.membership.Get(ref)
	require.True(t, ok)
	require.True(t, state.Draining)
	require.False(t, state.ReadyForAddress())
	published, ok := ep.GetZtunnelMembership()
	require.True(t, ok)
	require.Equal(t, endpoint.ZtunnelMembershipDraining, published.State)
}

func TestStrictNamespaceUnenrollmentRevokesRemoteMembershipAndRetainsCapture(t *testing.T) {
	_, _, mockEndpointManager, mockEnroller, ops, _ := setupTest(t)
	ops.strictCreationAdmission = true
	ep := requiredTestEndpoint(79, "orders", "api", "/runtime/netns/api")
	ep.K8sUID = "pod-incarnation-b"
	mockEndpointManager.Endpoints = []*endpoint.Endpoint{ep}
	ref, err := ops.membership.Require("namespace-incarnation-b", ep.K8sUID, ep.GetID16(), ep.GetContainerNetnsPath())
	require.NoError(t, err)
	generation, ok := ops.membership.BeginZDS(ref)
	require.True(t, ok)
	require.True(t, ops.membership.MarkCaptured(ref, generation))
	require.True(t, ops.membership.AcknowledgeZDS(ref, generation))
	require.True(t, ep.SetZtunnelMembership(endpoint.ZtunnelMembership{
		Version: 1, Revision: 1, Epoch: ref.Epoch, Generation: generation,
		State: endpoint.ZtunnelMembershipCaptured, NamespaceUID: ref.Key.NamespaceUID,
	}), "the fixture publishes captured membership")

	err = ops.Delete(t.Context(), ops.db.ReadTxn(), 1, &table.EnrolledNamespace{Name: "orders", UID: ref.Key.NamespaceUID})
	require.ErrorIs(t, err, zds.ErrStrictLiveUnenrollment)
	state, ok := ops.membership.Get(ref)
	require.True(t, ok)
	require.False(t, state.ReadyForAddress(), "unenrollment must revoke remote publication while keeping capture in place")
	published, ok := ep.GetZtunnelMembership()
	require.True(t, ok)
	require.Equal(t, endpoint.ZtunnelMembershipRequired, published.State)
	require.Zero(t, published.Generation)
	require.Empty(t, mockEnroller.deletedEndpoints, "strict unenrollment must not remove capture while live endpoints remain")
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/go-openapi/runtime"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/rate"
	testendpointmanager "github.com/cilium/cilium/pkg/testutils/endpointmanager"
)

type cniAdmissionGateFunc func(context.Context, *endpoint.Endpoint) error

func (f cniAdmissionGateFunc) WaitForEndpoint(ctx context.Context, ep *endpoint.Endpoint) error {
	return f(ctx, ep)
}

type cniAdmissionRemovalSpy struct {
	*testendpointmanager.MockEndpointManager
	removed []*endpoint.Endpoint
	configs []endpoint.DeleteConfig
}

func (s *cniAdmissionRemovalSpy) RemoveEndpoint(ep *endpoint.Endpoint, cfg endpoint.DeleteConfig) []error {
	s.removed = append(s.removed, ep)
	s.configs = append(s.configs, cfg)
	return nil
}

func TestEndpointCreationGateGroupPassesOrHasNoProviders(t *testing.T) {
	for _, withGate := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty-group", true: "successful-gate"}[withGate], func(t *testing.T) {
			spy := &cniAdmissionRemovalSpy{MockEndpointManager: testendpointmanager.NewMockEndpointManager()}
			manager := &endpointAPIManager{endpointManager: spy}
			ep := &endpoint.Endpoint{ID: 61}
			calls := 0
			if withGate {
				manager.endpointCreationGates = []endpointmanager.EndpointCreationGate{
					cniAdmissionGateFunc(func(_ context.Context, got *endpoint.Endpoint) error {
						require.Same(t, ep, got)
						calls++
						return nil
					}),
				}
			}
			require.NoError(t, manager.waitForEndpointCreationGates(t.Context(), ep))
			require.Empty(t, spy.removed)
			if withGate {
				require.Equal(t, 1, calls)
			} else {
				require.Zero(t, calls)
			}
		})
	}
}

func TestEndpointCreationGateFailureStopsBeforeLaterGates(t *testing.T) {
	expected := errors.New("proxy did not acknowledge enrollment")
	spy := &cniAdmissionRemovalSpy{MockEndpointManager: testendpointmanager.NewMockEndpointManager()}
	laterCalled := false
	manager := &endpointAPIManager{endpointManager: spy,
		endpointCreationGates: []endpointmanager.EndpointCreationGate{
			cniAdmissionGateFunc(func(context.Context, *endpoint.Endpoint) error { return expected }),
			cniAdmissionGateFunc(func(context.Context, *endpoint.Endpoint) error { laterCalled = true; return nil }),
		},
	}
	err := manager.waitForEndpointCreationGates(t.Context(), &endpoint.Endpoint{ID: 62})
	require.ErrorIs(t, err, expected)
	require.False(t, laterCalled)
	require.Empty(t, spy.removed, "Error-only helper must leave cleanup ownership with CreateEndpoint")
}

func TestEndpointAdmissionFailureUsesExistingCleanupCodeAndRetainsIpOwnership(t *testing.T) {
	expected := errors.New("injected capture failure")
	spy := &cniAdmissionRemovalSpy{MockEndpointManager: testendpointmanager.NewMockEndpointManager()}
	manager := &endpointAPIManager{endpointManager: spy,
		endpointCreationGates: []endpointmanager.EndpointCreationGate{
			cniAdmissionGateFunc(func(context.Context, *endpoint.Endpoint) error { return expected }),
		},
	}
	ep := &endpoint.Endpoint{ID: 63}
	failure := manager.waitForEndpointCreationGates(t.Context(), ep)
	require.ErrorIs(t, failure, expected)
	// This explicitly tests errorDuringCreation itself. Production source
	// must call it in the gate failure branch; full CNI integration verifies
	// that branch rather than this test duplicating CreateEndpoint internals.
	got, code, err := manager.errorDuringCreation(ep, failure)
	require.Nil(t, got)
	require.Equal(t, endpointapi.PutEndpointIDFailedCode, code)
	require.ErrorIs(t, err, expected)
	require.Len(t, spy.removed, 1)
	require.Same(t, ep, spy.removed[0])
	require.Len(t, spy.configs, 1)
	require.True(t, spy.configs[0].NoIPRelease, "CNI/runtime still owns release of the provided IP")
}

func TestEndpointCreationGatePreservesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	manager := &endpointAPIManager{endpointCreationGates: []endpointmanager.EndpointCreationGate{
		cniAdmissionGateFunc(func(ctx context.Context, _ *endpoint.Endpoint) error { return ctx.Err() }),
	}}
	require.ErrorIs(t, manager.waitForEndpointCreationGates(ctx, &endpoint.Endpoint{ID: 64}), context.Canceled)
}

// Embedding the real interface lets this stub override only CreateEndpoint;
// all other methods would panic if this handler unexpectedly used them.
type cniFailedCreateAPI struct {
	EndpointAPIManager
	failure error
	called  bool
}

func (m *cniFailedCreateAPI) CreateEndpoint(context.Context, *models.EndpointChangeRequest) (*endpoint.Endpoint, int, error) {
	m.called = true
	return nil, endpointapi.PutEndpointIDFailedCode, m.failure
}

func TestEndpointPutHandlerReturnsAdmissionFailureToCni(t *testing.T) {
	logger := hivetest.Logger(t)
	limiter, err := rate.NewAPILimiterSet(logger, nil, nil, nil)
	require.NoError(t, err) // absent named limiter uses the real no-op request path
	expected := errors.New("endpoint startup admission failed: proxy did not acknowledge")
	manager := &cniFailedCreateAPI{failure: expected}
	handler := &EndpointPutEndpointIDHandler{
		logger: logger, apiLimiterSet: limiter, endpointAPIManager: manager,
		waitReadyFn: func(context.Context) error { return nil },
	}
	response := handler.Handle(endpointapi.PutEndpointIDParams{
		HTTPRequest: httptest.NewRequest(http.MethodPut, "http://localhost/v1/endpoint/0", nil),
		Endpoint:    &models.EndpointChangeRequest{K8sNamespace: "apps", K8sPodName: "server", K8sUID: "pod-generation"},
	})
	writer := httptest.NewRecorder()
	response.WriteResponse(writer, runtime.JSONProducer())
	require.True(t, manager.called)
	require.Equal(t, endpointapi.PutEndpointIDFailedCode, writer.Code)
	require.NotEqual(t, http.StatusCreated, writer.Code)
	require.Contains(t, writer.Body.String(), expected.Error())
}

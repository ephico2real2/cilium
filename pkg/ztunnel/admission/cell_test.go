// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"context"
	"errors"
	goruntime "runtime"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ktesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hive"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	k8stestutils "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimmeta "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slimfake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	testendpointmanager "github.com/cilium/cilium/pkg/testutils/endpointmanager"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

func cniGateFixture(t *testing.T) (*gate, *slimfake.Clientset, *endpoint.Endpoint) {
	t.Helper()
	ns := &slimv1.Namespace{ObjectMeta: slimmeta.ObjectMeta{
		Name: "apps", UID: "namespace-generation", ResourceVersion: "1",
		Labels: map[string]string{"io.cilium/mtls-enabled": "true"},
	}}
	pod := &slimv1.Pod{ObjectMeta: slimmeta.ObjectMeta{
		Name: "server", Namespace: "apps", UID: "pod-generation", ResourceVersion: "1",
	}, Spec: slimv1.PodSpec{NodeName: "node-a", ServiceAccountName: "server"}}
	client := slimfake.NewSimpleClientset(ns, pod)
	ep := &endpoint.Endpoint{ID: 71, K8sNamespace: "apps", K8sPodName: "server", K8sUID: "pod-generation"}
	ep.SetContainerNetnsPath("/runtime-owned/netns/example")
	ep.SetPod(&slimv1.Pod{ObjectMeta: slimmeta.ObjectMeta{
		UID: "pod-generation", Name: "server", Namespace: "apps",
	}, Spec: slimv1.PodSpec{NodeName: "node-a", ServiceAccountName: "stale-cache-service-account"}})
	g := &gate{
		enabled: true, core: client.CoreV1(), logger: hivetest.Logger(t),
		agentNamespace: "agent-system", nodeName: func() string { return "node-a" },
		budget: 250 * time.Millisecond, attemptTimeout: 30 * time.Millisecond,
		initialBackoff: time.Millisecond,
		validateNetns:  func(string) error { return nil },
		enroll:         func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error { return nil },
	}
	return g, client, ep
}

func TestDisabledAdmissionHasNoDependenciesOrSideEffects(t *testing.T) {
	g := &gate{} // nil clients/enroller/logger are intentionally safe when disabled
	require.NoError(t, g.WaitForEndpoint(t.Context(), &endpoint.Endpoint{}))
}

func TestAdmissionUsesFreshPrivateMetadataAndRequiresEnrollment(t *testing.T) {
	g, client, managed := cniGateFixture(t)
	var enrolled atomic.Int32
	var validated atomic.Int32
	g.validateNetns = func(path string) error {
		require.Equal(t, managed.GetContainerNetnsPath(), path)
		validated.Add(1)
		return nil
	}
	g.enroll = func(ctx context.Context, owner, view *endpoint.Endpoint) error {
		require.Same(t, managed, owner)
		require.NotSame(t, managed, view)
		require.Equal(t, managed.GetID16(), view.GetID16())
		require.Equal(t, managed.K8sUID, view.K8sUID)
		require.Equal(t, managed.GetContainerNetnsPath(), view.GetContainerNetnsPath())
		require.Equal(t, "pod-generation", string(view.GetPod().UID))
		require.Equal(t, "server", view.GetPod().Spec.ServiceAccountName)
		require.Equal(t, "node-a", view.GetPod().Spec.NodeName)
		require.NoError(t, ctx.Err())
		enrolled.Add(1)
		return nil
	}
	require.NoError(t, g.WaitForEndpoint(t.Context(), managed))
	require.EqualValues(t, 1, enrolled.Load())
	require.EqualValues(t, 2, validated.Load())
	require.Len(t, client.Actions(), 4, "Namespace and Pod must each be read before and after enrollment")
	require.Equal(t, "stale-cache-service-account", managed.GetPod().Spec.ServiceAccountName, "Admission must not mutate shared endpoint metadata")
}

func TestAdmissionDoesNotAckMissingOrStaleManagedIdentity(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale-managed", true: "missing-managed"}[missing], func(t *testing.T) {
			g, _, ep := cniGateFixture(t)
			g.budget = 30 * time.Millisecond
			if missing {
				ep.SetPod(nil)
			} else {
				ep.SetPod(&slimv1.Pod{ObjectMeta: slimmeta.ObjectMeta{UID: "stale-generation", Name: "server", Namespace: "apps"}})
			}
			var enrolled atomic.Int32
			g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error { enrolled.Add(1); return nil }
			require.ErrorContains(t, g.WaitForEndpoint(t.Context(), ep), "managed endpoint metadata is not synchronized")
			require.Zero(t, enrolled.Load())
		})
	}
}

func TestAdmissionRecoversWhenManagedMetadataSynchronizes(t *testing.T) {
	g, client, ep := cniGateFixture(t)
	ep.SetPod(nil)
	var namespaceReads atomic.Int32
	var enrolled atomic.Int32
	// Do not issue nested fake-client operations inside a reactor: Fake
	// holds its own mutex while invoking reactors. An atomic SetPod is safe.
	client.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
		if namespaceReads.Add(1) >= 2 {
			ep.SetPod(&slimv1.Pod{ObjectMeta: slimmeta.ObjectMeta{
				UID: "pod-generation", Name: "server", Namespace: "apps",
			}, Spec: slimv1.PodSpec{NodeName: "node-a", ServiceAccountName: "server"}})
		}
		return false, nil, nil
	})
	g.enroll = func(_ context.Context, owner, view *endpoint.Endpoint) error {
		enrolled.Add(1)
		require.Equal(t, "pod-generation", string(view.GetPod().UID))
		return nil
	}
	require.NoError(t, g.WaitForEndpoint(t.Context(), ep))
	require.GreaterOrEqual(t, namespaceReads.Load(), int32(3))
	require.EqualValues(t, 1, enrolled.Load())
}

func TestAdmissionRejectsInvalidIdentityAndNamespaceInputs(t *testing.T) {
	for _, scenario := range []string{"missing-cni-uid", "missing-names-with-cni-uid", "missing-namespace", "missing-pod-name", "stale-live-uid", "missing-live-pod", "empty-serviceaccount", "foreign-node", "terminating", "missing-netns", "host-network", "agent-namespace"} {
		t.Run(scenario, func(t *testing.T) {
			g, client, ep := cniGateFixture(t)
			pod, err := client.CoreV1().Pods("apps").Get(t.Context(), "server", metav1.GetOptions{})
			require.NoError(t, err)
			switch scenario {
			case "missing-cni-uid":
				ep.K8sUID = ""
			case "missing-names-with-cni-uid":
				ep.K8sNamespace, ep.K8sPodName = "", ""
			case "missing-namespace":
				ep.K8sNamespace = ""
			case "missing-pod-name":
				ep.K8sPodName = ""
			case "stale-live-uid":
				pod.UID = "new-pod-generation"
			case "empty-serviceaccount":
				pod.Spec.ServiceAccountName = ""
			case "foreign-node":
				pod.Spec.NodeName = "node-b"
			case "terminating":
				now := slimmeta.NewTime(time.Now())
				pod.DeletionTimestamp = &now
			case "missing-netns":
				ep.SetContainerNetnsPath("")
			case "host-network":
				pod.Spec.HostNetwork = true
			case "agent-namespace":
				g.agentNamespace = "apps"
			}
			if scenario == "missing-live-pod" {
				require.NoError(t, client.CoreV1().Pods("apps").Delete(t.Context(), "server", metav1.DeleteOptions{}))
				g.budget = 30 * time.Millisecond
			} else {
				_, err = client.CoreV1().Pods("apps").Update(t.Context(), pod, metav1.UpdateOptions{})
				require.NoError(t, err)
			}
			var called atomic.Int32
			g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error { called.Add(1); return nil }
			require.Error(t, g.WaitForEndpoint(t.Context(), ep))
			require.Zero(t, called.Load(), "Invalid inputs must never result in enrollment or success")
		})
	}
}

func TestAdmissionRejectsNamespaceTypeFailureBeforeEnrollment(t *testing.T) {
	g, _, ep := cniGateFixture(t)
	g.budget = 30 * time.Millisecond
	expected := errors.New("injected non-network namespace")
	g.validateNetns = func(string) error { return expected }
	var calls atomic.Int32
	g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error { calls.Add(1); return nil }
	require.ErrorIs(t, g.WaitForEndpoint(t.Context(), ep), expected)
	require.Zero(t, calls.Load())
}

func TestAdmissionCanRecoverFromDisconnectedProxyAndNack(t *testing.T) {
	for _, scenario := range []string{"disconnected", "nack"} {
		t.Run(scenario, func(t *testing.T) {
			g, client, ep := cniGateFixture(t)
			var calls atomic.Int32
			g.enroll = func(ctx context.Context, _, _ *endpoint.Endpoint) error {
				if calls.Add(1) == 1 {
					if scenario == "disconnected" {
						<-ctx.Done()
						return ctx.Err()
					}
					return errors.New("injected proxy NACK")
				}
				return nil
			}
			client.ClearActions()
			require.NoError(t, g.WaitForEndpoint(t.Context(), ep))
			require.EqualValues(t, 2, calls.Load())
			require.GreaterOrEqual(t, len(client.Actions()), 6, "Recovery must refresh API intent, not reuse first attempt's objects")
		})
	}
}

func TestAdmissionCancellationNeverReportsSuccess(t *testing.T) {
	g, _, ep := cniGateFixture(t)
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered := make(chan struct{})
	var attempts atomic.Int32
	g.enroll = func(ctx context.Context, _, _ *endpoint.Endpoint) error {
		attempts.Add(1)
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}
	result := make(chan error, 1)
	go func() { result <- g.WaitForEndpoint(parent, ep) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Enrollment was not entered")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("Canceled admission did not exit")
	}
	require.EqualValues(t, 1, attempts.Load())
}

func TestAdmissionChecksCancellationEvenIfEnrollerReturnsNil(t *testing.T) {
	g, _, ep := cniGateFixture(t)
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error { cancel(); return nil }
	require.ErrorIs(t, g.WaitForEndpoint(parent, ep), context.Canceled)
}

func TestAdmissionDoesNotFailOpenOnApiForbidden(t *testing.T) {
	g, client, ep := cniGateFixture(t)
	var calls atomic.Int32
	client.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
		calls.Add(1)
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, "apps", errors.New("injected authorization refusal"))
	})
	err := g.WaitForEndpoint(t.Context(), ep)
	require.True(t, apierrors.IsForbidden(err))
	require.EqualValues(t, 1, calls.Load(), "Authorization errors must not be treated as enrollment absence")
}

func TestAdmissionPinsNamespaceUidAcrossRetries(t *testing.T) {
	g, client, ep := cniGateFixture(t)
	var calls atomic.Int32
	g.enroll = func(ctx context.Context, _, _ *endpoint.Endpoint) error {
		calls.Add(1)
		ns, err := client.CoreV1().Namespaces().Get(ctx, "apps", metav1.GetOptions{})
		require.NoError(t, err)
		ns.UID = "recreated-namespace"
		ns.ResourceVersion = "2"
		_, err = client.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
		require.NoError(t, err)
		return errors.New("injected disconnected operation before retry")
	}
	err := g.WaitForEndpoint(t.Context(), ep)
	require.ErrorContains(t, err, "namespace was recreated")
	require.EqualValues(t, 1, calls.Load())
}

func TestAdmissionCannotDowngradeRequiredIntentAfterAck(t *testing.T) {
	g, client, ep := cniGateFixture(t)
	var calls atomic.Int32
	g.enroll = func(ctx context.Context, _, _ *endpoint.Endpoint) error {
		calls.Add(1)
		ns, err := client.CoreV1().Namespaces().Get(ctx, "apps", metav1.GetOptions{})
		require.NoError(t, err)
		delete(ns.Labels, "io.cilium/mtls-enabled")
		ns.ResourceVersion = "2"
		_, err = client.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
		require.NoError(t, err)
		return nil
	}
	require.ErrorContains(t, g.WaitForEndpoint(t.Context(), ep), "enrollment intent changed during required")
	require.EqualValues(t, 1, calls.Load())
}

func TestAdmissionRetriesChangedNamespaceRvWithFreshAck(t *testing.T) {
	g, client, ep := cniGateFixture(t)
	var calls atomic.Int32
	g.enroll = func(ctx context.Context, _, _ *endpoint.Endpoint) error {
		if calls.Add(1) == 1 {
			ns, err := client.CoreV1().Namespaces().Get(ctx, "apps", metav1.GetOptions{})
			require.NoError(t, err)
			ns.ResourceVersion = "opaque-new-revision"
			_, err = client.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
			require.NoError(t, err)
		}
		return nil
	}
	require.NoError(t, g.WaitForEndpoint(t.Context(), ep))
	require.EqualValues(t, 2, calls.Load(), "Namespace change across ACK requires a new admission attempt/ACK")
}

func TestAdmissionPrivateMetadataIsStableDuringManagedMetadataUpdates(t *testing.T) {
	g, _, managed := cniGateFixture(t)
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			default:
			}
			managed.SetPod(&slimv1.Pod{ObjectMeta: slimmeta.ObjectMeta{
				UID: "pod-generation", Name: "server", Namespace: "apps",
			}, Spec: slimv1.PodSpec{NodeName: "node-a", ServiceAccountName: "concurrent-cache-service-account"}})
			goruntime.Gosched()
		}
	}()
	defer func() { close(stop); <-stopped }()
	g.enroll = func(_ context.Context, owner, view *endpoint.Endpoint) error {
		require.Same(t, managed, owner)
		require.NotSame(t, managed, view)
		require.Equal(t, "pod-generation", string(view.GetPod().UID))
		require.Equal(t, "server", view.GetPod().Spec.ServiceAccountName)
		return nil
	}
	require.NoError(t, g.WaitForEndpoint(t.Context(), managed))
}

func TestAdmissionRejectsPodUidChangeAfterAck(t *testing.T) {
	g, client, ep := cniGateFixture(t)
	g.enroll = func(ctx context.Context, _, _ *endpoint.Endpoint) error {
		pod, err := client.CoreV1().Pods("apps").Get(ctx, "server", metav1.GetOptions{})
		require.NoError(t, err)
		pod.UID = "changed-after-ack"
		_, err = client.CoreV1().Pods("apps").Update(ctx, pod, metav1.UpdateOptions{})
		require.NoError(t, err)
		return nil
	}
	require.ErrorContains(t, g.WaitForEndpoint(t.Context(), ep), "Pod identity changed")
}

func TestAdmissionRejectsNamespaceTypeFailureAfterAck(t *testing.T) {
	g, _, ep := cniGateFixture(t)
	var validations atomic.Int32
	g.validateNetns = func(string) error {
		if validations.Add(1) > 1 {
			return errors.New("namespace path stopped being a network namespace")
		}
		return nil
	}
	require.ErrorContains(t, g.WaitForEndpoint(t.Context(), ep), "invalid after enrollment")
	require.EqualValues(t, 2, validations.Load())
}

func TestAdmissionUnenrolledIntentDoesNotEnroll(t *testing.T) {
	g, client, ep := cniGateFixture(t)
	ns, err := client.CoreV1().Namespaces().Get(t.Context(), "apps", metav1.GetOptions{})
	require.NoError(t, err)
	ns.Labels = nil
	_, err = client.CoreV1().Namespaces().Update(t.Context(), ns, metav1.UpdateOptions{})
	require.NoError(t, err)
	client.ClearActions()
	g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error {
		t.Fatal("Unenrolled intent must not enroll")
		return nil
	}
	g.validateNetns = func(string) error { t.Fatal("Unenrolled intent must not validate capture namespace"); return nil }
	require.NoError(t, g.WaitForEndpoint(t.Context(), ep))
	require.Len(t, client.Actions(), 4)
}

func TestAdmissionRejectsNamespaceWithoutResourceVersion(t *testing.T) {
	g, client, ep := cniGateFixture(t)
	ns, err := client.CoreV1().Namespaces().Get(t.Context(), "apps", metav1.GetOptions{})
	require.NoError(t, err)
	ns.ResourceVersion = ""
	_, err = client.CoreV1().Namespaces().Update(t.Context(), ns, metav1.UpdateOptions{})
	require.NoError(t, err)
	g.enroll = func(context.Context, *endpoint.Endpoint, *endpoint.Endpoint) error {
		t.Fatal("Incomplete namespace identity must not enroll")
		return nil
	}
	require.ErrorContains(t, g.WaitForEndpoint(t.Context(), ep), "namespace identity is empty")
}

type gateGroupInput struct {
	cell.In
	Gates []endpointmanager.EndpointCreationGate `group:"endpoint-creation-gates"`
}

func TestAdmissionHiveUsesRealZdsProviderAndTypedGroup(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "compatible", true: "strict"}[strict], func(t *testing.T) {
			logger := hivetest.Logger(t)
			_, cs := k8stestutils.NewFakeClientset(logger)
			var received []endpointmanager.EndpointCreationGate
			h := hive.New(
				cell.Provide(func() config.Config {
					cfg := config.DefaultConfig
					cfg.EnableZTunnel, cfg.RequireMTLS = strict, strict
					return cfg
				}),
				cell.Provide(func() k8sclient.Clientset { return cs }),
				cell.Provide(func() *option.DaemonConfig { return &option.DaemonConfig{K8sNamespace: "custom-agent-system"} }),
				cell.Provide(func() endpointmanager.EndpointManager { return testendpointmanager.NewMockEndpointManager() }),
				zds.Cell,
				Cell,
				cell.Invoke(func(in gateGroupInput) { received = in.Gates }),
			)
			// Populate-only: actual ZDS dependencies are constructed, but its
			// lifecycle never creates the real default Unix socket.
			require.NoError(t, h.Populate(logger))
			require.Len(t, received, 1)
			require.NotNil(t, received[0])
		})
	}
}

func TestAdmissionRejectsManagedDeletionBeforeAndAfterACK(t *testing.T) {
	for _, when := range []string{"before-attempt", "during-ack", "after-api-recheck"} {
		t.Run(when, func(t *testing.T) {
			g, client, view := cniGateFixture(t)
			logger := hivetest.Logger(t)
			repo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
			ep, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{Logger: logger, PolicyRepo: repo}, nil, nil,
				&models.EndpointChangeRequest{ID: int64(view.ID), K8sUID: view.K8sUID, K8sNamespace: view.K8sNamespace,
					K8sPodName: view.K8sPodName, ContainerNetnsPath: view.GetContainerNetnsPath()}, nil)
			require.NoError(t, err)
			ep.UpdateLogger(nil)
			ep.SetPod(view.GetPod().DeepCopy())
			require.True(t, ep.SetState(endpoint.StateWaitingForIdentity, "admission test"))
			disconnect := func() {
				require.True(t, ep.SetState(endpoint.StateDisconnecting, "concurrent deletion"))
				require.True(t, ep.SetState(endpoint.StateDisconnected, "deletion complete"))
			}
			calls := 0
			g.enroll = func(_ context.Context, owner, private *endpoint.Endpoint) error {
				require.Same(t, ep, owner)
				require.NotSame(t, owner, private)
				calls++
				if when == "during-ack" {
					disconnect()
				}
				return nil
			}
			if when == "before-attempt" {
				disconnect()
			}
			if when == "after-api-recheck" {
				reads := 0
				client.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
					reads++
					if reads == 2 {
						disconnect()
					}
					return false, nil, nil
				})
			}
			require.ErrorContains(t, g.WaitForEndpoint(t.Context(), ep), "managed endpoint disconnected")
			if when == "before-attempt" {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
		})
	}
}

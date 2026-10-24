// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/time"
)

type admissionLogOutput struct {
	bytes.Buffer
	retry chan struct{}
}

func (w *admissionLogOutput) Write(b []byte) (int, error) {
	n, err := w.Buffer.Write(b)
	if bytes.Contains(b, []byte("Endpoint startup admission retry")) {
		select {
		case w.retry <- struct{}{}:
		default:
		}
	}
	return n, err
}

func TestAdmissionCancellationDuringBackoffLogsTerminalOutcome(t *testing.T) {
	g, _, ep := cniGateFixture(t)
	output := &admissionLogOutput{retry: make(chan struct{}, 1)}
	g.logger = slog.New(slog.NewJSONHandler(output, nil))
	g.initialBackoff = time.Second
	g.budget = 2 * time.Second
	g.enroll = func(context.Context, *endpoint.Endpoint) error {
		return errors.New("injected missing proxy ACK")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- g.WaitForEndpoint(ctx, ep) }()
	select {
	case <-output.retry:
	case <-time.After(time.Second):
		t.Fatal("Retry was not logged")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorContains(t, err, "injected missing proxy ACK")
	case <-time.After(time.Second):
		t.Fatal("Canceled backoff did not exit")
	}
	// No logger goroutine remains after result publication; reading is safe.
	decoder := json.NewDecoder(&output.Buffer)
	var retry, terminal map[string]any
	require.NoError(t, decoder.Decode(&retry))
	require.NoError(t, decoder.Decode(&terminal))
	require.Equal(t, "WARN", retry["level"])
	require.Equal(t, "ERROR", terminal["level"])
	require.Equal(t, "Endpoint startup admission failed", terminal["msg"])
	for _, key := range []string{"stage", "attempt", "elapsedDuration", "deadline", "endpointID", "k8sUID", "pod", "k8sNamespace", "error"} {
		require.Contains(t, retry, key)
		require.Contains(t, terminal, key)
	}
	require.Equal(t, "cni-startup-admission", terminal["stage"])
	require.Equal(t, float64(1), terminal["attempt"])
	require.Equal(t, "pod-generation", terminal["k8sUID"])
}

func TestAdmissionDoesNotExemptCopiedProxyAppLabel(t *testing.T) {
	g, client, ep := cniGateFixture(t)
	pod, err := client.CoreV1().Pods("apps").Get(t.Context(), "server", metav1.GetOptions{})
	require.NoError(t, err)
	pod.Labels = map[string]string{"app": "ztunnel-cilium"}
	_, err = client.CoreV1().Pods("apps").Update(t.Context(), pod, metav1.UpdateOptions{})
	require.NoError(t, err)
	ep.SetPod(pod.DeepCopy())
	calls := 0
	g.enroll = func(context.Context, *endpoint.Endpoint) error {
		calls++
		return nil
	}
	require.NoError(t, g.WaitForEndpoint(t.Context(), ep))
	require.Equal(t, 1, calls, "A copied proxy label must still require enrollment and its ACK")
}

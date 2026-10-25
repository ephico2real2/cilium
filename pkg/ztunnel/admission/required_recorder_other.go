//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package admission

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cilium/cilium/pkg/endpoint"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

var errRecorderUnsupported = errors.New("durable required admission requires Linux")

type unsupportedRecorder struct{}

func newRequiredRecorder(string, uint32, func() string, *slog.Logger) requiredRecorder {
	return unsupportedRecorder{}
}
func (unsupportedRecorder) Lookup(context.Context, string) (string, bool, error) {
	return "", false, errRecorderUnsupported
}
func (unsupportedRecorder) Record(context.Context, *endpoint.Endpoint, string, *slimv1.Pod) (func() error, func(), error) {
	return nil, nil, errRecorderUnsupported
}
func (unsupportedRecorder) Close() error { return nil }

func isRequiredConflict(error) bool { return false }

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package admission

import (
	"context"

	"github.com/cilium/cilium/pkg/endpoint"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// fakeRequiredRecorder keeps old admission tests independent of filesystem and
// Linux namespace privileges. New tests below use the REAL durable store inside
// its Record hook and execute the REAL WaitForEndpoint retry/cancellation path.
type fakeRequiredRecorder struct {
	lookup func(context.Context, string) (string, bool, error)
	record func(context.Context, *endpoint.Endpoint, string, *slimv1.Pod) (func() error, func(), error)
}

func (f *fakeRequiredRecorder) Lookup(ctx context.Context, uid string) (string, bool, error) {
	if f.lookup != nil {
		return f.lookup(ctx, uid)
	}
	return "", false, nil
}
func (f *fakeRequiredRecorder) Record(ctx context.Context, ep *endpoint.Endpoint, uid string, pod *slimv1.Pod) (func() error, func(), error) {
	if f.record != nil {
		return f.record(ctx, ep, uid, pod)
	}
	return func() error { return nil }, func() {}, nil
}
func (*fakeRequiredRecorder) Close() error { return nil }

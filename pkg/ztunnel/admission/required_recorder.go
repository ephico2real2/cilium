// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package admission

import (
	"context"

	"github.com/cilium/cilium/pkg/endpoint"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// requiredRecorder persists intent only. It neither installs a kernel fence nor
// restores capture/ACK evidence. Required remains sticky across request retries.
type requiredRecorder interface {
	Lookup(context.Context, string) (namespaceUID string, required bool, err error)
	Record(context.Context, *endpoint.Endpoint, string, *slimv1.Pod) (recheck func() error, release func(), err error)
	Close() error
}

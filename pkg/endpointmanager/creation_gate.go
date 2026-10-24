// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"

	"github.com/cilium/cilium/pkg/endpoint"
)

// EndpointCreationGate is a prerequisite for returning endpoint creation success
// to the CNI caller. Implementations must honor caller cancellation and return
// an error when a required prerequisite cannot be verified. Passing a gate alone
// does not establish that the endpoint is protected.
type EndpointCreationGate interface {
	WaitForEndpoint(context.Context, *endpoint.Endpoint) error
}

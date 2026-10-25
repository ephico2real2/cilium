// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package membership

import (
	"context"

	"github.com/cilium/cilium/pkg/endpoint"
)

// EndpointRevalidator rebuilds strict admission evidence for an endpoint that
// Cilium restored from disk or whose namespace has just become enrolled.
type EndpointRevalidator interface {
	ShouldRevalidate(context.Context, *endpoint.Endpoint, bool) (bool, error)
	RevalidateEndpoint(context.Context, *endpoint.Endpoint) error
}

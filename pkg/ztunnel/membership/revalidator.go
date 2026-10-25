// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package membership

import (
	"context"

	"github.com/cilium/cilium/pkg/endpoint"
)

// EndpointRevalidator rebuilds strict admission evidence for an endpoint that
// Cilium restored from disk or whose namespace has just become enrolled.
// VerifyEndpoint only checks that the existing evidence is still current; it
// changes nothing. RevalidateEndpoint runs full admission, which quarantines
// the endpoint and starts a new capture generation.
// RestrictRestoredEndpoint runs before ZDS can carry an ADD: it quarantines a
// restored endpoint that needs re-admission and reports whether it does.
type EndpointRevalidator interface {
	ShouldRevalidate(context.Context, *endpoint.Endpoint, bool) (bool, error)
	RestrictRestoredEndpoint(context.Context, *endpoint.Endpoint, bool) (bool, error)
	VerifyEndpoint(context.Context, *endpoint.Endpoint) error
	RevalidateEndpoint(context.Context, *endpoint.Endpoint) error
}

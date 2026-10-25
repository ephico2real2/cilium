// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package membership

import (
	"context"

	"github.com/cilium/cilium/pkg/endpoint"
)

// Stages that name why a caller ensures an endpoint is admitted. They appear
// as the stage of every admission log line the call produces.
const (
	StageRestoredReadmission = "restored-readmission"
	StageNamespaceEnrollment = "namespace-enrollment"
	StageSourceVerification  = "source-verification"
)

// EndpointRevalidator rebuilds strict admission evidence for an endpoint that
// Cilium restored from disk or whose namespace has just become enrolled.
// EnsureEndpoint verifies the endpoint's current evidence and runs full
// admission, which quarantines the endpoint and starts a new capture
// generation, only when that evidence is no longer current. It is the only
// way to re-admit: the check and the admission run as one step per endpoint,
// so concurrent callers never repeat or revoke each other's admission.
// RestrictRestoredEndpoint runs before ZDS can carry an ADD: it quarantines a
// restored endpoint that needs re-admission and reports whether it does.
type EndpointRevalidator interface {
	ShouldRevalidate(context.Context, *endpoint.Endpoint, bool) (bool, error)
	RestrictRestoredEndpoint(context.Context, *endpoint.Endpoint, bool) (bool, error)
	EnsureEndpoint(ctx context.Context, ep *endpoint.Endpoint, stage string) error
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"errors"
	"fmt"
)

var (
	errInvalidWorkloadData   = errors.New("invalid workload data")
	errInvalidDiscoveryState = errors.New("invalid discovery state")
	errEndpointSourceClosed  = errors.New("endpoint event source closed")
)

func wrapValidationError(cause error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", cause, fmt.Sprintf(format, args...))
}

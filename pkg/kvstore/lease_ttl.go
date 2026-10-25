// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/time"
)

// ErrLeaseTTLWriteConflict means the writer lock or the persistent server-side
// write head changed. The caller must not retry the same stale operation.
var ErrLeaseTTLWriteConflict = errors.New("short lease write head or lock changed")

// The unleased head survives source key expiry. It is deliberately outside the
// agents watch prefix and must never be garbage-collected while a writer RPC
// from any prior ownership epoch can remain in flight.
func leaseTTLWriteHead(key string) string {
	return JoinKey(LeaseTTLWriteHeadsPrefix, fmt.Sprintf("%x", sha256.Sum256([]byte(key))))
}

// LeaseTTLWriter writes one value with an explicitly bounded key lease while
// requiring the caller to own a distributed lock. A persistent write head
// prevents an ambiguous older transaction from overwriting a newer completed
// restrictive publication, even when the leased data key later expires. It is an optional extension
// because ordinary KVStore records must continue using the configured global
// lease behavior.
type LeaseTTLWriter interface {
	UpdateWithLeaseTTLIfLocked(ctx context.Context, key string, value []byte, ttl time.Duration, lock KVLocker) error
}

// LeaseTTLWriterFor exposes this optional capability only when the selected
// backend actually implements it. The client wrapper must not make an
// unsupported backend appear capable merely because it can return an error at
// write time.
func LeaseTTLWriterFor(client Client) (LeaseTTLWriter, bool) {
	if client == nil {
		return nil, false
	}
	if wrapper, ok := client.(*clientImpl); ok {
		writer, supported := wrapper.BackendOperations.(LeaseTTLWriter)
		return writer, supported
	}
	writer, supported := client.(LeaseTTLWriter)
	return writer, supported
}

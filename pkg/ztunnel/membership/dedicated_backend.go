// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package membership

import (
	"context"
	"log/slog"

	"google.golang.org/grpc"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/kvstore"
)

// OpenDedicatedBackend opens a dedicated etcd connection to this cluster's
// source membership records, for the publisher or the same-cluster reader. It
// is separate from the agent's global kvstore, which stays disabled, so it
// does not switch on node, ipcache or identity kvstore synchronization. The
// configured credentials hold only the ztunnel membership writer role, which
// reads and writes the membership prefix and nothing else.
func OpenDedicatedBackend(logger *slog.Logger, configPath string, resolver dial.Resolver) func(context.Context) (kvstore.BackendOperations, error) {
	return func(ctx context.Context) (kvstore.BackendOperations, error) {
		opts := kvstore.ExtraOptions{
			// The writer role grants no init-lock key: the membership lock
			// and the lease-fenced writes are themselves quorum operations.
			NoLockQuorumCheck:      true,
			NoEndpointStatusChecks: true,
			LeaseTTL:               defaults.KVstoreLeaseTTL,
			ClusterName:            "ztunnel-membership",
		}
		if resolver != nil {
			// Resolve the in-cluster service without depending on cluster DNS.
			opts.DialOption = []grpc.DialOption{grpc.WithContextDialer(dial.NewContextDialer(logger, resolver))}
		}
		backend, errCh := kvstore.NewClient(ctx, logger, kvstore.EtcdBackendName,
			map[string]string{kvstore.EtcdOptionConfig: configPath}, opts)
		select {
		case err := <-errCh:
			if err != nil {
				if backend != nil {
					backend.Close()
				}
				return nil, err
			}
			return backend, nil
		case <-ctx.Done():
			if backend != nil {
				backend.Close()
			}
			return nil, ctx.Err()
		}
	}
}

# Authorization resource lifecycle

The local ztunnel ADS service now serves `istio.security.Authorization` through Cilium's existing delta engine (`pkg/envoy/xds`). The address discovery handler remains separate. Each type owns its nonce/ACK state; both handlers serialize gRPC writes on the shared connection. A protocol or send error terminates the stream and cancels its watches. This is a transport implementation, not a Cilium policy compiler or a packet admission gate.

`AuthorizationPolicies.Apply` is the typed Hive interface for a future effective-policy compiler. A batch atomically upserts and removes resources, validates namespace/name keys against payloads and known scope/action enums, and rejects ambiguous upsert/remove overlap. Protobufs are cloned and checked for wire-encoding errors before publication. Identical updates do not advance versions. The validation is structural; supported Cilium policy semantics must be enforced by the future compiler before calling this interface.

The cache is agent-local and in memory. Versions are not durable admission epochs. On reconnect the delta engine resends current subscribed resources and explicitly removes stale names supplied in `initial_resource_versions`, regardless of old version numbers. Named/wildcard subscriptions, combined ACK/subscription requests, one outstanding response per type and client, NACK without advancement, and cache-change notifications use the shared delta implementation. Independent clients observe the same desired state without sharing ACK state. There is no disk or KVStoreMesh persistence requirement for this cache; the eventual policy producer must reconstruct desired resources before claiming readiness.

The schema is pinned in [the protocol source record](../pb/security/SOURCE.md). The selected proxy's [client node ID](https://github.com/cilium/ztunnel/blob/5bb9cf256b10a209ae9bc0624ddfbf27dbc439de/src/xds/client.rs#L336) uses the format accepted by the shared delta engine. This client-provided node ID is a protocol identifier, not an authenticated cluster or workload identity. Its [policy store](https://github.com/cilium/ztunnel/blob/5bb9cf256b10a209ae9bc0624ddfbf27dbc439de/src/state/policy.rs#L24) indexes resource keys and removes their associated namespace/global entries on deletion. Namespace/name keys must agree with workload policy references. Future incarnation/cluster binding must be designed into those references and generated names; this cache does not invent it.

`cilium_ztunnel_xds_authorization_events_total{status}` reports protocol ACK, NACK, cancellation and send-failure events. An ACK means the proxy accepted an xDS response; it never means that a namespace is Protected. Address enrollment failures remain in their own metric. There is no acknowledgment-derived readiness API.

The Go tests exercise the actual ADS handler through in-memory gRPC, including update/delete, immutable batches, reconnect cleanup, simultaneous subscriptions and acknowledgments, independent streams, NACK/stale ACK, malformed acknowledgment rejection and separation from Address ACKs. They use fake policy inputs; no effective Cilium policy translation or Rust engine decision is being asserted. Run them on Linux (the package imports Linux datapath dependencies):

```sh
go test -race -count=1 ./pkg/ztunnel/pb/... ./pkg/ztunnel/xds ./pkg/envoy/xds
```

The existing focused authorization workflow retains JSON test events and exact source/toolchain metadata. It is extended for this slice instead of adding a second overlapping workflow.

No producer is enabled by this patch. Missing policy references can still allow traffic in the selected proxy; persistent fail-closed admission, authenticated remote workload discovery, issuer/cluster binding, effective policy translation, and workload references remain required. The ClusterMesh compatibility guard, Observe-only CMTC schema and Protected status gates are unchanged. Do not deploy an encrypted or Strict profile based on this transport slice.

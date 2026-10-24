# Local authorization ADS lifecycle evidence

Source `42f89f83aa5a03ea80f7a2b8cece56b27f87385a`, [Cilium fork PR #6](https://github.com/ephico2real2/cilium/pull/6). This MacBook ran Go 1.27.1 inside its dedicated Ubuntu ARM64 Colima VM. The Go container is pinned by digest in `source.json`.

All 150 tests/subtests across protocol bindings, ztunnel xDS and the shared Cilium delta engine passed with the race detector. `tests.jsonl` retains every Go test event. Go vet, actionlint and diff checks passed. The xDS package depends on Linux datapath code; direct Darwin compilation was therefore not used as qualification.

The new tests call the actual Go ADS handler over in-memory gRPC. They cover validated atomic/immutable policy batches, versioned updates and deletion, named subscription changes combined with ACKs, NACK without ACK advancement, stale ACKs, stale resource removal on reconnect, concurrent clients with independent outstanding responses, Address/Authorization coexistence and cross-type ACK rejection, node-ID changes and write failure. The shared delta package's existing subscription/nonce regression cases run in the same suite.

This is policy transport evidence using fake policy inputs. It does not validate effective Cilium policy translation, Rust proxy enforcement, authenticated remote identity, admission, workload mTLS or WireGuard/IPsec composition. No policy producer is enabled; the ClusterMesh compatibility guard remains. Protocol ACK counters cannot mark workloads Protected.

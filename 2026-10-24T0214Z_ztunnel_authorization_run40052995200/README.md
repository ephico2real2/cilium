# AMD64 authorization ADS lifecycle CI evidence

[Successful workflow 40052995200](https://github.com/ephico2real2/cilium/actions/runs/40052995200), source `42f89f83aa5a03ea80f7a2b8cece56b27f87385a`, [PR #6](https://github.com/ephico2real2/cilium/pull/6). The existing focused protocol workflow now includes the transport lifecycle and shared delta engine instead of starting a second overlapping workflow.

All 150 tests/subtests passed with the race detector on Linux AMD64, Go 1.27.1. Go vet and exact checksum-pinned protobuf regeneration passed. `tests.jsonl` retains every test event; the other files record the exact checked-out source, compiler and platform. The local Linux ARM64 qualification passed the same 150 tests/subtests.

These tests call the actual Go ADS handler over in-memory gRPC with fake policies. They establish resource lifecycle and protocol behavior, not effective Cilium policy translation, Rust proxy enforcement, remote identity, admission, workload mTLS or layered encryption. No policy producer or protected profile is enabled. The compatibility guard remains.

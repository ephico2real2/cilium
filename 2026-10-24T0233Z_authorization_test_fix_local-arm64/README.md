# Local authorization test corrections

150 race-enabled tests/subtests passed across the protocol, ztunnel xDS and shared delta packages. The pinned golangci-lint 2.15.0 and go vet passed in the local Ubuntu ARM64 VM. Source is mounted read-only in the pinned Go container.

The only changes after the published runtime source are test imports and test context creation; test-only.diff records them. This is transport lifecycle evidence. Effective-policy production, remote identity, packet admission and workload mTLS are not established.

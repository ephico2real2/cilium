# Focused fork CI

On 2026-10-23 the repository owner approved disabling the twelve inherited suites below on `ephico2real2/cilium` and cancelling only their runs triggered by workflow-only merge `ae098cf0d9eda61c18fafb36ab0e1216fa058adc`. This is a GitHub repository workflow setting, not a deletion or change to upstream test definitions.

Keep enabled: `cmtc-ztunnel-protocol.yaml`, `cmtc-development-images.yaml`, `hubble-l7-dashboard-evidence.yaml`, and the Go/build/lint/source checks. CMTC's own repository retains its single `ci.yaml` for unit tests and the deployed two-cluster lab.

Draft PRs skip the automatic Hubble native-build job. `workflow_dispatch` remains available on the draft branch, so a source-pinned GHCR qualification can finish and its evidence can be attached before marking the PR ready. Subsequent changes to a ready PR run the normal regression workflow. This avoids launching a second image build when explicitly testing an already-published bundle.

| Disabled inherited suite | Workflow file |
| --- | --- |
| Gateway API | `conformance-gateway-api.yaml` |
| Hubble CLI integration | `hubble-cli-integration-test.yaml` |
| K8s network E2E | `k8s-kind-network-e2e.yaml` |
| Embedded Envoy | `conformance-kind-proxy-embedded.yaml` |
| Multi-pool IPAM | `conformance-multi-pool.yaml` |
| Delegated IPAM | `conformance-delegated-ipam.yaml` |
| Ingress | `conformance-ingress.yaml` |
| IPv6 installation | `tests-smoke-ipv6.yaml` |
| Cyclonus | `conformance-k8s-network-policies.yaml` |
| K8s policy E2E | `k8s-kind-network-policies-e2e.yaml` |
| Smoke conformance | `tests-smoke-conformance.yaml` |
| Runtime | `conformance-runtime.yaml` |

These upstream suites automatically fan out on fork main merges and consume runner capacity; they do not replace the GHCR, real Gateway load, or CMTC two-cluster qualification. Keep the relevant source checks, and configure/re-enable an inherited suite when its broader coverage is required. For example:

```sh
gh workflow enable conformance-gateway-api.yaml -R ephico2real2/cilium
```

The upstream Quay OIDC publisher is also guarded to run only in `cilium/cilium`, since its broker does not trust fork identities. The fork publishes versioned images to GHCR instead. Historical version-specific image workflows (`v1.18`, `v1.19`, `v1.20`) share the display name “Image CI Build”; those names alone do not identify duplicate main runs.

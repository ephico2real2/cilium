# Namespace incarnation metadata: local validation

This increment preserves Kubernetes Namespace UID through the common namespace reflector and ztunnel enrollment projection. Name remains the lookup key. It adds no authorization, restore release, cryptographic provenance or protection status; the existing name-based reconciler/startup behavior and ClusterMesh compatibility guard remain unchanged. Empty UID means unknown metadata, not validated identity. A future security consumer must validate the exact Namespace/Pod/sandbox incarnation separately.

Base: `8b01a7c95440f6db398a87bdac2136d36711d23f`. Canonical upstream `main` fetched at `fe561573e0a8adc43bacbcc70bda0c9e01d6676d`; the base feature branch is34 ahead/zero behind. Personal fork origin and canonical upstream remain configured.

Full affected ARM64 Podman race tests ran for `pkg/k8s/tables`, all `pkg/ztunnel/...`, `operator/pkg/ztunnel/reconciler`, `pkg/endpoint/metadata`, and `pkg/ipam/metadata`. The first run passed208 top-level/239 subtests but failed the new namespace recreation fixture: it exported the table before the asynchronous informer delivered the replacement. Adding a state-table comparison barrier fixes the synchronization. Ten repeated race runs of the actual namespace delete/add script pass; package-qualified combined coverage is209 top-level/240 subtests, zero skipped. Affected-package vet passes.

Required lint initially found one formatting error in the new UID field declaration. It was formatted and the complete affected lint run reports `0 issues.`. No lint categories were disabled.

The real fake-client reflector fixture deletes UID A and adds UID B under the same name; `k8s/update` deliberately preserves immutable UIDs and cannot model recreation. Tests also verify UID on derived insert/delete records, unknown/empty metadata, cloning/status updates and same-name statedb replacement. Table columns and current enrollment behavior stay unchanged.

Diagnostics remain in `/private/tmp/cmtc-namespace-uid-proposal/`: `qualification-first.log`, `qualification-namespace-retry.log`, `lint-first.log`, `lint-final.log`. This is source qualification. Exact-image build, live table inspection and runtime regression remain pending. Do not infer strict restore, authentication, effective policy or mTLS from these tests. CI and publishing remain deferred.

# CMTC local recovery checkpoint

This commit preserves the unfinished isolated implementation at the user's explicit request. It is a recovery commit, not a release or proof of end-to-end workload mTLS.

Claude Code Opus5.5High session `c03d57db-e2bf-4848-ab73-3f2696a27d2f` stopped on its monthly spend limit. Preserve the original mixed Codex/Cursor/Claude work and test failures. Primary Codex now owns continuation. Cursor Grok4.7ExtraHigh reviews the node-name port without source edits.

Use edit → run against cmtc-a/cmtc-b → test traffic, failures and recovery → package the verified change. Preserve the native ClusterMesh path, signer state, security guards and owned lab resources. CI and publication remain deferred. No ztunnel proxy is running in either cluster at this checkpoint.

C1 source checks passed57 top-level/180 total race tests,21 pre-existing integration skips,vet and48 kernel subtests. Subsequent C2 edits are partial and UNTESTED. Native Node-name mapping, first-packet/restore/endpoint-ID safety and full mTLS integration remain open. A stray dpgen output is retained as docs/cmtc/recovery/util_generated.go.txt, outside the root Go package.

Original base HEAD: `07722a595ae00e36489e33c60a1319be6b310233`.

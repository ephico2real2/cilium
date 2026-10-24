# CMTC development images

This fork publishes three matching binaries from an exact source commit: Cilium agent, generic operator and ClusterMesh API server. The chart must come from that same commit. This is a development build; the ztunnel compatibility guard remains in place.

All components use the existing **public** GHCR package `ghcr.io/ephico2real2/cilium-dev`, with separate component tags. A source tag has the form `sha-<40-character commit>-agent` (or `operator-generic`, `clustermesh-apiserver`); the native build tags append `-arm64` or `-amd64`. The bundle artifact records immutable multi-architecture digests. Consumers must pin those digests rather than `latest`.

## Local build and push

Select the intended Docker context first. Authenticate without printing your token, then build from a committed, clean source checkout:

```sh
gh auth token | docker login ghcr.io -u ephico2real2 --password-stdin
CILIUM_TARGET_PLATFORM=linux/arm64 bash contrib/cmtc-images/build.sh /path/to/cilium /tmp/cilium-images
```

On Intel/Linux, use `linux/amd64`. The script uses Cilium's native Dockerfiles and produces a native digest lock and Buildx metadata. It never publishes to upstream Quay. Keep credentials outside source/evidence directories.

Run the fork-only `CMTC fork development images` workflow with the same full `source_sha`. Its native Ubuntu AMD64/ARM64 jobs reuse complete locally published sets after checking source/platform labels, or build missing sets, verify the agent binary version, and publish a two-platform bundle. It authenticates with the run's `GITHUB_TOKEN` and `packages: write`; no personal SSH key or token is installed in CI.

```sh
gh workflow run cmtc-development-images.yaml -R ephico2real2/cilium -f source_sha=<full-fork-commit> -f local_arm64=true
```

Download `cilium-image-bundle/images.lock.json` from the successful run. In CMTC, use `CILIUM_IMAGE_LOCK=/absolute/path/images.lock.json make lab-up`, or deliberately update its checked-in lock to advance the default development version. The lab fetches the exact chart, renders explicit image overrides and verifies all deployed component digests and agent binary versions. Retain the publisher and deployed CI links when updating a pin.

The Hubble dashboard regression workflow also accepts `image_lock_url`. Set it to an immutable raw CMTC lock URL and pass its matching `source_sha`; the job skips native image compilation, verifies the source, deploys the GHCR digest references with the matching chart, then runs the existing external Gateway, pod Gateway and direct-pod load streams before the Grafana browser assertions. The native build path remains available when the input is omitted.

See [FORK_CI.md](FORK_CI.md) for the owner-approved workflow scope and how to re-enable broader upstream suites.

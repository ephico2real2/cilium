#!/usr/bin/env bash
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0
# Build on the selected local Docker engine, then push immutable source/role/arch tags.
set -euo pipefail
source_dir=$(cd "${1:?source checkout required}" && pwd)
out=${2:?output directory required}
mkdir -p "$out"
out=$(cd "$out" && pwd)
sha=$(git -C "$source_dir" rev-parse HEAD)
[ -z "$(git -C "$source_dir" status --porcelain --untracked-files=no)" ] || { echo 'Commit tracked source changes before publishing' >&2; exit 1; }
repository=${CILIUM_IMAGE_REPOSITORY:-ghcr.io/ephico2real2/cilium-dev}
platform=${CILIUM_TARGET_PLATFORM:-linux/$(docker info --format '{{.Architecture}}')}
platform=${platform/aarch64/arm64}
platform=${platform/x86_64/amd64}
case "$platform" in linux/amd64|linux/arm64) ;; *) echo "Unsupported platform: $platform" >&2; exit 1;; esac
arch=${platform#linux/}
make -C "$source_dir" GIT_VERSION images/cilium/Dockerfile.dockerignore images/operator/Dockerfile.dockerignore images/clustermesh-apiserver/Dockerfile.dockerignore
for role in agent operator-generic clustermesh-apiserver; do
  directory=$role
  args=()
  case "$role" in
    agent) directory=cilium;;
    operator-generic) directory=operator; args+=(--build-arg OPERATOR_VARIANT=operator-generic);;
  esac
  tag="$repository:sha-$sha-$role-$arch"
  if [ "${GITHUB_ACTIONS:-false}" = true ]; then
    args+=(--cache-from "type=gha,scope=cmtc-$role-$arch" --cache-to "type=gha,scope=cmtc-$role-$arch,mode=max")
  fi
  docker buildx build --platform "$platform" --target release \
    --file "$source_dir/images/$directory/Dockerfile" \
    --label "org.opencontainers.image.source=https://github.com/ephico2real2/cilium" \
    --label "org.opencontainers.image.revision=$sha" \
    --tag "$tag" --metadata-file "$out/$role.json" \
    --push "${args[@]}" "$source_dir"
done
python3 - "$out" "$sha" "$repository" "$platform" <<'PY'
import json,pathlib,sys
out,sha,repository,platform=sys.argv[1:]
out=pathlib.Path(out)
images={}
for role in ('agent','operator-generic','clustermesh-apiserver'):
    metadata=json.loads((out/(role+'.json')).read_text())
    digest=metadata['containerimage.digest']
    images[role]={'image':repository+'@'+digest,'tag':f'{repository}:sha-{sha}-{role}-{platform.split("/")[1]}'}
lock={'source_sha':sha,'repository':repository,'platforms':[platform],'images':images}
(out/'images.lock.json').write_text(json.dumps(lock,indent=2)+'\n')
print(json.dumps(lock,indent=2))
PY

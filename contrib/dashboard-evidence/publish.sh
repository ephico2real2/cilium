#!/usr/bin/env bash
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# Per-run ci-captures folders and race-safe retries, adapted from demo55-ci.
# Only screenshots and allowlisted dashboard evidence are published; see SOURCE.md.
set -euo pipefail
out=${CAPTURE_OUT:-artifacts/screenshots}
branch=${CAPTURE_BRANCH:-ci-captures}
case "$out" in artifacts/*) ;; *) echo 'Publication must read artifacts/' >&2;exit 1;; esac
case "$out" in *..*) exit 1;; esac
shopt -s nullglob
pngs=("$out"/*.png)
if [ "${#pngs[@]}" = 0 ]; then
  echo 'No browser captures to publish' | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
  exit 0
fi
: "${GITHUB_REPOSITORY:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}" "${GH_TOKEN:?}"
git check-ref-format "refs/heads/$branch"
remote="https://github.com/$GITHUB_REPOSITORY.git"
dir="$(date -u +%Y-%m-%dT%H%MZ)_hubble_l7_run${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}_${GITHUB_JOB:-lab}"
mkdir -p .tmp
stage=$(mktemp -d "$PWD/.tmp/capture-publish.XXXXXX")
trap 'rm -rf "$stage"' EXIT
# The runner uses its ephemeral workflow token. Human SSH keys are never copied to CI.
# The helper writes credentials only into Git's private credential protocol.
# The helper expands the ephemeral token only when Git invokes it.
# shellcheck disable=SC2016
auth=(-c credential.helper= -c 'credential.helper=!f() { echo "username=x-access-token"; echo "password=$GH_TOKEN"; }; f')
export GIT_TERMINAL_PROMPT=0
git init -q "$stage"
git -C "$stage" config user.name ephico2real2
git -C "$stage" config user.email 123043136+ephico2real2@users.noreply.github.com
git -C "$stage" remote add origin "$remote"
pushed=no
for attempt in 1 2 3 4 5; do
  exists=$(git "${auth[@]}" ls-remote --heads "$remote" "refs/heads/$branch")
  if [ -n "$exists" ]; then
    git -C "$stage" "${auth[@]}" fetch -q --depth=1 origin "$branch"
    git -C "$stage" checkout -q --detach FETCH_HEAD
  else
    git -C "$stage" checkout -q --orphan "captures-$attempt"
  fi
  mkdir -p "$stage/$dir"
  cp "${pngs[@]}" "$stage/$dir/"
  for name in walk.log walk-results.json results.json live-results.json source.json before.log after.log; do
    if [ -f "$out/$name" ]; then cp "$out/$name" "$stage/$dir/"; fi
  done
  git -C "$stage" add -- "$dir"
  if ! git -C "$stage" diff --cached --quiet; then git -C "$stage" commit -qm "captures: $dir"; fi
  if git -C "$stage" "${auth[@]}" push -q origin "HEAD:refs/heads/$branch"; then pushed=yes;break;fi
  echo "Capture publication raced another run; retry $attempt/5 on its new tip" >&2
  sleep $((attempt * 2 + RANDOM % 4))
done
[ "$pushed" = yes ] || { echo 'Capture publication failed after five attempts' >&2;exit 1; }
revision=$(git -C "$stage" rev-parse HEAD)
python3 - "$out" "$GITHUB_REPOSITORY" "$revision" "$dir" "${GITHUB_STEP_SUMMARY:-/dev/null}" <<'PY'
import json,pathlib,sys
out,repo,revision,directory,summary=sys.argv[1:]
root=pathlib.Path(out)
url=f'https://github.com/{repo}/tree/{revision}/{directory}'
lines=[f'## Browser captures — [{directory}]({url})','',
       'Real two-node Cilium Gateway and direct-pod HTTP load. Browser/API assertions are enforced after publication. The artifact contains measured load results and source/image/placement proof. No workload-mTLS claim.','']
log=root/'walk.log'
if log.exists():
    for line in log.read_text().splitlines():
        if not line.strip(): continue
        verdict='❌' if 'FAILED' in line else '⏸️' if 'BLOCKED' in line else '✅' if 'expectations met' in line else '·'
        safe=line.replace('`',"'")
        lines.append(f'- {verdict} `{safe}`')
for p in sorted(root.glob('*.png')):
    lines += ['',f'### {p.stem}','',f'![{p.stem}](https://raw.githubusercontent.com/{repo}/{revision}/{directory}/{p.name})']
with open(summary,'a') as f: f.write('\n'.join(lines)+'\n')
(root/'publication.json').write_text(json.dumps({'repository':repo,'commit':revision,'directory':directory,'url':url},indent=2)+'\n')
print(f'Captures published: {url}')
PY

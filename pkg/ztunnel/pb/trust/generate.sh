#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(protoc --version)" == 'libprotoc 36.2' ]]
[[ "$(protoc-gen-go --version)" == 'protoc-gen-go v1.36.12' ]]
protoc -I . --plugin="$(command -v protoc-gen-go)" --go_out=paths=source_relative:. trust/issuer_profile.proto

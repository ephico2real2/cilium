#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
set -euo pipefail
cd "$(dirname "$0")/.."
includes=(-I .)
if [ -n "${PROTOC_INCLUDE_DIR:-}" ]; then includes+=(-I "$PROTOC_INCLUDE_DIR"); fi
protoc "${includes[@]}" \
  --plugin="$(command -v protoc-gen-go)" \
  --plugin="$(command -v protoc-gen-go-json)" \
  --plugin="$(command -v protoc-gen-doc)" \
  --go_out=paths=source_relative:. \
  --go-json_out=orig_name=true,paths=source_relative:. \
  --doc_out=. --doc_opt=markdown,README.md,source_relative \
  security/authorization_ztunnel.proto
python3 security/normalize-docs.py

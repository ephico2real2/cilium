#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
"""Normalize whitespace emitted by the pinned documentation plugin."""
from pathlib import Path

path = Path(__file__).with_name("README.md")
path.write_text("\n".join(line.rstrip() for line in path.read_text().splitlines()).rstrip() + "\n")

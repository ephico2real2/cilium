#!/usr/bin/env python3
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0
"""Select digest-pinned published images without changing the tested source chart."""
import json
import os
import re
import subprocess
from pathlib import Path

lock = json.loads(Path('artifacts/published-images.lock.json').read_text())
assert lock['source_sha'] == os.environ['DASHBOARD_SOURCE_SHA'], 'Image and chart source differ'
values = {}
images = []
for role, key in [('agent', 'image'), ('operator-generic', 'operator')]:
    image = lock['images'][role]['image']
    assert re.fullmatch(r'ghcr\.io/ephico2real2/[a-z0-9/_.-]+@sha256:[0-9a-f]{64}', image), image
    subprocess.run(['docker', 'pull', image], check=True)
    settings = {'override': image, 'pullPolicy': 'IfNotPresent'}
    values[key] = settings if role == 'agent' else {'image': settings}
    images.append(image)
Path('.tmp').mkdir(exist_ok=True)
Path('.tmp/published-values.json').write_text(json.dumps(values, indent=2)+'\n')
with Path('artifacts/live/built-images.json').open('w') as output:
    subprocess.run(['docker', 'image', 'inspect', *images], stdout=output, check=True)
print('Published fork images selected; kubelet will pull their public digests into kind')

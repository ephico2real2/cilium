# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# Prepared Ubuntu browser image, reused from the CMTC/PoC capture pattern.
FROM mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27
WORKDIR /opt/cmtc-capture
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && node -e "const {chromium}=require('playwright');(async()=>{const b=await chromium.launch();await b.close()})().catch(e=>{console.error(e);process.exit(1)})"
COPY walk.cjs walk-smoke.cjs ./
RUN node walk-smoke.cjs
WORKDIR /workspace
ENTRYPOINT ["node", "/opt/cmtc-capture/walk.cjs"]

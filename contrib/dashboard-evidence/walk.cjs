// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

// Adapted from ephico2real2/cilium-implementation-poc at 22fb6e14c0cca8c78af1f072d1e89ebaea6a916b.
// See SOURCE.md for provenance and CMTC-specific adaptations.
// walk.js — drive a browser through pages named in a spec (YAML or JSON) and leave a PNG and an evidence line per page,
// with the page's EXPECTATIONS measured: a page that fails one is a failed page, and the walk exits 2 — the captures
// are a test, not only pictures (the operator, 2026-09-15: "a test that shows that all the fields in the policy verdict
// dashboard have data"; "hubble ui show traffic"). The spec is data, so a new endpoint is a new entry, not new code.
// Playwright resolves the lab's *.poc.local names itself from the spec's "resolve" map (Chromium --host-resolver-rules),
// so /etc/hosts is not needed on the runner or the Mac; ${VAR} in the spec expands from the environment.
//
//   S=<out dir> GW=… HUBBLE=… node scripts/capture/walk.js scripts/capture/lab.yaml
//
// spec: viewport {width, height}; resolve {host: "${GW}"}; login {url, user: [sel, value], password: [sel, value],
//       submit: sel}; pages: [ {name, url, settle: true|false, settleSeconds, before: ms, fullPage,
//       actions: [ {click: "visible text, exact"}, {clickSelector: css}, {fill: [sel, value]}, {wait: ms} ],
//       screenshot: true, evidence: panels | text | title,
//       expect: { noDataAllowed: [panel titles that may say "No data", each with its reason in a comment — every
//                                 other panel must show data (evidence: panels)],
//                 text: [strings the page's text must contain (evidence: text)],
//                 panelsMin: n } } ]
//
// Grafana's panel DOM (checked against the deployed CMTC Grafana image in CI): every panel is a
// <section data-testid="data-testid Panel header <title>"> (packages/grafana-ui/…/PanelChrome.tsx); an empty timeseries
// or table renders PanelDataErrorView's message "No data" (public/app/features/panel/components/PanelDataErrorView.tsx),
// an empty stat renders a value whose text is "No data" (packages/grafana-data/src/field/fieldDisplay.ts,
// createNoValuesFieldDisplay) unless the panel configures noValue — so "empty" is any leaf element in the section whose
// text is exactly "No data". Panels below the fold are lazy — not queried until scrolled to — so a "panels" page is
// scrolled through to the bottom before it is read.
const { chromium } = require('playwright'); const fs = require('fs');
const S = process.env.S || '.';
const variables = {...process.env, ...JSON.parse(process.env.CMTC_WALK_ENV_JSON || '{}')};
const expand = s => String(s).replace(/\$\{(\w+)\}/g, (_, k) => variables[k] ?? '');
const specFile = process.argv[2] || 'scripts/capture/lab.yaml'; const raw = expand(fs.readFileSync(specFile, 'utf8'));
const spec = /\.ya?ml$/.test(specFile) ? require('js-yaml').load(raw) : JSON.parse(raw);
if (!Array.isArray(spec.pages) || !spec.pages.length) throw Error('The walk needs at least one page');
for (const page of spec.pages) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(page.name)) throw Error(`Invalid capture name: ${page.name}`);
}
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
async function settled(p, seconds) { // Grafana: no panel still loading (gotcha #66's lesson), then the caller's settle
  for (let i = 0; i < seconds; i++) {
    const loading = await p.evaluate(() => document.querySelectorAll('[aria-label="Panel loading bar"], [data-testid="Panel loading bar"], .panel-loading').length);
    if (loading === 0 && i > 2) return i; await p.waitForTimeout(1000);
  }
  return seconds;
}
async function scrollThrough(p) { // the dashboard's own scroll container, a viewport at a time, so lazy panels load and query
  const steps = await p.evaluate(async () => {
    const sec = document.querySelector('section[data-testid^="data-testid Panel header "]'); if (!sec) return 0;
    let el = sec.parentElement;
    while (el && el !== document.body && !(el.scrollHeight > el.clientHeight + 4 && /auto|scroll/.test(getComputedStyle(el).overflowY))) el = el.parentElement;
    const box = (el && el !== document.body) ? el : document.scrollingElement;
    let n = 0; for (let y = 0; y < box.scrollHeight; y += box.clientHeight) { box.scrollTop = y; n++; await new Promise(r => setTimeout(r, 1500)); }
    box.scrollTop = 0; return n;
  });
  await p.waitForTimeout(1000); return steps;
}
const readPanels = p => p.evaluate(() => {
  const pre = 'data-testid Panel header '; const secs = Array.from(document.querySelectorAll(`section[data-testid^="${pre}"]`));
  const title = s => s.getAttribute('data-testid').slice(pre.length);
  const empty = secs.filter(s => Array.from(s.querySelectorAll('*')).some(e => e.children.length === 0 && /^No data$/.test((e.innerText || '').trim()))).map(title);
  return { titles: secs.map(title), empty };
});
const evidence = {
  panels: async p => { const r = await readPanels(p); return { line: `panels=${r.titles.length}; "No data"=${r.empty.length}${r.empty.length ? ' [' + r.empty.join(' | ') + ']' : ''}; first: ${r.titles.slice(0, 5).join(' | ')}`, ...r }; },
  text: async p => { const t = await p.evaluate(() => document.body.innerText); return { line: t.split('\n').filter(l => l.trim()).slice(0, 12).join(' | '), text: t }; },
  title: async p => ({ line: `title: ${await p.title()}` }),
};
function check(page, ev) { // the page's expectations against its evidence; the reasons a page fails, in words
  const e = page.expect || {}, why = [];
  if (e.noDataAllowed !== undefined) { const allowed = new Set(e.noDataAllowed || []); const bad = (ev.empty || []).filter(t => !allowed.has(t)); if (bad.length) why.push(`"No data" on ${bad.length} panel(s) not allowed to be empty: ${bad.join(' | ')}`); }
  if (e.panelsMin && (ev.titles || []).length < e.panelsMin) why.push(`${(ev.titles || []).length} panels, expected at least ${e.panelsMin}`);
  for (const s of e.text || []) if (!(ev.text || '').includes(s)) why.push(`text "${s}" not on the page`);
  if (e.prometheusTotal !== undefined || e.prometheusMin !== undefined) {
    const actual = ev.queryEvidence;
    if (!actual) why.push('No real Grafana Prometheus response was captured');
    else {
      if (actual.errors.length) why.push(`Grafana query errors: ${actual.errors.join('; ')}`);
      if (e.prometheusMin !== undefined && actual.total < e.prometheusMin) why.push(`Prometheus total ${actual.total}; expected at least ${e.prometheusMin}`);
      if (e.prometheusTotal !== undefined && Math.abs(actual.total - e.prometheusTotal) > e.prometheusTotal * 0.02) why.push(`Prometheus total ${actual.total}; expected ${e.prometheusTotal} within 2%`);
      if (e.prometheusSeries !== undefined && actual.series.length !== e.prometheusSeries) why.push(`Prometheus series ${actual.series.length}; expected ${e.prometheusSeries}`);
    }
  }
  return why;
}
(async () => {
  const rules = Object.entries(spec.resolve || {}).map(([h, a]) => `MAP ${h} ${a}`).join(', ');
  const b = await chromium.launch({ args: rules ? [`--host-resolver-rules=${rules}`] : [] });
  const ctx = await b.newContext({ ignoreHTTPSErrors: !!spec.ignoreHTTPSErrors, viewport: spec.viewport || { width: 1600, height: 1100 } }); const p = await ctx.newPage();
  if (spec.login) { const l = spec.login; await p.goto(l.url, { waitUntil: 'load', timeout: 60000 }); await p.fill(l.user[0], l.user[1]); await p.fill(l.password[0], l.password[1]); await p.click(l.submit); await p.waitForTimeout(3000); console.log(`login: ${l.url} → ${await p.title()}`); }
  let failures = 0; const results = [];
  for (const page of spec.pages) {
    const observations = [], pending = [];
    const recordQuery = response => {
      if (!response.url().includes('/api/ds/query')) return;
      pending.push((async () => {
        try {
          const request = response.request().postDataJSON();
          const expressions = (request?.queries || []).map(q => q.expr || '').filter(q => q.includes('hubble_http_requests_total'));
          if (!expressions.length) return;
          const body = await response.json(), series = [];
          for (const result of Object.values(body.results || {})) for (const frame of result.frames || []) {
            for (let i = 0; i < (frame.schema?.fields || []).length; i++) {
              const field = frame.schema.fields[i];
              if (field.type !== 'number') continue;
              const values = (frame.data?.values?.[i] || []).filter(v => typeof v === 'number' && Number.isFinite(v));
              if (values.length) series.push({labels:field.labels || {},value:values.at(-1)});
            }
          }
          const errors = Object.values(body.results || {}).map(r => r.error).filter(Boolean);
          if (!response.ok()) errors.push(`HTTP ${response.status()}`);
          observations.push({expressions,series,errors,total:series.reduce((sum,s) => sum+s.value,0)});
        } catch {}
      })());
    };
    p.on('response', recordQuery);
    try {
      await p.goto(page.url, { waitUntil: 'load', timeout: 60000 });
      let waited = page.settle === false ? 0 : await settled(p, page.settleSeconds || 90);
      await p.waitForTimeout(page.before || 5000);
      for (const a of page.actions || []) {
        // "click" is visible text, exact; "clickSelector" is CSS. (A heuristic that guessed "bank" was a CSS tag and
        // "cf2cnp-lab30" was text cost one capture in run 34905753996 — no guessing.)
        if (a.click) await p.getByText(new RegExp('^' + esc(a.click) + '$')).filter({ visible: true }).first().click({ timeout: a.timeout || 8000 });
        if (a.clickSelector) await p.locator(a.clickSelector).first().click({ timeout: a.timeout || 8000 });
        if (a.fill) await p.fill(a.fill[0], a.fill[1]);
        if (a.wait) await p.waitForTimeout(a.wait);
      }
      if ((page.evidence || 'title') === 'panels') { const n = await scrollThrough(p); waited += page.settle === false ? 0 : await settled(p, 60); if (n > 1) console.log(`${page.name}: scrolled ${n} screens for the lazy panels`); }
      if (page.screenshot !== false) await p.screenshot({ path: `${S}/${page.name}.png`, fullPage: !!page.fullPage });
      const ev = await (evidence[page.evidence || 'title'])(p);
      await Promise.all(pending);
      ev.queryEvidence = observations.at(-1) || null;
      if (ev.queryEvidence) ev.line += `; browser Prometheus total=${ev.queryEvidence.total}, series=${ev.queryEvidence.series.length}`;
      const why = check(page, ev);
      const blocked = page.blockedSignalsOnNoData ? (ev.empty || []) : [];
      results.push({name:page.name,render:why.length?'failed':'passed',featureEvidence:why.length?'failed':blocked.length?'blocked':'passed',blockedSignals:blocked,failures:why,queryEvidence:ev.queryEvidence});
      if (why.length) { failures++; console.log(`${page.name}: settled ${waited}s; ${ev.line}`); console.log(`${page.name}: FAILED — ${why.join('; ')}`); }
      else if (blocked.length) console.log(`${page.name}: settled ${waited}s; ${ev.line} — render passed; feature evidence BLOCKED: ${blocked.join(' | ')}`);
      else console.log(`${page.name}: settled ${waited}s; ${ev.line}${page.expect ? ' — expectations met' : ''}`);
    } catch (e) { failures++; results.push({name:page.name,render:'failed',featureEvidence:'failed',error:e.message.split('\n')[0]}); console.log(`${page.name}: FAILED — ${e.message.split('\n')[0]}`); try { await p.screenshot({ path: `${S}/${page.name}-failed.png` }); } catch {} }
    finally { p.off('response', recordQuery); }
  }
  await b.close(); fs.writeFileSync(`${S}/walk-results.json`, JSON.stringify({pages:results},null,2)+'\n'); if (failures) { console.log(`${failures} page(s) failed`); process.exit(2); }
})().catch(e => { console.error('ERR', e.message); process.exit(1); });

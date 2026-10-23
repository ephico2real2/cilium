#!/usr/bin/env python3
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

"""Synthetic counters served to real Prometheus; no application traffic."""
import argparse
import os
import json
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import subprocess

RELATIVE = 'install/kubernetes/cilium/files/hubble/dashboards/hubble-l7-http-metrics-by-workload.json'
BASE = os.environ.get('DASHBOARD_BASE_SHA', '3b6e980b3d4eaa5be4532602ccb2bd54d8540dc4')
SOURCE = os.environ.get('DASHBOARD_SOURCE_SHA', 'e00be3729bf71334a500b5202a8e1136177697b3')

def walk(items):
    for item in items:
        yield item
        yield from walk(item.get('panels', []))

def prepare(source, out):
    before = json.loads(subprocess.check_output(['git', 'show', f'{BASE}:{RELATIVE}'], cwd=source))
    after = json.loads((source / RELATIVE).read_text())
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip() == SOURCE
    before['uid'] = 'baseline-hubble-l7-all'
    before['title'] += ' (baseline)'
    for name, data in [('before', before), ('after', after)]:
        p = out / 'grafana/dashboards' / f'{name}.json'
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data))
    datasource = {'apiVersion': 1, 'datasources': [{'name': 'Fixture Prometheus', 'uid': 'fixture-prometheus', 'type': 'prometheus', 'access': 'proxy', 'url': 'http://127.0.0.1:9090', 'isDefault': True, 'jsonData': {'timeInterval': '1s'}}]}
    providers = {'apiVersion': 1, 'providers': [{'name': 'fixture', 'orgId': 1, 'type': 'file', 'options': {'path': '/var/lib/grafana/dashboards'}}]}
    for name, data in [('datasources/fixture.yaml', datasource), ('dashboards/fixture.yaml', providers)]:
        p = out / 'grafana/provisioning' / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data))
    (out / 'prometheus.json').write_text(json.dumps({'global': {'scrape_interval': '1s', 'scrape_timeout': '800ms', 'evaluation_interval': '1s'}, 'scrape_configs': [{'job_name': 'synthetic-fixture', 'static_configs': [{'targets': ['127.0.0.1:18080']}]}]}))
    cases = [('before-all-destination', before['uid'], 'All', 'destination', 50, 1), ('after-all-destination', after['uid'], 'All', 'destination', 550, 1), ('before-all-source', before['uid'], 'All', 'source', 50, 1), ('after-all-source', after['uid'], 'All', 'source', 550, 2), ('after-selected-source', after['uid'], 'selected', 'destination', 50, 1)]
    pages = [{'name': '00-synthetic-fixture', 'url': 'http://127.0.0.1:18080/', 'evidence': 'text', 'settle': False, 'expect': {'text': ['SYNTHETIC', '500', '50', 'No application traffic']}}]
    for name, uid, selection, group, total, count in cases:
        panel = next(p for p in walk(after['panels']) if any(t.get('expr', '').startswith('round(sum(rate(hubble_http_requests_total') and f'by (cluster, {group}_namespace, {group}_workload, status)' in t['expr'] for t in p.get('targets', [])))
        variables = {'orgId': 1, 'from': 'now-2m', 'to': 'now', 'panelId': panel['id'], 'var-DS_PROMETHEUS': 'fixture-prometheus', 'var-cluster': 'poc1', 'var-destination_namespace': 'team-a', 'var-destination_workload': 'shop', 'var-reporter': 'client', 'var-source_namespace': '$__all' if selection == 'All' else 'loadtest', 'var-source_workload': '$__all' if selection == 'All' else 'load'}
        pages.append({'name': name, 'url': f'http://127.0.0.1:3000/d-solo/{uid}/fixture?{urllib.parse.urlencode(variables)}', 'before': 6000, 'evidence': 'panels', 'expect': {'panelsMin': 1, 'noDataAllowed': [], 'prometheusTotal': total, 'prometheusSeries': count}})
    (out / 'walk.json').write_text(json.dumps({'viewport': {'width': 1600, 'height': 1000}, 'pages': pages}, indent=2))
    (out / 'source.json').write_text(json.dumps({'source': SOURCE, 'upstream_base': BASE, 'kind': 'synthetic dashboard regression', 'grafana': '12.2.0', 'prometheus': '3.10.0', 'application_load': False}, indent=2) + '\n')

def serve():
    started = time.monotonic()
    base = dict(cluster='poc1', destination_namespace='team-a', destination_workload='shop', reporter='client', status='200')
    streams = [(500, dict(source_namespace='', source_workload='')), (50, dict(source_namespace='loadtest', source_workload='load')), (999, dict(cluster='poc2', source_namespace='', source_workload='')), (777, dict(destination_workload='other', source_namespace='', source_workload='')), (111, dict(destination_namespace='team-b', source_namespace='', source_workload='')), (222, dict(reporter='server', source_namespace='', source_workload=''))]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/metrics':
                lines = ['# TYPE hubble_http_requests_total counter']
                for rate, overrides in streams:
                    labels = ','.join(f'{k}={json.dumps(v)}' for k, v in sorted((base | overrides).items()))
                    lines.append('hubble_http_requests_total{' + labels + '} ' + str((time.monotonic() - started) * rate))
                body = ('\n'.join(lines) + '\n').encode()
                content_type = 'text/plain; version=0.0.4'
            else:
                body = b'<!doctype html><html><meta charset="utf-8"><title>Synthetic dashboard fixture</title><body style="font:24px sans-serif;max-width:1000px;margin:80px auto"><h1>SYNTHETIC dashboard regression fixture</h1><p>No application traffic is generated.</p><table cellpadding="15"><tr><th>Counter stream</th><th>Rate / second</th></tr><tr><td>Gateway: empty source namespace/workload</td><td>500</td></tr><tr><td>Pod: loadtest/load</td><td>50</td></tr><tr><td>Expected All total</td><td>550</td></tr><tr><td>Expected selected pod total</td><td>50</td></tr></table><p>Other clusters, destinations and reporters are isolation controls.</p></body></html>'
                content_type = 'text/html; charset=utf-8'
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    HTTPServer(('127.0.0.1', 18080), Handler).serve_forever()

def check(source, out):
    dashboard = json.loads((source / RELATIVE).read_text())
    expr = next(t['expr'] for p in walk(dashboard['panels']) for t in p.get('targets', []) if t.get('expr', '').startswith('round(sum(rate(hubble_http_requests_total') and 'by (cluster, destination_namespace, destination_workload, status)' in t['expr'])
    results = []
    for name, ns, workload, expected in [('baseline-all', '(loadtest)', '(load)', 50), ('fixed-all', '.*', '.*', 550), ('explicit-source', 'loadtest', 'load', 50)]:
        query = expr
        for key, value in dict(cluster='poc1', destination_namespace='team-a', destination_workload='shop', reporter='client', source_namespace=ns, source_workload=workload).items():
            query = query.replace('${' + key + '}', value)
        query = 'sum(' + query.replace('$__rate_interval', '10s') + ')'
        for attempt in range(45):
            try:
                with urllib.request.urlopen('http://127.0.0.1:9090/api/v1/query?' + urllib.parse.urlencode({'query': query}), timeout=5) as response:
                    data = json.load(response)
                value = sum(float(s['value'][1]) for s in data['data']['result'])
                if abs(value - expected) < expected * .02:
                    break
            except (OSError, KeyError, ValueError):
                pass
            time.sleep(1)
        else:
            raise RuntimeError(f'{name} did not produce {expected}: {data if "data" in locals() else "no response"}')
        results.append({'name': name, 'query': query, 'expected': expected, 'actual': value, 'synthetic': True})
    (out / 'live-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['prepare', 'serve', 'check'])
    parser.add_argument('--source', type=Path, default=Path('source'))
    parser.add_argument('--out', type=Path, default=Path('artifacts'))
    args = parser.parse_args()
    if args.mode == 'serve':
        serve()
    elif args.mode == 'prepare':
        prepare(args.source, args.out)
    else:
        check(args.source, args.out)

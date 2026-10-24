#!/usr/bin/env python3
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

"""Assert real deployed HTTP traffic before making live Grafana capture specs."""
import json
import hashlib
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

SOURCE = os.environ.get('DASHBOARD_SOURCE_SHA', 'e00be3729bf71334a500b5202a8e1136177697b3')
OUT = Path('artifacts')
LIVE = OUT / 'live'
SELECTOR = 'cluster="poc1",destination_namespace="team-a",destination_workload="shop"'
APP_SELECTOR = 'cluster="poc1",destination_namespace="team-a",destination_app="storefront"'

def query(expr):
    with urllib.request.urlopen('http://127.0.0.1:9090/api/v1/query?' + urllib.parse.urlencode({'query': expr}), timeout=10) as response:
        data = json.load(response)
    assert data['status'] == 'success', data
    return data['data']['result']

def value(expr):
    return sum(float(item['value'][1]) for item in query(expr))

def grafana_version():
    with urllib.request.urlopen('http://127.0.0.1:3000/api/health', timeout=5) as response:
        health = json.load(response)
    assert health['database'] == 'ok' and isinstance(health.get('version'), str) and health['version'], health
    (LIVE / 'grafana-health.json').write_text(json.dumps(health, indent=2) + '\n')
    return health['version']

def snapshot():
    try:
        (LIVE / 'all-http-series.json').write_text(json.dumps(query('hubble_http_requests_total'), indent=2) + '\n')
        with urllib.request.urlopen('http://127.0.0.1:9090/api/v1/targets', timeout=10) as response:
            (LIVE / 'scrape-targets.json').write_text(json.dumps(json.load(response), indent=2) + '\n')
    except (OSError, ValueError, KeyError) as error:
        print(f'Scrape snapshot not available: {error}', flush=True)

def check():
    LIVE.mkdir(parents=True, exist_ok=True)
    # More than two minutes of real load, multiple 10-second scrapes and rule evaluations.
    start = time.monotonic()
    last_error = None
    while time.monotonic() - start < 300:
        try:
            grafana = grafana_version()
            snapshot()
            gateway_reporters = query('sum by (reporter) (rate(hubble_http_requests_total{' + SELECTOR + ',node="poc1-worker",source_namespace="",source_workload="",status="200"}[1m]))')
            gateway = max((float(item['value'][1]) for item in gateway_reporters), default=0)
            direct = value('sum(rate(hubble_http_requests_total{' + SELECTOR + ',reporter="server",source_namespace="loadtest",source_workload="load",status="200"}[1m]))')
            print(f'Gateway HTTP200={gateway:.3f}/s; direct HTTP200={direct:.3f}/s', flush=True)
            if time.monotonic() - start >= 120 and gateway > 50 and direct > 5:
                break
        except (OSError, ValueError, KeyError, AssertionError) as error:
            last_error = str(error)
        time.sleep(5)
    else:
        raise RuntimeError(f'Real Gateway/direct HTTP rates unavailable: {last_error}; Gateway={locals().get("gateway")}, direct={locals().get("direct")}')
    series = query('hubble_http_requests_total{' + SELECTOR + '}')
    (LIVE / 'hubble-http-series.json').write_text(json.dumps(series, indent=2) + '\n')
    reporter = max(gateway_reporters, key=lambda item: float(item['value'][1]))['metric']['reporter']
    total_query = 'sum(rate(hubble_http_requests_total{' + SELECTOR + ',reporter="' + reporter + '",source_namespace=~".*",source_workload=~".*"}[1m]))'
    baseline_query = 'sum(rate(hubble_http_requests_total{' + SELECTOR + ',reporter="' + reporter + '",source_namespace=~"(loadtest)",source_workload=~"(load)"}[1m]))'
    total = value(total_query)
    baseline = value(baseline_query)
    assert total > 50 and total - baseline > gateway * .8, (total, baseline)
    app_total = value('sum(rate(hubble_http_requests_total{' + APP_SELECTOR + ',reporter="' + reporter + '",source_namespace=~".*",source_app=~".*",status="200"}[1m]))')
    app_direct = value('sum(rate(hubble_http_requests_total{' + APP_SELECTOR + ',reporter="server",source_namespace="loadtest",source_app="checkout-client",status="200"}[1m]))')
    app_gateway = value('sum(rate(hubble_http_requests_total{' + APP_SELECTOR + ',reporter="' + reporter + '",source_namespace="loadtest",source_app="checkout-client",status="200"}[1m]))')
    assert total * .9 <= app_total <= total * 1.1, (app_total, total)
    assert direct * .9 <= app_direct <= direct * 1.1, (app_direct, direct)
    assert baseline * .9 <= app_gateway <= baseline * 1.1, (app_gateway, baseline)
    app_series = query('hubble_http_requests_total{' + APP_SELECTOR + '}')
    assert any(item['metric'].get('destination_workload') == 'shop' and item['metric'].get('source_app') == 'checkout-client' and item['metric'].get('source_workload') == 'load' for item in app_series), 'App names must differ from workload names in the regression fixture'
    gateway_series = [item for item in series if item['metric'].get('reporter') == reporter and not item['metric'].get('source_namespace') and item['metric'].get('node') == 'poc1-worker']
    assert gateway_series, 'Missing remote-workload metrics on Gateway worker node'
    pods = json.loads(subprocess.check_output(['kubectl', 'get', 'pods', '-n', 'team-a', '-l', 'app=shop', '-o', 'json']))
    assert pods['items'] and all(pod['spec']['nodeName'] == 'poc1-control-plane' for pod in pods['items'])
    agents = json.loads((LIVE / 'agent-pods.json').read_text())
    assert len(agents['items']) == 2
    expected_agent = 'docker.io/ephico2real2/cilium:dashboard-test'
    expected_operator = 'docker.io/ephico2real2/operator-generic:dashboard-test'
    if (OUT / 'published-images.lock.json').exists():
        lock = json.loads((OUT / 'published-images.lock.json').read_text())
        assert lock['source_sha'] == SOURCE
        expected_agent = lock['images']['agent']['image']
        expected_operator = lock['images']['operator-generic']['image']
    assert all(p['spec']['containers'][0]['image'] == expected_agent for p in agents['items'])
    operators = json.loads((LIVE / 'operator-pods.json').read_text())
    assert operators['items'] and all(p['spec']['containers'][0]['image'] == expected_operator for p in operators['items'])
    # Verify live versions include this exact fork source, rather than a release image.
    assert SOURCE[:8] in (LIVE / 'cilium-version.txt').read_text()
    results = {'application_load': True, 'requested_qps': {'external_gateway': 200, 'pod_gateway': 200, 'direct_pod': 20}, 'gateway_measured_http_200_qps': gateway, 'gateway_reporter': reporter, 'gateway_client': 'external Docker container on kind bridge', 'direct_measured_http_200_qps': direct, 'fixed_all_qps': total, 'baseline_enumerated_source_qps': baseline, 'baseline_query': baseline_query, 'fixed_query': total_query, 'remote_backend_node': 'poc1-control-plane', 'gateway_reporter_node': 'poc1-worker', 'source_commit': SOURCE}
    results['app_dashboard'] = {'uid':'hubble-l7-http-by-app','generator_commit':'22fb6e14c0cca8c78af1f072d1e89ebaea6a916b','destination_app':'storefront','destination_workload':'shop','source_app':'checkout-client','source_workload':'load','all_qps':app_total,'direct_qps':app_direct,'pod_gateway_qps':app_gateway}
    (OUT / 'live-results.json').write_text(json.dumps(results, indent=2) + '\n')
    source = json.loads((OUT / 'source.json').read_text())
    source.update(images={'agent':expected_agent,'operator':expected_operator},kind='real two-node Cilium Gateway load', application_load=True, grafana=grafana, prometheus='kube-prometheus-stack 90.1.1', traffic='Fortio 1.75.3: external Gateway 200, pod Gateway 200, direct pod 20 req/s; six minutes each')
    source['evidence_tools_source'] = os.environ.get('DASHBOARD_TOOLS_SHA', os.environ.get('GITHUB_SHA', 'unrecorded'))
    source['app_dashboard'] = results['app_dashboard'] | {'generator_sha256':hashlib.sha256(Path('poc/demos/37-two-gateways/l7-by-app-dashboard.py').read_bytes()).hexdigest()}
    (OUT / 'source.json').write_text(json.dumps(source, indent=2) + '\n')
    pages = []
    cases = [('01-before-all-destination', 'baseline-hubble-l7-all', 10, reporter, True, False), ('02-after-all-destination', '3g264CZVz', 10, reporter, False, False), ('03-before-all-source', 'baseline-hubble-l7-all', 3, reporter, True, False), ('04-after-all-source', '3g264CZVz', 3, reporter, False, False), ('05-after-selected-direct-source', '3g264CZVz', 10, 'server', False, True)]
    for name, uid, panel, page_reporter, before, selected in cases:
        variables = {'orgId': 1, 'from': 'now-5m', 'to': 'now', 'panelId': panel, 'var-DS_PROMETHEUS': 'prometheus', 'var-cluster': 'poc1', 'var-destination_namespace': 'team-a', 'var-destination_workload': 'shop', 'var-reporter': page_reporter, 'var-source_namespace': 'loadtest' if selected else '$__all', 'var-source_workload': 'load' if selected else '$__all'}
        # BEFORE excludes the external Gateway stream; AFTER must include it.
        expect = {'panelsMin': 1, 'prometheusTotal': baseline, 'prometheusSeries': 1 if baseline > 0 else 0} if before else ({'panelsMin': 1, 'noDataAllowed': [], 'prometheusTotal': direct, 'prometheusSeries': 1} if selected else {'panelsMin': 1, 'noDataAllowed': [], 'prometheusMin': baseline + gateway * .7})
        pages.append({'name': name, 'url': 'http://127.0.0.1:3000/d-solo/' + uid + '/live?' + urllib.parse.urlencode(variables), 'before': 6000, 'evidence': 'panels', 'expect': expect})
    selected_variables = dict(variables) | {'var-reporter': reporter, 'var-source_namespace':'loadtest', 'var-source_workload':'load'}
    pages.append({'name':'06-after-selected-pod-gateway-source', 'url':'http://127.0.0.1:3000/d-solo/3g264CZVz/live?' + urllib.parse.urlencode(selected_variables), 'before':6000, 'evidence':'panels', 'expect':{'panelsMin':1, 'noDataAllowed':[], 'prometheusTotal':baseline, 'prometheusSeries':1}})
    pages.append({'name': '07-after-live-dashboard-overview', 'url': 'http://127.0.0.1:3000/d/3g264CZVz/live?' + urllib.parse.urlencode({k:v for k,v in variables.items() if k != 'panelId'} | {'var-reporter':reporter, 'var-source_namespace':'$__all', 'var-source_workload':'$__all'}), 'fullPage': True, 'before': 6000, 'evidence': 'panels', 'expect': {'panelsMin':11, 'noDataAllowed':[]}})
    app_variables = {'orgId':1,'from':'now-5m','to':'now','panelId':10,'var-DS_PROMETHEUS':'prometheus','var-cluster':'poc1','var-destination_namespace':'team-a','var-destination_app':'storefront','var-reporter':reporter,'var-source_namespace':'$__all','var-source_app':'$__all'}
    app_cases = [
        ('08-by-app-all', app_variables, {'prometheusMin':baseline + gateway * .7}),
        ('09-by-app-selected-direct', app_variables | {'var-reporter':'server','var-source_namespace':'loadtest','var-source_app':'checkout-client'}, {'prometheusTotal':app_direct,'prometheusSeries':1}),
        ('10-by-app-selected-gateway', app_variables | {'var-source_namespace':'loadtest','var-source_app':'checkout-client'}, {'prometheusTotal':app_gateway,'prometheusSeries':1}),
    ]
    for name, app_vars, expected in app_cases:
        pages.append({'name':name,'url':'http://127.0.0.1:3000/d-solo/hubble-l7-http-by-app/live?' + urllib.parse.urlencode(app_vars),'before':6000,'evidence':'panels','expect':{'panelsMin':1,'noDataAllowed':[]} | expected})
    pages.append({'name':'11-by-app-dashboard-overview','url':'http://127.0.0.1:3000/d/hubble-l7-http-by-app/live?' + urllib.parse.urlencode({k:v for k,v in app_variables.items() if k != 'panelId'}),'fullPage':True,'before':6000,'evidence':'panels','expect':{'panelsMin':9,'noDataAllowed':[]}})
    (OUT / 'walk.json').write_text(json.dumps({'viewport': {'width': 1600, 'height': 1000}, 'pages': pages}, indent=2) + '\n')
    print(json.dumps(results, indent=2))

def loads():
    result = {}
    for stream, target in [('gateway', 200), ('pod-gateway', 200), ('direct', 20)]:
        raw = (LIVE / (stream + '-load.json')).read_text()
        # fortio curl includes HTTP headers before its body.
        data = json.loads(raw[raw.index('{'):])
        codes = data['RetCodes']
        calls = sum(codes.values())
        assert calls > target * 120, (stream, calls)
        assert codes.get('200', 0) / calls >= .99, (stream, codes)
        assert data['ActualQPS'] >= target * .5, (stream, data['ActualQPS'])
        result[stream] = {'requests': calls, 'http_status_counts': codes, 'actual_qps': data['ActualQPS'], 'duration_ns': data['ActualDuration']}
    (LIVE / 'load-validation.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    loads() if sys.argv[1:] == ['loads'] else check()

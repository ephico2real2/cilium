#!/usr/bin/env python3
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

"""Check the real dashboard queries with synthetic Prometheus counter series."""
import copy
import json
import re
import os
from pathlib import Path
import subprocess
import sys

workspace = Path(sys.argv[1])
output = Path(os.environ.get("DASHBOARD_EVIDENCE_OUT", str(Path(__file__).parent)))
output.mkdir(parents=True, exist_ok=True)
promtool = Path(os.environ.get("DASHBOARD_PROMTOOL", str(output / "tools/prometheus-3.10.0.darwin-arm64/promtool")))
relative = "install/kubernetes/cilium/files/hubble/dashboards/hubble-l7-http-metrics-by-workload.json"
before = json.loads(subprocess.check_output(["git", "show", f"upstream/main:{relative}"], cwd=workspace))
after = json.loads((workspace / relative).read_text())
addon = workspace / "examples/kubernetes/addons/prometheus/files/grafana-dashboards" / Path(relative).name
assert addon.is_symlink() and addon.read_bytes() == (workspace / relative).read_bytes()
without_fix = copy.deepcopy(after)
for variable in without_fix["templating"]["list"]:
    if variable["name"] in ("source_namespace", "source_workload"):
        assert variable.pop("allValue") == ".*"
        assert variable["includeAll"] and variable["multi"]
assert without_fix == before, "Only the two source All regex values may change"

def panels(items):
    for item in items:
        yield item
        yield from panels(item.get("panels", []))

queries = []
for panel in panels(after["panels"]):
    for target in panel.get("targets", []):
        expr = target.get("expr", "")
        if expr.startswith("round(sum(rate(hubble_http_requests_total") and "${source_namespace}" in expr:
            queries.append((panel["title"], expr))
assert len(queries) == 2

base_labels = dict(cluster="poc1", destination_namespace="team-a", destination_workload="shop", reporter="client", status="200")
def series(rate, **extra):
    labels = base_labels | extra
    formatted = ",".join(f"{key}={json.dumps(value)}" for key, value in sorted(labels.items()))
    return {"series": "hubble_http_requests_total{" + formatted + "}", "values": f"0+{rate}x30"}

inputs = [
    series(500, source_namespace="", source_workload=""),
    series(50, source_namespace="loadtest", source_workload="load"),
    series(999, cluster="poc2", source_namespace="", source_workload=""),
    series(777, destination_workload="other", source_namespace="", source_workload=""),
    series(111, destination_namespace="team-b", source_namespace="", source_workload=""),
    series(222, reporter="server", source_namespace="", source_workload=""),
]
def query(expr, namespace, workload):
    substitutions = {"cluster": "poc1", "destination_namespace": "team-a", "destination_workload": "shop", "reporter": "client", "source_namespace": namespace, "source_workload": workload}
    for key, value in substitutions.items():
        expr = expr.replace("${" + key + "}", value)
    expr = expr.replace("$__rate_interval", "10s")
    assert "$" not in expr
    return "sum(" + expr + ")"

def fixture(cases):
    return {"rule_files": [], "evaluation_interval": "1s", "tests": [{"name": "Gateway source labels and existing selection boundaries", "interval": "1s", "input_series": inputs, "promql_expr_test": cases}]}

def case(expr, expected):
    return {"expr": expr, "eval_time": "20s", "exp_samples": [{"labels": "{}", "value": expected}]}

variables = {v["name"]: v for v in after["templating"]["list"]}
checks = []
before_checks = []
for title, expr in queries:
    checks.extend([
        case(query(expr, variables["source_namespace"]["allValue"], variables["source_workload"]["allValue"]), 550),
        case(query(expr, "loadtest", "load"), 50),
        case(query(expr, ".*", "load"), 50),
        case(query(expr, "loadtest", ".*"), 50),
    ])
    # Grafana's default All expands the listed nonempty values. It omits the
    # Gateway series, whose source identity has neither namespace nor workload.
    before_checks.append(case(query(expr, "(loadtest)", "(load)"), 550))

for name, cases in [("after", checks), ("before", before_checks)]:
    path = output / f"{name}.test.json"
    path.write_text(json.dumps(fixture(cases), indent=2) + "\n")
    result = subprocess.run([str(promtool), "test", "rules", str(path)], text=True, capture_output=True)
    log = result.stdout + result.stderr
    (output / f"{name}.log").write_text(log)
    if name == "after":
        assert result.returncode == 0, log
    else:
        mismatches = re.findall(r"exp:\s+\{\}\s+(\S+)\s+got:\s+\{\}\s+(\S+)", log)
        assert result.returncode != 0 and len(mismatches) == 2, log
        assert all(float(expected) == 550 and float(actual) == 50 for expected, actual in mismatches), log

report = {"base": subprocess.check_output(["git", "rev-parse", "upstream/main"], cwd=workspace, text=True).strip(), "validation": "synthetic PromQL fixtures, not live load", "prometheus": "3.10.0", "dashboard_id_preserved": after["uid"], "only_changes": ["source_namespace.allValue", "source_workload.allValue"], "addon_symlink_resolves_to_chart": True, "baseline_gateway_all": "FAIL as expected: 50 instead of 550 req/s", "fixed_gateway_all": "PASS: 550 req/s", "explicit_source_filters": "PASS: 50 req/s", "namespace_cluster_workload_reporter_isolation": "PASS", "promql_assertions": len(checks)}
(output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))

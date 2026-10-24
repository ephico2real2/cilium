#!/usr/bin/env python3
"""l7-by-app-dashboard.py <chart dashboard json> > <lab dashboard json>

The lab's copy of Cilium's "Hubble L7 HTTP Metrics by Workload", keyed on the app labels instead of the workload ones —
gotcha #115: `destination_workload` (the Deployment name, from the pod's Kubernetes metadata) is filled only when the
backend pod is local to the node whose Envoy reported the flow, so for Gateway traffic the chart's dashboard shows the
local fraction or nothing; `destination_app` / `source_app` ("the pod's app name from labels — app.kubernetes.io/name,
k8s-app, or app", the metrics reference) come from the identity labels every agent knows for every peer. Cilium's own
dashboard is left untouched (the chart provisions it); this one is provisioned beside it from this file.

What changes, and nothing else: every Hubble query's `destination_workload` → `destination_app`, `source_workload` →
`source_app`, the two template variables likewise (their queries read label_values of the new labels), the title and
uid. The CPU panels join Hubble's workload name onto kube-state-metrics' `kube_pod_owner` — an app name is not a
workload name, so those two panels are dropped rather than left silently wrong."""
import json, sys
UPSTREAM = "--upstream" in sys.argv          # the shape proposed to cilium/cilium: same title and uid, the CPU panels kept
d = json.load(open([a for a in sys.argv[1:] if not a.startswith("--")][0]))
if not UPSTREAM:
    d["title"] = "Hubble L7 HTTP Metrics by App (Gateway-aware)"
    d["uid"] = "hubble-l7-http-by-app"; d["id"] = None
    d.pop("__inputs", None); d.pop("__requires", None)
swap = [("destination_workload", "destination_app"), ("source_workload", "source_app")]
def fix(expr):
    for a, b in swap: expr = expr.replace(a, b)
    return expr
for v in d["templating"]["list"]:
    if v["name"] in ("destination_workload", "source_workload"):
        v["name"] = fix(v["name"]); v["label"] = v.get("label", v["name"]).replace("Workload", "App").replace("workload", "app")
        q = v["query"]
        if isinstance(q, dict): q["query"] = fix(q["query"])
        else: v["query"] = fix(q)
        v["definition"] = fix(v.get("definition", ""))
    else:
        q = v.get("query")
        if isinstance(q, dict) and "query" in q: q["query"] = fix(q["query"])
        elif isinstance(q, str): v["query"] = fix(q)
    # "All" on a multi-value variable is a regex of the LISTED values, and label_values never lists the empty string —
    # the Gateway's traffic has source_app="" (the source is reserved:ingress, no app) and source_namespace="", so
    # every "by Source" panel dropped it; the chart's dashboard has the same hole with source_workload. allValue ".*"
    # makes "All" mean all, the empty value included.
    if v.get("includeAll"):
        v["allValue"] = ".*"
def walk(panels):
    keep = []
    for p in panels:
        if p.get("type") == "row" and p.get("panels"): p["panels"] = walk(p["panels"])
        exprs = [t.get("expr", "") for t in p.get("targets", [])]
        if any("kube_pod_owner" in e for e in exprs):
            if UPSTREAM:
                keep.append(p); continue   # upstream: kept as they are — their workload variable stays, sourced from kube-state-metrics below
            continue   # the lab copy: an app is not a workload, drop rather than mislabel
        for t in p.get("targets", []):
            if "expr" in t: t["expr"] = fix(t["expr"])
            if "legendFormat" in t: t["legendFormat"] = fix(t["legendFormat"])
        if "title" in p: p["title"] = p["title"].replace("Workload", "App")
        keep.append(p)
    return keep
d["panels"] = walk(d["panels"])
if UPSTREAM:
    # the CPU panels still read ${destination_workload} / ${source_workload}: give them variables that come from
    # kube-state-metrics (always complete), no longer from Hubble's label (empty for a remote backend)
    ds = d["templating"]["list"][0].get("datasource", {"type": "prometheus", "uid": "${DS_PROMETHEUS}"})
    for name, q in (("destination_workload", 'label_values(namespace_workload_pod:kube_pod_owner:relabel{cluster=~"${cluster}", namespace=~"${destination_namespace}"}, workload)'),
                    ("source_workload", 'label_values(namespace_workload_pod:kube_pod_owner:relabel{cluster=~"${cluster}", namespace=~"${source_namespace}"}, workload)')):
        d["templating"]["list"].append({"name": name, "label": name.replace("_", " ") + " (CPU panels)", "type": "query", "datasource": ds,
            "definition": q, "query": {"query": q, "refId": "PrometheusVariableQueryEditor-VariableQuery"}, "refresh": 2,
            "includeAll": True, "allValue": ".*", "multi": True, "sort": 1, "current": {"selected": True, "text": ["All"], "value": ["$__all"]}})
json.dump(d, sys.stdout, indent=2 if UPSTREAM else None, separators=(",", ": ") if UPSTREAM else (",", ":"))
if UPSTREAM: sys.stdout.write("\n")

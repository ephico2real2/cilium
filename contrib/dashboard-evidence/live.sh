#!/usr/bin/env bash
# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# Real, bounded Gateway load; adapted from PoC demos 37/39 and lab-observability.
set -euo pipefail
mkdir -p artifacts/live
exec > >(tee -a artifacts/live/setup.log) 2>&1
case "${1:-}" in
build)
  # Native builds are loaded locally, never pushed to upstream Quay.
  make -C source docker-cilium-image docker-operator-generic-image \
    DOCKER_REGISTRY=docker.io DOCKER_DEV_ACCOUNT=ephico2real2 \
    DOCKER_IMAGE_TAG=dashboard-test DOCKER_FLAGS=--load
  docker build -t routedemo:local -f poc/demos/09-routes/app/Containerfile poc/demos
  docker build -t cilium-dashboard-capture:dev contrib/dashboard-evidence
  docker image inspect docker.io/ephico2real2/cilium:dashboard-test docker.io/ephico2real2/operator-generic:dashboard-test routedemo:local > artifacts/live/built-images.json
  ;;
install)
  bash poc/scripts/bootstrap/ubuntu.sh
  cat > .tmp/kind.yaml <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  kubeProxyMode: none
nodes:
  - role: control-plane
  - role: worker
YAML
  kind create cluster --name poc1 --image kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed --config .tmp/kind.yaml --wait 60s
  kind load docker-image --name poc1 docker.io/ephico2real2/cilium:dashboard-test docker.io/ephico2real2/operator-generic:dashboard-test routedemo:local
  gateway_version=$(awk '$1 == "sigs.k8s.io/gateway-api" {print $2}' source/go.mod)
  curl -fsSL --retry 4 "https://github.com/kubernetes-sigs/gateway-api/releases/download/$gateway_version/experimental-install.yaml" -o artifacts/live/gateway-crds.yaml
  kubectl apply --server-side -f artifacts/live/gateway-crds.yaml
  control_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' poc1-control-plane)
  helm install cilium source/install/kubernetes/cilium -n kube-system \
    -f contrib/dashboard-evidence/cilium-live.yaml \
    --set k8sServiceHost="$control_ip" --set k8sServicePort=6443 --wait --timeout 12m
  kubectl rollout status -n kube-system ds/cilium --timeout=5m
  kubectl rollout status -n kube-system ds/cilium-envoy --timeout=5m
  kubectl wait --for=condition=Ready nodes --all --timeout=5m
  helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
  helm upgrade --install monitoring prometheus-community/kube-prometheus-stack --version 90.1.1 \
    -n monitoring --create-namespace -f poc/demos/16-monitoring/values-kube-prometheus-stack.yaml \
    -f contrib/dashboard-evidence/monitoring-live.yaml --wait --timeout 15m
  helm upgrade cilium source/install/kubernetes/cilium -n kube-system --reuse-values \
    -f poc/demos/16-monitoring/values-cilium-metrics.yaml \
    --set hubble.metrics.dashboards.enabled=false --set dashboards.enabled=false \
    --set operator.dashboards.enabled=false --set clustermesh.useAPIServer=false \
    --set clustermesh.apiserver.metrics.serviceMonitor.enabled=false --wait --timeout 10m
  kubectl rollout status -n kube-system ds/cilium --timeout=5m
  kubectl create configmap dashboard-regression -n monitoring \
    --from-file=before.json=artifacts/grafana/dashboards/before.json \
    --from-file=after.json=artifacts/grafana/dashboards/after.json
  kubectl label configmap dashboard-regression -n monitoring grafana_dashboard=1
  kubectl apply -f contrib/dashboard-evidence/apps-live.yaml
  kubectl rollout status -n team-a deployment/shop --timeout=5m
  kubectl rollout status -n loadtest deployment/load --timeout=5m
  kubectl wait -n team-a --for=condition=Programmed gateway/shop --timeout=5m
  worker_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' poc1-worker)
  kubectl exec -n loadtest deployment/load -- fortio curl -H 'Host: shop.poc.local' "http://$worker_ip:8080/" > artifacts/live/gateway-probe.log
  kubectl exec -n loadtest deployment/load -- fortio curl http://shop.team-a.svc.cluster.local:8080/ > artifacts/live/direct-probe.log
  kubectl get nodes -o wide > artifacts/live/nodes.txt
  kubectl get pods -A -o wide > artifacts/live/pods.txt
  kubectl get -n team-a gateway,httproute -o yaml > artifacts/live/gateway-route.yaml
  kubectl get pods -n kube-system -l k8s-app=cilium -o json > artifacts/live/agent-pods.json
  kubectl get pods -n kube-system -l name=cilium-operator -o json > artifacts/live/operator-pods.json
  client_agent=$(kubectl get pods -n kube-system -l k8s-app=cilium --field-selector spec.nodeName=poc1-worker -o jsonpath='{.items[0].metadata.name}')
  kubectl exec -n kube-system "$client_agent" -- cilium-dbg version > artifacts/live/cilium-version.txt
  kubectl exec -n kube-system "$client_agent" -- cilium-dbg status --verbose > artifacts/live/cilium-status.txt
  kubectl port-forward -n monitoring service/monitoring-kube-prometheus-prometheus 9090:9090 > artifacts/live/prometheus-forward.log 2>&1 &
  echo $! > .tmp/prometheus-forward.pid
  kubectl port-forward -n monitoring service/monitoring-grafana 3000:80 > artifacts/live/grafana-forward.log 2>&1 &
  echo $! > .tmp/grafana-forward.pid
  # Keep all three loads active through scrapes and browser captures. Record the actual Fortio summary.
  # The Gateway client is outside Kubernetes: it has no source namespace/workload.
  docker run -d --name gateway-load --network kind \
    -v "$PWD/artifacts/live:/results" fortio/fortio:1.75.3 \
    load -qps 200 -c 8 -t 6m -nocatchup -uniform \
    -H 'Host: shop.poc.local' -json /results/gateway-load.json "http://$worker_ip:8080/"
  kubectl exec -n loadtest deployment/load -- fortio load -qps 200 -c 8 -t 6m -nocatchup -uniform \
    -H 'Host: shop.poc.local' -json /data/gateway-load.json "http://$worker_ip:8080/" > artifacts/live/pod-gateway-load.log 2>&1 &
  echo $! > .tmp/pod-gateway-load.pid
  kubectl exec -n loadtest deployment/load -- fortio load -qps 20 -c 2 -t 6m -nocatchup -uniform \
    -json /data/direct-load.json http://shop.team-a.svc.cluster.local:8080/ > artifacts/live/direct-load.log 2>&1 &
  echo $! > .tmp/direct-load.pid
  ;;
collect)
  curl -fsSG --data-urlencode 'query=hubble_http_requests_total' http://127.0.0.1:9090/api/v1/query > artifacts/live/final-http-series.json || true
  curl -fsS http://127.0.0.1:9090/api/v1/targets > artifacts/live/final-scrape-targets.json || true
  for node in poc1-worker poc1-control-plane; do
    node_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$node" 2>/dev/null || true)
    if [ -n "$node_ip" ]; then curl -fsS "http://$node_ip:9965/metrics" > "artifacts/live/$node-hubble.prom" || true; fi
    agent=$(kubectl get pods -n kube-system -l k8s-app=cilium --field-selector "spec.nodeName=$node" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    if [ -n "$agent" ]; then kubectl exec -n kube-system "$agent" -- hubble observe --protocol http --last 100 -o jsonpb > "artifacts/live/$node-http-flows.jsonl" 2>&1 || true; fi
  done
  kubectl get pods -A -o wide > artifacts/live/final-pods.txt || true
  kubectl get events -A --sort-by=.lastTimestamp > artifacts/live/events.txt || true
  for app in cilium cilium-envoy; do
    kubectl logs -n kube-system -l k8s-app="$app" --all-containers --tail=400 --prefix > "artifacts/live/$app.log" 2>&1 || true
  done
  if ! kubectl get deployment -n loadtest load >/dev/null 2>&1; then
    echo 'No load deployment; retained available setup diagnostics.'
    exit 0
  fi
  # Bounded six-minute loads finish while the dashboards are being inspected.
  for stream in gateway pod-gateway direct; do
    ready=no
    for attempt in $(seq 1 48); do
      if [ "$stream" != gateway ]; then
        remote_stream=$stream
        if [ "$stream" = pod-gateway ]; then remote_stream=gateway; fi
        kubectl exec -n loadtest deployment/load -- fortio curl "http://localhost:8079/fortio/data/$remote_stream-load.json" > "artifacts/live/$stream-load.json" 2>/dev/null || true
      fi
      if python3 -c 'import json,sys; s=open(sys.argv[1]).read(); d=json.loads(s[s.index("{"):]); assert "RetCodes" in d' "artifacts/live/$stream-load.json" 2>/dev/null; then
        ready=yes; break
      fi
      echo "Waiting for measured $stream load results ($attempt/48)"
      sleep 5
    done
    [ "$ready" = yes ] || echo "Missing final $stream load JSON" >&2
  done
  docker logs gateway-load > artifacts/live/gateway-load.log 2>&1 || true
  docker inspect gateway-load > artifacts/live/gateway-client.json 2>/dev/null || true
  ;;
*) echo 'expected build, install or collect' >&2; exit 2;;
esac

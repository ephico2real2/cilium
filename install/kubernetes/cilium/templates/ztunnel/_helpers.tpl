{{/*
ztunnel's SPIRE trust domain and delegated socket. encryption.ztunnel.spire wins over
authentication.mutual.spire, so ztunnel can use a SPIRE CA without Cilium mutual authentication.
*/}}
{{- define "cilium.ztunnel.spireTrustDomain" -}}
{{- .Values.encryption.ztunnel.spire.trustDomain | default .Values.authentication.mutual.spire.trustDomain -}}
{{- end -}}

{{- define "cilium.ztunnel.spireSocketPath" -}}
{{- .Values.encryption.ztunnel.spire.delegatedSocketPath | default .Values.authentication.mutual.spire.adminSocketPath -}}
{{- end -}}

{{/* The cert-manager issuer of a ztunnel client or server certificate: its own, else the clustermesh one. */}}
{{- define "cilium.ztunnel.certManagerIssuerRef" -}}
{{- $issuer := index . 0 -}}
{{- $root := index . 1 -}}
{{- toYaml ($issuer | default $root.Values.clustermesh.apiserver.tls.auto.certManagerIssuerRef) -}}
{{- end -}}

{{/* One projected-volume source for the tls.caBundle trust bundle, written as <path>. */}}
{{- define "cilium.ztunnel.caBundleSource" -}}
{{- $root := index . 0 -}}
{{- $path := index . 1 -}}
{{- $kind := $root.Values.tls.caBundle.useSecret | ternary "secret" "configMap" -}}
- {{ $kind }}:
    name: {{ $root.Values.tls.caBundle.name }}
    items:
      - key: {{ $root.Values.tls.caBundle.key }}
        path: {{ $path }}
{{- end -}}

{{/*
A JSON array of strings as Python's json.dumps writes it ("a", "b"), which the lab's first
ConfigMaps used. The agent reads each file as YAML; keeping the bytes avoids a needless reload.
*/}}
{{- define "cilium.ztunnel.flowList" -}}
[{{ range $i, $v := . }}{{ if $i }}, {{ end }}{{ $v | toString | quote }}{{ end }}]
{{- end -}}

{{/*
MESH_EGRESS_CONFIG, with each cluster's fields in the order of ztunnel's MeshClusterRanges
(clusterId, trustDomain, podCidrs, serviceCidrs). toJson would sort them.
*/}}
{{- define "cilium.ztunnel.meshEgressConfig" -}}
{{- $clusters := list -}}
{{- range .clusters -}}
{{- $clusters = append $clusters (printf "{\"clusterId\":%s,\"trustDomain\":%s,\"podCidrs\":%s,\"serviceCidrs\":%s}" (toJson .clusterId) (toJson .trustDomain) (toJson .podCidrs) (toJson .serviceCidrs)) -}}
{{- end -}}
{{- printf "{\"clusters\":[%s],\"exceptions\":%s}" (join "," $clusters) (toJson (.exceptions | default list)) -}}
{{- end -}}

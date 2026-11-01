{{/* Chart identity helpers (labels only -- posture lives in the templates). */}}
{{- define "rsecopsx.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "rsecopsx.labels" -}}
app.kubernetes.io/name: {{ include "rsecopsx.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "rsecopsx.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rsecopsx.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Common chart helpers.
*/}}

{{- define "stele.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "stele.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* image returns the fully-qualified image reference. */}}
{{- define "stele.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/* podSecurityContext + containerSecurityContext blocks. */}}
{{- define "stele.podSecurityContext" -}}
{{- toYaml .Values.securityContext -}}
{{- end -}}

{{- define "stele.containerSecurityContext" -}}
{{- toYaml .Values.containerSecurityContext -}}
{{- end -}}

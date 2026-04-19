{{/*
Common helpers for the sigillum chart.
*/}}

{{- define "sigillum.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sigillum.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "sigillum.api.fullname" -}}
{{ include "sigillum.fullname" . }}-api
{{- end -}}

{{- define "sigillum.controller.fullname" -}}
{{ include "sigillum.fullname" . }}-controller
{{- end -}}

{{- define "sigillum.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "sigillum.labels" -}}
app.kubernetes.io/name: {{ include "sigillum.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "sigillum.api.labels" -}}
{{ include "sigillum.labels" . }}
app.kubernetes.io/component: api
{{- end -}}

{{- define "sigillum.controller.labels" -}}
{{ include "sigillum.labels" . }}
app.kubernetes.io/component: controller
{{- end -}}

{{- define "sigillum.api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sigillum.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: api
{{- end -}}

{{- define "sigillum.controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sigillum.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: controller
{{- end -}}

{{- define "sigillum.webhook.serviceName" -}}
{{ include "sigillum.controller.fullname" . }}-webhook
{{- end -}}

{{- define "sigillum.webhook.secretName" -}}
{{- default (printf "%s-webhook-tls" (include "sigillum.fullname" .)) .Values.webhook.certificate.secretName -}}
{{- end -}}

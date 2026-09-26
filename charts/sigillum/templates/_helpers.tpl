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

{{- define "sigillum.smtp.fullname" -}}
{{ include "sigillum.fullname" . }}-smtp
{{- end -}}

{{- define "sigillum.smtp.labels" -}}
{{ include "sigillum.labels" . }}
app.kubernetes.io/component: smtp
{{- end -}}

{{- define "sigillum.smtp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sigillum.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: smtp
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

{{/*
Rate-limit flags shared by every Deployment that sends mail.
*/}}
{{- define "sigillum.ratelimitArgs" -}}
- --ratelimit-backend={{ .Values.rateLimit.backend }}
{{- if eq .Values.rateLimit.backend "redis" }}
{{- if not .Values.rateLimit.redis.addrs }}
{{- fail "rateLimit.redis.addrs is required when rateLimit.backend=redis" }}
{{- end }}
- --redis-addrs={{ .Values.rateLimit.redis.addrs | join "," }}
{{- with .Values.rateLimit.redis.masterName }}
- --redis-master={{ . }}
{{- end }}
- --redis-db={{ .Values.rateLimit.redis.db }}
- --redis-tls={{ .Values.rateLimit.redis.tls }}
- --ratelimit-fail-open={{ .Values.rateLimit.failOpen }}
{{- end }}
{{- end }}

{{/*
Redis credentials from an existing Secret (never rendered into args).
*/}}
{{- define "sigillum.ratelimitEnv" -}}
{{- if and (eq .Values.rateLimit.backend "redis") .Values.rateLimit.redis.existingSecret }}
- name: SIGILLUM_REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.rateLimit.redis.existingSecret }}
      key: {{ .Values.rateLimit.redis.passwordKey }}
{{- with .Values.rateLimit.redis.usernameKey }}
- name: SIGILLUM_REDIS_USERNAME
  valueFrom:
    secretKeyRef:
      name: {{ $.Values.rateLimit.redis.existingSecret }}
      key: {{ . }}
      optional: true
{{- end }}
{{- end }}
{{- end }}

{{/*
OpenTelemetry env (US-4.4). Rendered only when an endpoint is configured.
Arg: dict "root" $ "service" "<service name>".
*/}}
{{- define "sigillum.tracingEnv" -}}
{{- $t := .root.Values.tracing }}
{{- if $t.endpoint }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ $t.endpoint | quote }}
- name: OTEL_SERVICE_NAME
  value: {{ .service | quote }}
{{- with $t.sampler }}
- name: OTEL_TRACES_SAMPLER
  value: {{ . | quote }}
{{- end }}
{{- with $t.samplerArg }}
- name: OTEL_TRACES_SAMPLER_ARG
  value: {{ . | quote }}
{{- end }}
{{- with $t.resourceAttributes }}
- name: OTEL_RESOURCE_ATTRIBUTES
  value: {{ . | quote }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common args of the mail-sending components: cluster name and the namespaces
whose Secrets may be read (release namespace + rbac.allowedSecretNamespaces).
*/}}
{{- define "sigillum.commonArgs" -}}
{{- with .Values.clusterName }}
- --cluster-name={{ . }}
{{- end }}
- --secret-namespaces={{ prepend .Values.rbac.allowedSecretNamespaces .Release.Namespace | uniq | join "," }}
{{- end }}

{{/*
True (non-empty) when generated MailCredentials are enabled. The
controller's Secret-write permission is only ever rendered together with the
credential Secret guard.
*/}}
{{- define "sigillum.credentials.guarded" -}}
{{- if and .Values.controller.enabled .Values.credentials.enabled -}}
true
{{- end -}}
{{- end }}

{{- define "sigillum.credentials.guardName" -}}
{{ include "sigillum.fullname" . }}-credential-guard
{{- end }}

{{/*
Host written into generated credential Secrets.
*/}}
{{- define "sigillum.credentials.smtpHost" -}}
{{- default (printf "%s.%s.svc" (include "sigillum.smtp.fullname" .) .Release.Namespace) .Values.credentials.smtpHost -}}
{{- end }}

{{/*
Effective smtp.allowInsecureAuth: an explicit true/false wins, unset follows
TLS (insecure AUTH only while no STARTTLS certificate is configured).
*/}}
{{- define "sigillum.smtp.allowInsecureAuth" -}}
{{- if kindIs "bool" .Values.smtp.allowInsecureAuth -}}
{{- .Values.smtp.allowInsecureAuth -}}
{{- else -}}
{{- empty .Values.smtp.tls.secretName -}}
{{- end -}}
{{- end }}

{{/*
AUTH PLAIN / LOGIN with MailCredentials needs TLS; plaintext only with an
explicit smtp.allowInsecureAuth: true (null, the default, does not count).
*/}}
{{- define "sigillum.smtp.allowInsecureCredentialAuth" -}}
{{- and (kindIs "bool" .Values.smtp.allowInsecureAuth) .Values.smtp.allowInsecureAuth -}}
{{- end }}

# Sigillum

Kubernetes-native, policy-enforced mail gateway. Workloads authenticate with
their ServiceAccount token, POST JSON to the api-server, and Sigillum applies a
declarative `MailPolicy` (sender/recipient allowlists, size limits, rate limits)
before forwarding through a `MailBackend` (SMTP) relay.

- **Custom resources:** `MailBackend`, `ClusterMailBackend`, `MailPolicy`,
  `MailCredential`
- **Transports:** REST (`POST /v1/messages`) and an optional SMTP submission
  proxy for legacy workloads and off-the-shelf apps
- **Auth:** projected ServiceAccount tokens, verified via `TokenReview`
  (REST: `Authorization: Bearer`, SMTP: `AUTH OAUTHBEARER`); Sigillum-issued
  SMTP usernames and passwords bound to a ServiceAccount (`AUTH PLAIN` /
  `LOGIN`); opt-in pod-IP fallback for SMTP clients that cannot authenticate
- **Policy:** sender allowlists (envelope and header), recipient domain and
  address allowlists and domain denylists, size and recipient limits,
  sliding-window rate limits per minute, hour and day (in-memory or Redis
  for multi-replica deployments)
- **Drivers:** SMTP (STARTTLS, PLAIN/LOGIN/CRAM-MD5); Microsoft Graph
  (app-only `sendMail`, v0.4.0) for Microsoft 365 without SMTP AUTH. The
  Gmail API is planned for v0.4.0; SendGrid is a reserved enum value, not
  implemented.
- **Observability:** structured slog (JSON), separate audit stream,
  Prometheus metrics with optional `ServiceMonitor`, OpenTelemetry tracing

See [`docs/SPEC.md`](docs/SPEC.md) for the full specification, roadmap and
known gaps.

## Install

```sh
# 1. cert-manager is required for the validating webhook serving cert.
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.1/cert-manager.yaml

# 2. Install the chart.
helm install sigillum ./charts/sigillum \
  --namespace sigillum-system --create-namespace \
  --set webhook.certificate.useCertManager=true
```

Without cert-manager, add `--set webhook.enabled=false` instead: the
controller and the gateway then apply the admission rules themselves (see
[`examples/local-dev/`](examples/local-dev/)). To keep the webhook with your
own certificate, create the Secret `sigillum-webhook-tls` (`tls.crt`,
`tls.key`, and `ca.crt` or `--set webhook.certificate.caBundle=<base64 CA
PEM>`) first. A webhook without a trusted certificate would block every
Sigillum resource, so `helm install` refuses it.

## Quickstart

Point Sigillum at an SMTP relay and authorize a workload to send mail through it.

```yaml
# 1. Credentials for the upstream relay (omit for unauth relays).
apiVersion: v1
kind: Secret
metadata:
  name: corporate-smtp-credentials
  namespace: sigillum-system
type: Opaque
stringData:
  username: sigillum
  password: <relay-password>
---
# 2. A cluster-scoped backend pointing at the relay.
apiVersion: sigillum.dev/v1alpha1
kind: ClusterMailBackend
metadata:
  name: corporate-smtp
spec:
  type: smtp
  smtp:
    endpoints:
      - { host: smtp.example.com, port: 587, tls: starttls }
    authType: PLAIN
    credentialsRef:
      name: corporate-smtp-credentials
      namespace: sigillum-system
    # optional, for a relay certificate from a private CA: PEM CA
    # certificates trusted in addition to the system roots (key ca.crt)
    # caSecretRef: { name: corporate-ca, namespace: sigillum-system }
  # optional: the relay sends only for these. "*@example.com" does not
  # cover subdomains, so list every domain the policies use.
  allowedSenders: ["*@example.com", "*@billing.example.com", "*@monitoring.example.com"]
---
# 3. A namespace-scoped policy binding a ServiceAccount to that backend.
apiVersion: sigillum.dev/v1alpha1
kind: MailPolicy
metadata:
  name: default
  namespace: my-team
spec:
  priority: 100
  subjects:
    - serviceAccount: { name: billing-mailer }
  backendRef: { name: corporate-smtp, kind: ClusterMailBackend }
  senderRestrictions:
    allowedSenders: ["noreply@example.com", "*@billing.example.com"]
  recipientRestrictions:
    allowedDomains: ["example.com", "customer.example.com"]  # every mailbox in these domains
    allowedRecipients: ["alerts@partner.example.org", "*@oncall.example.com"]  # plus single mailboxes / globs
    blockedDomains: []            # denylist wins over both allowlists
  messageLimits:
    maxRecipients: 50
  rateLimits:
    messagesPerMinute: 60
    messagesPerHour: 1000
    messagesPerDay: 5000          # stay below the upstream mailbox's daily quota
```

Mount a projected token with audience `sigillum` in the workload pod, then:

```sh
TOKEN=$(cat /var/run/secrets/tokens/sigillum)
curl -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"from":"noreply@example.com","to":["dev@example.com"],"subject":"hi","body":{"text":"hello"}}' \
     http://sigillum-api.sigillum-system.svc:8443/v1/messages
```

A successful send returns `202 Accepted` with a `messageId` and the name of the
matched policy. All errors use [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807).

### SMTP (legacy workloads)

Enable the proxy with `--set smtp.enabled=true`. Clients authenticate with
`AUTH OAUTHBEARER` using the same projected token as the REST path:

```text
host: sigillum-smtp.sigillum-system.svc   port: 587
AUTH OAUTHBEARER base64("n,a=<any>,\x01auth=Bearer <token>\x01\x01")
```

Both the envelope sender (`MAIL FROM`) and the header `From` must satisfy
`allowedSenders`; recipients are checked against the envelope (`RCPT TO`).
Messages need exactly one `From` field, and the null sender `<>` is refused.
`Bcc:` header fields are removed before relaying. `maxSizeBytes` ignores
transfer-encoding overhead (an 8 MiB attachment counts as 8 MiB, as on the
REST path); headers and MIME framing count on SMTP.
Policy denials answer `550`, rate limits `421`, retryable upstream problems
`451`, permanent upstream rejections `554`. The message is relayed byte-for-byte with a `Received` header that
carries the Sigillum message id.

### SMTP credentials for off-the-shelf apps

Grafana, Alertmanager, Gitea, Nextcloud, Keycloak and most other
third-party software only take an SMTP username and password. Enable
`smtp.authModes: [oauthbearer, credential]` (and STARTTLS via
`smtp.tls.secretName`), then commit a `MailCredential` next to the app's
`MailPolicy`:

```yaml
apiVersion: sigillum.dev/v1alpha1
kind: MailCredential
metadata:
  name: grafana
  namespace: monitoring
spec:
  serviceAccountName: grafana    # the identity policies see
  secretName: grafana-smtp       # created by the controller
  rotation:
    interval: 90d                # optional; or annotate sigillum.dev/rotate=<anything new>
    gracePeriod: 24h             # the previous password keeps working this long
```

The controller writes a random 256-bit password into the Secret
`grafana-smtp` (`username`, `password`, `host`, `port`) and stores only its
hash; nothing secret goes into Git. The app logs in as
`grafana.monitoring` and is then treated exactly like the `grafana`
ServiceAccount. Deleting the `MailCredential` revokes it immediately. Teams
that bring their own Secret set `spec.passwordHash` (argon2id) instead of
`secretName`.

The controller may write
Secrets in any namespace except `credentials.excludeNamespaces` (default
`kube-*`) and the release namespace, and the chart confines that permission
with a `ValidatingAdmissionPolicy` guard that only admits labelled Secrets
owned by a `MailCredential`. The controller checks the guard and writes
nothing while it is missing or changed. Passwords are only accepted over
STARTTLS unless `smtp.allowInsecureAuth: true`. Per-app settings and TLS
advice: [`examples/clients/`](examples/clients/).

For clients that cannot do SASL at all, `smtp.authModes: [oauthbearer, podip]`
identifies them by source pod IP. This is deliberately weak: it only matches
policies that set `legacyAuth.podIPFallback: true` (flagged by the
`UsingLegacyAuth` condition), and `podSelector` subjects apply only to such
callers. STARTTLS is offered when `smtp.tls.secretName` is set.

## Operations

| Concern | Setting |
|---|---|
| Multi-replica rate limits | `rateLimit.backend=redis`, `rateLimit.redis.addrs`, optional `masterName` (Sentinel) and `existingSecret`. Fails closed (`503`) when Redis is down unless `rateLimit.failOpen=true`. |
| Audit stream | One JSON line per request (accepted or rejected) on stdout, tagged `"stream":"audit"`; `audit.output: stdout\|stderr\|none`. Never contains subject or body. |
| Tracing | `tracing.endpoint` (OTLP/HTTP, e.g. `http://otel-collector:4318`) plus the standard `OTEL_*` variables. Spans: `http.request` → `auth.tokenreview`, `policy.evaluate`, `ratelimit.allow`, `backend.send`. |
| Several clusters | `clusterName: prod-eu` adds a `cluster` field to every audit record and log line and a `cluster` target label to the ServiceMonitor. |
| Rolling updates | On SIGTERM a pod fails readiness for `shutdownDelay` (5s) while still serving, then drains for up to `shutdownTimeout` (25s); `terminationGracePeriodSeconds` is 35. |
| Upstream errors (REST) | `502 upstream-error` is transient, retry with backoff; `422 upstream-rejected` means the relay refused this message for good. |
| Backend credentials in other namespaces | List them in `rbac.allowedSecretNamespaces`; components only read Secrets there and in the release namespace. |

## Recipes

[`examples/`](examples/) holds tested configurations of standard tools
rather than more Sigillum features: a local-development profile with
Mailpit, NetworkPolicy/Cilium rules that block direct SMTP egress so
Sigillum cannot be bypassed, admission policies (ValidatingAdmissionPolicy
and Kyverno) for policy authors, backends for Microsoft 365 (including the
options that survive the retirement of SMTP AUTH passwords), Azure
Communication Services, Google Workspace, Amazon SES, Mailgun, Postmark and
Brevo, MailCredential setups for common apps, and a Stakater Reloader recipe
for credential rotation.

## Upgrading

Helm installs CRDs only on first install. Apply them before upgrading the
release:

```sh
kubectl apply --server-side -f charts/sigillum/crds/
helm upgrade sigillum ./charts/sigillum -n sigillum-system --reuse-values
```

All changes per release: [`CHANGELOG.md`](CHANGELOG.md) (also the notes of
each [GitHub Release](https://github.com/se-wo/sigillum/releases)). Changes in
0.3.0 that may need attention:

- New CRD `MailCredential`, new field `recipientRestrictions.allowedRecipients`.
  Apply the CRDs first. With the 0.2 CRDs the API server would drop
  `allowedRecipients` without an error, and a policy restricted only by it
  would allow every recipient that is not blocked. From 0.3.0 on, every
  component checks the installed CRDs at startup and refuses to start
  until they are updated, so the old pods keep serving.
- REST: permanent upstream rejections answer `422 upstream-rejected`
  instead of `502 upstream-error`; audit and metric reason
  `upstream_rejected` on both transports.
- The chart requires Kubernetes 1.32 or later (`kubeVersion`), the oldest
  version still in (LTS) support.
- With `credentials.enabled` (default), the controller gets cluster-wide
  `create`/`patch` on Secrets, confined by the credential Secret guard. Set
  `credentials.enabled=false` to opt out.
- Components now read Secrets only from the release namespace and
  `rbac.allowedSecretNamespaces` (a `MailBackend`'s credentials in another
  namespace need that namespace listed, as the RBAC already required).
- `terminationGracePeriodSeconds` is 35 for the api-server and SMTP proxy.

## Supply chain

Releases after v0.2.1 are built and published only by
[`release.yml`](.github/workflows/release.yml) from a `v*` tag. For each
release:

- the image (`ghcr.io/se-wo/sigillum`) and chart
  (`oci://ghcr.io/se-wo/charts/sigillum`) are signed keyless with cosign and
  carry a GitHub [artifact attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
  (SLSA build provenance), both tied to the release workflow's identity;
- the image also carries an SPDX SBOM and BuildKit provenance for each
  platform (the SBOMs are attached to the workflow run as well);
- base images are pinned by digest and all Actions by commit SHA.

Verify before deploying (replace `0.3.0` with the version):

```sh
# cosign signature (image; same for ghcr.io/se-wo/charts/sigillum)
cosign verify ghcr.io/se-wo/sigillum:0.3.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/se-wo/sigillum/\.github/workflows/release\.yml@refs/tags/v'

# build provenance
gh attestation verify oci://ghcr.io/se-wo/sigillum:0.3.0 --repo se-wo/sigillum \
  --signer-workflow se-wo/sigillum/.github/workflows/release.yml \
  --source-ref refs/tags/v0.3.0
gh attestation verify oci://ghcr.io/se-wo/charts/sigillum:0.3.0 --repo se-wo/sigillum \
  --signer-workflow se-wo/sigillum/.github/workflows/release.yml \
  --source-ref refs/tags/v0.3.0

# SBOM for one platform
docker buildx imagetools inspect ghcr.io/se-wo/sigillum:0.3.0 \
  --format '{{ json (index .SBOM "linux/amd64").SPDX }}'
```

In CI, `govulncheck` fails the build on known vulnerabilities that the code
actually reaches, dependency review blocks PRs that add vulnerable
dependencies, and CodeQL scans the Go code and the workflows. actionlint and
zizmor check the workflows and local actions for mistakes and security issues
([`lint-actions.yml`](.github/workflows/lint-actions.yml)). Go's native
fuzzer exercises the parsers of SMTP and REST input on every PR and daily
([`fuzz.yml`](.github/workflows/fuzz.yml)). Dependabot
opens weekly update PRs for Go modules, Actions and base images, after a
7-day cooldown; security updates skip the cooldown. See
[SECURITY.md](SECURITY.md) to report a vulnerability.

## Development

```sh
make build              # compile bin/sigillum
make manifests generate # regenerate CRDs + deepcopy
make test               # unit + envtest suite
make vulncheck          # govulncheck against the Go vulnerability database
make e2e                # kind + Mailpit smoke (needs docker)
```

## Layout

```
cmd/sigillum/                  # single entrypoint, --mode=api|controller|smtp
api/v1alpha1/                  # CRD types + generated deepcopy
internal/driver/               # Driver interface + registry
internal/driver/smtp/          # SMTP driver (STARTTLS, PLAIN/LOGIN/CRAM-MD5, MIME)
internal/driver/graph/         # Microsoft Graph driver, app-only sendMail (v0.4.0)
internal/oauth/                # OAuth 2.0 token sources and cache for API backends (v0.4.0, not wired yet)
internal/policy/               # priority+tiebreak engine, sliding-window rate limit (memory, Redis)
internal/credential/           # MailCredential usernames, hashing, verification, Secret guard
internal/gateway/              # transport-agnostic send pipeline shared by REST and SMTP
internal/apiserver/            # chi router, TokenReview auth, RFC-7807 problems
internal/smtpproxy/            # SMTP submission proxy (OAUTHBEARER, PLAIN/LOGIN credentials, pod-IP fallback)
internal/audit/                # audit stream
internal/controller/           # MailBackend / ClusterMailBackend / MailPolicy / MailCredential reconcilers
internal/webhook/              # ValidatingWebhook for all four CRDs
internal/telemetry/            # slog JSON logger, Prometheus registry, OpenTelemetry
config/{crd,rbac,webhook}/     # generated manifests
charts/sigillum/               # Helm chart (CRDs in crds/, api + controller + optional smtp)
examples/                      # recipes: local dev, egress, admission, providers, clients, Reloader
test/chart/, test/examples/    # chart rendering and recipe checks (helm, envtest)
test/e2e/                      # kind + Mailpit end-to-end suite
```

## Not yet implemented

Next up: Microsoft 365, Outlook.com and Gmail without passwords (v0.4.0,
before Microsoft switches off SMTP AUTH with passwords and app passwords at
the end of December 2026): OAuth (XOAUTH2) for the SMTP driver with a
one-time sign-in for Outlook.com and a Gmail API driver for Google
Workspace and personal Gmail. The daily limit, the sender allowlist per
backend and the Microsoft Graph driver for Microsoft 365 are done. Then install without
cert-manager, preflight and a `kubectl` plugin (including
`credential create` / `rotate`), SMTPS on port 465, an OpenAPI
description, dashboards and alerts (v0.5.0). Sigillum stays below 1.0
until it has production users. See the roadmap and feature decisions in
[`docs/SPEC.md`](docs/SPEC.md#8-roadmap).

## License

[MIT](LICENSE)

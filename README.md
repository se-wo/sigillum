# Sigillum

Kubernetes-native, policy-enforced mail gateway. Workloads authenticate with
their ServiceAccount token, POST JSON to the api-server, and Sigillum applies a
declarative `MailPolicy` (sender/recipient allowlists, size limits, rate limits)
before forwarding through a `MailBackend` (SMTP) relay.

- **Custom resources:** `MailBackend`, `ClusterMailBackend`, `MailPolicy`
- **Transports:** REST (`POST /v1/messages`) and an optional SMTP submission
  proxy for legacy workloads
- **Auth:** projected ServiceAccount tokens, verified via `TokenReview`
  (REST: `Authorization: Bearer`, SMTP: `AUTH OAUTHBEARER`); opt-in pod-IP
  fallback for SMTP clients that cannot authenticate
- **Policy:** sender allowlists (envelope and header), recipient domain
  allow/denylists, size and recipient limits, sliding-window rate limits
  (in-memory or Redis for multi-replica deployments)
- **Drivers:** SMTP (STARTTLS, PLAIN/LOGIN/CRAM-MD5). Microsoft
  Graph / SendGrid / Gmail are reserved enum values, not implemented.
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
  recipientRestrictions:         # domain-wide: every mailbox in a listed domain
    allowedDomains: ["example.com", "customer.example.com"]
    blockedDomains: []            # denylist wins over allowlist
  messageLimits:
    maxRecipients: 50
  rateLimits:
    messagesPerMinute: 60
    messagesPerHour: 1000
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
`451`. The message is relayed byte-for-byte with a `Received` header that
carries the Sigillum message id.

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
gh attestation verify oci://ghcr.io/se-wo/sigillum:0.3.0 --repo se-wo/sigillum
gh attestation verify oci://ghcr.io/se-wo/charts/sigillum:0.3.0 --repo se-wo/sigillum

# SBOM for one platform
docker buildx imagetools inspect ghcr.io/se-wo/sigillum:0.3.0 \
  --format '{{ json (index .SBOM "linux/amd64").SPDX }}'
```

In CI, `govulncheck` fails the build on known vulnerabilities that the code
actually reaches, dependency review blocks PRs that add vulnerable
dependencies, and CodeQL scans the Go code and the workflows. Dependabot
opens weekly update PRs for Go modules, Actions and base images, after a
7-day cooldown; security updates skip the cooldown. See
[SECURITY.md](SECURITY.md) to report a vulnerability.

## Development

```sh
make build              # compile bin/sigillum
make manifests generate # regenerate CRDs + deepcopy
make test               # unit + envtest suite
make vulncheck          # govulncheck against the Go vulnerability database
make e2e                # kind + MailHog smoke (needs docker)
```

## Layout

```
cmd/sigillum/                  # single entrypoint, --mode=api|controller|smtp
api/v1alpha1/                  # CRD types + generated deepcopy
internal/driver/               # Driver interface + registry
internal/driver/smtp/          # SMTP driver (STARTTLS, PLAIN/LOGIN/CRAM-MD5, MIME)
internal/policy/               # priority+tiebreak engine, sliding-window rate limit (memory, Redis)
internal/gateway/              # transport-agnostic send pipeline shared by REST and SMTP
internal/apiserver/            # chi router, TokenReview auth, RFC-7807 problems
internal/smtpproxy/            # SMTP submission proxy (OAUTHBEARER, pod-IP fallback)
internal/audit/                # audit stream
internal/controller/           # MailBackend / ClusterMailBackend / MailPolicy reconcilers
internal/webhook/              # ValidatingWebhook for all three CRDs
internal/telemetry/            # slog JSON logger, Prometheus registry, OpenTelemetry
config/{crd,rbac,webhook}/     # generated manifests
charts/sigillum/               # Helm chart (CRDs in crds/, api + controller + optional smtp)
```

## Not yet implemented

Istio mTLS auth, `MailQuota`, `/v1/policies/preflight`, Grafana dashboards
and runbooks (planned for v0.3.0); Microsoft Graph / SendGrid / Gmail
drivers, read-path, IMAP-proxy, webhook-receiver. The CRD shape and `Driver` interface stay
wide enough to add each of these without breaking changes.

## License

[MIT](LICENSE)

# Sigillum

Kubernetes-native, policy-enforced mail gateway. Workloads authenticate with
their ServiceAccount token, POST JSON to the api-server, and Sigillum applies a
declarative `MailPolicy` (sender/recipient allowlists, size limits, rate limits)
before forwarding through a `MailBackend` (SMTP) relay.

- **Custom resources:** `MailBackend`, `ClusterMailBackend`, `MailPolicy`
- **Auth:** projected ServiceAccount tokens, verified via `TokenReview`
- **Drivers (v0.1.0):** SMTP (STARTTLS, PLAIN/LOGIN/CRAM-MD5). Microsoft
  Graph / SendGrid / Gmail are reserved enum values, not implemented.
- **Observability:** structured slog (JSON), Prometheus metrics, optional
  `ServiceMonitor`

See [`docs/SPEC.md`](docs/SPEC.md) for the full specification and
[`docs/PLAN.md`](docs/PLAN.md) for the v0.1.0 implementation plan.

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
  recipientRestrictions:
    maxRecipients: 50
  rateLimit:
    perMinute: 60
    perHour: 1000
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

## Development

```sh
make build              # compile bin/sigillum
make manifests generate # regenerate CRDs + deepcopy
make test               # unit + envtest suite
make e2e                # kind + MailHog smoke (needs docker)
```

## Layout

```
cmd/sigillum/                  # single entrypoint, --mode=api|controller
api/v1alpha1/                  # CRD types + generated deepcopy
internal/driver/               # Driver interface + registry
internal/driver/smtp/          # SMTP driver (STARTTLS, PLAIN/LOGIN/CRAM-MD5, MIME)
internal/policy/               # priority+tiebreak engine, sliding-window rate limit
internal/apiserver/            # chi router, TokenReview auth, RFC-7807 problems
internal/controller/           # MailBackend / ClusterMailBackend / MailPolicy reconcilers
internal/webhook/              # ValidatingWebhook for all three CRDs
internal/telemetry/            # slog JSON logger + Prometheus registry
config/{crd,rbac,webhook}/     # generated manifests
charts/sigillum/               # Helm chart (CRDs in crds/, two Deployments)
```

## Out of scope (v0.1.0)

SMTP-proxy, Redis rate limit, recipient allow/denylist, OTel tracing,
Istio mTLS / SASL OAUTHBEARER, `MailQuota`, `/v1/policies/preflight`,
audit-log stream, Microsoft Graph / SendGrid / Gmail drivers, read-path,
IMAP-proxy, webhook-receiver. The CRD shape and `Driver` interface stay
wide enough to add each of these without breaking changes.

## License

[MIT](LICENSE)

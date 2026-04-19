# Sigillum

Kubernetes-native, policy-enforced mail gateway. v0.1.0 ships the REST send
path, the `MailBackend` / `ClusterMailBackend` / `MailPolicy` CRDs (with the
SMTP driver implemented and Microsoft Graph / SendGrid / Gmail reserved as
schema enum values), an in-memory rate limiter, structured slog logs and
Prometheus metrics, packaged as a single image with two start modes
(`--mode=api` / `--mode=controller`) and a Helm chart.

See [`docs/SPEC.md`](docs/SPEC.md) for the full specification and
[`docs/PLAN.md`](docs/PLAN.md) for the v0.1.0 implementation plan.

## Quickstart

```sh
make build
make manifests generate
make docker-build
make e2e         # requires kind + helm + docker
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

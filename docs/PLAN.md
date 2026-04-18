# Sigillum v0.1.0 — Implementation Plan (MVP)

## Context

The repo is greenfield (LICENSE only, single initial commit). The spec defines the full product surface, but §8.1 explicitly scopes v0.1.0 to the core "developer sends via REST, policy enforced" loop. This plan covers exactly that slice — enough to be usable end-to-end in a cluster (REST send path + policy + CRDs + controller + Helm chart), while keeping the CRD shape and Driver interface wide enough for the future backends and read-path described in §1.5 and §4.5. SMTP-proxy, Redis rate-limit, Istio mTLS, audit stream, and tracing are deliberately excluded — they land in v0.2/v0.3 per the roadmap.

**Assumed defaults**: Go module path `github.com/se-wo/sigillum`, API group `sigillum.dev`, product name `Sigillum`. Single container image with two start modes (`--mode=api`, `--mode=controller`) to keep release artifacts minimal per spec §4.2.

## Repository layout

```
cmd/sigillum/main.go                        # single entrypoint, --mode=api|controller
api/v1alpha1/
    groupversion_info.go
    mailbackend_types.go
    clustermailbackend_types.go
    mailpolicy_types.go
    zz_generated.deepcopy.go
internal/driver/
    driver.go
    registry.go
    smtp/smtp.go
internal/policy/
    engine.go
    ratelimit/
        ratelimit.go
        memory.go
internal/apiserver/
    server.go
    messages.go
    health.go
    auth/tokenreview.go
    problem/problem.go
internal/controller/
    mailbackend_controller.go
    clustermailbackend_controller.go
    mailpolicy_controller.go
    probe.go
internal/webhook/
    mailbackend_webhook.go
    mailpolicy_webhook.go
internal/telemetry/
    logging.go
    metrics.go
config/crd/bases/
config/webhook/
config/rbac/
charts/sigillum/
    Chart.yaml
    values.yaml
    crds/
    templates/
Dockerfile
Makefile
.github/workflows/ci.yml
```

## Phase summary

1. **Scaffolding** — go.mod, Makefile, CI.
2. **API types** — MailBackend / ClusterMailBackend / MailPolicy in v1alpha1 with full spec from §4.3, only `type: smtp` accepted in v1 webhook.
3. **Driver interface** — Send-only in v1; Read/Subscribe kept off interface until a Read-capable driver exists. SMTP driver with STARTTLS, PLAIN/LOGIN auth, MIME multipart assembly.
4. **Controller + ValidatingWebhook** — Reconcile backends with periodic HealthCheck, update status/conditions/capabilities. Webhook rejects unknown backend types, empty endpoints, missing subjects.
5. **api-server** — chi router, TokenReview + LRU cache, policy engine (priority + alphabetic tiebreak, default-deny), in-memory sliding-window rate-limit, RFC 7807 errors, graceful shutdown, Prometheus metrics, slog JSON logs.
6. **Packaging** — distroless/static image, Helm chart with two Deployments sharing one image, CRDs in chart-level `crds/` dir, least-privilege RBAC, PDB, restricted SecurityContext, ServiceMonitor.
7. **Tests** — unit (engine, ratelimiter, MIME), envtest (reconcilers + webhook), kind E2E against MailHog.

## Out of scope (per §8)

SMTP-proxy, Redis rate-limit, recipient allow/denylists, OTel, Istio mTLS / SASL OAUTHBEARER, `MailQuota`, `/v1/policies/preflight`, audit-log stream, Grafana dashboards, Microsoft Graph / SendGrid / Gmail drivers, read-path, IMAP-proxy, webhook-receiver. CRD shape and `Driver` interface stay wide enough for each of these to be additive.

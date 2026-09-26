# Changelog

All notable changes to Sigillum are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) with the pre-1.0 rules in
[`docs/SPEC.md`](docs/SPEC.md#8-roadmap) §8.0: minor releases may change CRDs
with a documented migration, patch releases never do.

The section of a version becomes the notes of its GitHub Release
(`hack/release-notes.sh`, run by the release workflow). Add entries under
the version being prepared in the same pull request as the change.

## [0.3.0] - 2026-09-26

Works with off-the-shelf apps and cannot be bypassed (SPEC §8.2).

### Upgrading

- Helm installs CRDs only on first install. Apply them before upgrading:
  `kubectl apply --server-side -f charts/sigillum/crds/`. With the 0.2
  CRDs the API server drops `allowedRecipients` without an error (a
  server-side apply only warns), and a policy restricted only by it would
  allow every recipient that is not blocked. The 0.3.0 pods therefore
  refuse to start until the CRDs are updated; the old pods keep serving.
- REST: a permanent upstream rejection now answers `422 upstream-rejected`
  instead of `502 upstream-error`. Audit and metric reason
  `upstream_rejected` on both transports (was `upstream_error`).
- Kubernetes 1.32 or later is required (chart `kubeVersion`), the oldest
  version still in (LTS) support. Older versions are out of support, and
  the credential Secret guard needs `ValidatingAdmissionPolicy`.
- With `credentials.enabled` (the default), the controller gets
  cluster-wide `create`/`patch` on Secrets, confined by the credential
  Secret guard. Set `credentials.enabled=false` to opt out.
- Components read Secrets only from the release namespace and
  `rbac.allowedSecretNamespaces`.
- `terminationGracePeriodSeconds` is 35 (was 30) for the api-server and
  SMTP proxy.
- The SMTP proxy's default memory limit is 512Mi (was 256Mi): besides
  message buffers it now budgets for two concurrent argon2id checks of up
  to 64 MiB each (`values.yaml` explains the budget).

### Added

- `MailCredential`: SMTP username (`<name>.<namespace>`) and password bound
  to one ServiceAccount, for apps that only speak `AUTH PLAIN`/`LOGIN`
  (US-3.7).
  - Generated mode: the controller writes a 256-bit random password into a
    Secret (`username`, `password`, `host`, `port`) and stores only its
    SHA-256.
  - Rotation on `spec.rotation.interval` or on demand
    (`sigillum.dev/rotate`), with a grace period for the previous password.
  - Bring-your-own-hash mode with an argon2id `spec.passwordHash`.
  - The aggregated `edit` and `admin` roles cover `MailCredential`; `view`
    does not, so viewers cannot read a bring-your-own password hash.
- SMTP proxy auth mode `credential` (`AUTH PLAIN`, `AUTH LOGIN`), offered
  only over STARTTLS unless `smtp.allowInsecureAuth: true`. Failed logins
  are audited; failed logins of bring-your-own-hash credentials are
  throttled per username and source IP. Deleting a `MailCredential` also
  ends open sessions (`454 4.7.0`, so a message queued before a rotation
  is retried with the new password instead of bouncing). A spec edit
  does not interrupt logins while the controller catches up, except a
  changed ServiceAccount or password hash, which takes effect once
  accepted.
- Credential Secret guard: a `ValidatingAdmissionPolicy` that confines the
  controller's Secret writes to `Opaque` credential Secrets outside
  excluded namespaces. The controller verifies it and writes nothing while it is
  missing or changed (`SecretsManaged` condition,
  `sigillum_credential_guard_ok` metric).
- `recipientRestrictions.allowedRecipients`: exact mailboxes and globs
  anchored on a domain (`*@oncall.example.com`), matched like
  `allowedSenders` (US-2.4, #6).
- `--cluster-name` / chart `clusterName`: `cluster` field in audit records
  and logs, `cluster` target label on the ServiceMonitor (US-4.5).
- Audit fields `credential`, `credential_previous` and `cluster`; reasons
  `invalid_credentials`, `auth_rate_limited`, `auth_unavailable`,
  `upstream_rejected`.
- Metric `sigillum_auth_failures_total`. A failed TokenReview (kube-apiserver
  unreachable) counts as `auth_unavailable`, not `invalid_token`, and
  answers `503 unavailable` (REST) or `454 4.7.0` (SMTP) instead of an
  authentication failure.
- `--shutdown-delay` (chart `api.shutdownDelay`, `smtp.shutdownDelay`).
- Startup check of the installed CRDs: every component exits with an
  error naming the missing kinds and fields when the CRDs are older than
  the binary (`--skip-crd-check` to turn it off).
- Recipes in `examples/`: local development with Mailpit, egress blocking
  (NetworkPolicy, Kyverno, Cilium), admission guardrails
  (ValidatingAdmissionPolicy, Kyverno), provider backends (Microsoft 365
  via SMTP AUTH, relay connector or High Volume Email, Azure Communication
  Services, Google Workspace, Amazon SES, Mailgun, Postmark, Brevo, with
  the state of password logins per provider), MailCredential setups for
  Grafana, Alertmanager, Gitea, Nextcloud, Keycloak and Argo CD
  notifications, and Stakater Reloader for rotations.
- Release: images and charts are signed keyless with cosign and carry SLSA
  build provenance; images carry SPDX SBOMs (README, "Supply chain").
  GitHub Releases with notes from this file.

### Changed

- REST distinguishes permanent (`422 upstream-rejected`) from transient
  (`502 upstream-error`) upstream failures (gap G-1).
- On SIGTERM, pods fail readiness for the shutdown delay while still
  serving, then drain (gap G-3).
- `Received` header protocol follows RFC 3848 (`ESMTPA`, `ESMTPSA`).
- End-to-end tests use Mailpit instead of MailHog.

### Fixed

- The Secret informer was cluster-wide while the chart only grants
  namespaced Secret RBAC, so reading a backend's credentials Secret could
  hang. It is now limited to the readable namespaces
  (`--secret-namespaces`).
- Webhook registration with the controller-runtime v0.25 typed builder.

### Security

- TokenReview cache entries no longer outlive the token's `exp` claim
  (gap G-5).
- A namespaced `MailBackend` can only use a credentials Secret of its own
  namespace, now also enforced at runtime and not only by the webhook, so
  it cannot read the relay credentials when the webhook is disabled.
- gRPC updated to v1.83.2 (GHSA-2v4p-qf9q-27wj).

## [0.2.1] - 2026-09-26

Security patch release addressing the findings of the whitebox review.

### Security

- Local parts with routing semantics (`%`, `!`, quoted local parts) are
  rejected on the REST and SMTP paths and again in policy evaluation; an
  upstream MTA honouring them could otherwise deliver to another domain.
- Display names, comments and encoded-words containing `@` are rejected in
  `From`, `Sender` and `Reply-To`.
- The `Sender` header is checked against `allowedSenders`, `Reply-To`
  against `recipientRestrictions`. `Resent-*` fields and duplicate
  `From`/`Sender`/`Reply-To` fields (SMTP) or header keys (REST) are
  rejected.

### Changed

- REST size accounting includes the subject and custom headers; header
  values are limited to 998 characters.
- Helm: `smtp.allowInsecureAuth` follows `smtp.tls.secretName` by default;
  NOTES warn about plaintext operation and `rateLimit.failOpen`.

## [0.2.0] - 2026-09-26

### Added

- SMTP submission proxy (`--mode=smtp`) with `AUTH OAUTHBEARER` and an
  opt-in pod-IP fallback (`legacyAuth.podIPFallback`) (US-1.2, US-3.4,
  US-3.5).
- Redis-backed rate limiting for multi-replica deployments (single node,
  Sentinel, Cluster), failing closed by default.
- Audit log stream and a transport-agnostic gateway pipeline shared by
  REST and SMTP (US-4.3).
- Recipient domain allow/denylists (US-2.4).
- OpenTelemetry tracing (US-4.4).

### Fixed

- `serviceAccountSelector` subjects: matching fixed, and fail closed when
  the ServiceAccount lookup fails.
- Messages with more than one `From` field and the null sender are
  refused; SMTP size limits cannot be bypassed with MIME padding; `Bcc`
  header fields are stripped before relaying.
- Only a 5xx reply to MAIL, RCPT or DATA counts as a permanent upstream
  error; transient failures refund the rate-limit charge.

### Security

- TokenReview `status.audiences` is verified, so tokens for the
  kube-apiserver are not accepted (also in 0.1.1).

## [0.1.1] - 2026-09-26

### Security

- Verify TokenReview `status.audiences`: an audience-unaware authenticator
  could otherwise make Sigillum accept a kube-apiserver token.

### Fixed

- Release workflow: no third-party actions, cross-compiled multi-arch
  images, dry runs on pull requests.

## [0.1.0] - 2026-04-21

First release (MVP).

### Added

- `POST /v1/messages` with attachments (JSON and multipart).
- ServiceAccount token authentication via TokenReview.
- CRDs `MailBackend`, `ClusterMailBackend` and `MailPolicy` (`type: smtp`)
  with a validating webhook and a controller running backend health
  checks.
- Sender restrictions, in-memory rate limiting, message size and
  recipient limits.
- Prometheus metrics, structured JSON logs, Helm chart.

[0.3.0]: https://github.com/se-wo/sigillum/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/se-wo/sigillum/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/se-wo/sigillum/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/se-wo/sigillum/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/se-wo/sigillum/releases/tag/v0.1.0

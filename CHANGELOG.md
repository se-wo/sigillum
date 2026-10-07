# Changelog

All notable changes to Sigillum are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) with the pre-1.0 rules in
[`docs/SPEC.md`](docs/SPEC.md#8-roadmap) §8.0: minor releases may change CRDs
with a documented migration, patch releases never do.

The section of a version becomes the notes of its GitHub Release
(`hack/release-notes.sh`, run by the release workflow). Add entries under
the version being prepared in the same pull request as the change.

## [0.4.0] - unreleased

### Upgrading

- Apply the CRDs before upgrading:
  `kubectl apply --server-side -f charts/sigillum/crds/`. The 0.4.0 pods
  refuse to start on 0.3 CRDs, which would drop `messagesPerDay` and a
  backend's `allowedSenders` without an error, leaving the policy without
  a daily cap and the backend unbounded.
- The credential Secret guard changes (it also admits the OAuth token
  Secrets of delegated backends). Upgrade the chart and the controller
  together with `helm upgrade`. While the old guard and a new
  controller, or the new guard and an old controller, meet during the
  rollout, that controller reports the guard as changed and writes no
  generated credential Secrets (`SecretsManaged=False`) until the other
  side is updated; it re-checks every 30 s.
- REST: `POST /v1/messages` now rejects unknown JSON fields and messages
  without content with `400 invalid-payload` (see Changed). Check that
  clients send only the documented fields.
- Policies and backends are now checked against the admission rules
  outside the webhook too (see Fixed). One created without the webhook,
  or admitted by an older version with laxer rules, turns `Ready=False`
  (`InvalidConfiguration`) and is no longer used: after the upgrade, run
  `kubectl get mailpolicies,mailbackends,clustermailbackends -A` and fix
  any that are not Ready.

### Added

- `sigillum_smtp_messages_in_flight{namespace}` metric and the
  `smtp.maxConcurrentPerTenant` setting (see Fixed, #73).
- `sigillum_upstream_auth_failures_total{backend}` metric (see Fixed, #58).
- `spec.smtp.caSecretRef` on `MailBackend` and `ClusterMailBackend`: PEM
  CA certificates (key `ca.crt` by default) trusted in addition to the
  system roots, for relays with a certificate from a private CA. Before,
  such a relay only worked with `tls: none`, which sends the relay
  password in cleartext. The Secret follows the namespace rules of
  `credentialsRef`; the probe and every send use it (#57).
- `MailPolicy.spec.rateLimits.messagesPerDay`: a sliding 24-hour cap per
  policy, next to the per-minute and per-hour caps, to keep one workload
  from using up the daily quota of the upstream mailbox (US-2.7). With a
  daily cap, the in-memory store keeps a timestamp per message for a day
  and Redis keeps the counter key for a day.
- `MailBackend.spec.allowedSenders` and
  `ClusterMailBackend.spec.allowedSenders`: the senders a backend sends
  for, checked on every send in addition to the policy's
  `senderRestrictions` (`From`, envelope sender, `Sender`). A policy can
  narrow the list but never widen it, so a personal account is used only
  with its own address and a relay only for its domains (US-2.8).
  Violations answer `403 sender-not-allowed` (reason
  `sender_not_allowed`); the log names the backend. Entries must be plain
  addresses or globs anchored on a domain; an empty list denies every
  sender and draws a warning. The Gmail and Microsoft 365 recipes pin
  their backend to the mailbox.
- Microsoft Graph backend (`type: microsoftGraph`) for Microsoft 365 work
  and school accounts, app-only with an Entra application and
  `POST /users/{From}/sendMail`, so it needs no SMTP AUTH and keeps working
  after Basic auth for SMTP is switched off at the end of December 2026
  (US-6.1). `spec.microsoftGraph` holds `tenantID`, `clientID` and
  `credentialsRef` (key `client_secret`); `allowedSenders` is required.
  REST and the SMTP proxy both work. The delivered recipients always equal
  the checked envelope: a `To` or `Cc` address outside it is refused as
  `recipient_not_allowed`, blind copies go into `Bcc`. Messages up to 4 MB.
  The health check acquires a token, so a wrong secret shows as not ready.
  Recipe `examples/providers/microsoft-365-graph.yaml`, with RBAC for
  Applications to confine the app to its mailboxes.

### Changed

- Chart: `helm install` and `helm upgrade` fail with an explanation when
  the admission webhook is enabled (the default) without cert-manager
  (`webhook.certificate.useCertManager=false`, the default) and the
  serving-certificate Secret does not exist, or nothing names the CA that
  issued it. Before, the release installed "successfully", the controller
  crash-looped, and the webhook (`failurePolicy: Fail`) rejected every
  Sigillum resource in the cluster. Without cert-manager the chart now sets
  the webhook's `caBundle` from the new `webhook.certificate.caBundle`, else
  from `ca.crt` in the Secret, else keeps the one already on the object.
  The checks need a cluster connection, so `helm template` skips them
  (GitOps renders without cert-manager set `webhook.certificate.caBundle`);
  the NOTES warn whenever cert-manager is off, and the controller waits for
  a missing Secret instead of crash-looping (#40).
- REST: unknown fields in the JSON body (or the multipart `data` part)
  answer `400 invalid-payload` naming the field, with a hint for common
  slips (`did you mean body.text?`), and a message needs a non-blank
  `body.text` or `body.html`, or a non-empty attachment. Before, both were
  accepted with `202`, so a top-level `"text"` delivered an empty
  message. In a multipart request, Base64 `attachments` in the `data`
  part are now sent (they were dropped), and a plain form field named like
  a message field (`text`, `subject`, …) is refused instead of being
  mailed as a file (#42).
- `Retry-After` (REST) is the wait until every full window has room
  again, not only the shortest one; a caller retrying then is no longer
  rejected by the hourly or daily window right after.
- Credential Secret guard: a second allowed shape for the OAuth token
  Secrets of delegated backends (label `sigillum.dev/oauth-token`,
  annotation `sigillum.dev/oauth-token-uid`, controlled by the
  `MailBackend` or `ClusterMailBackend`, only the keys `refresh_token`,
  `access_token` and `expires_at`), also in the release namespace. Nothing
  writes such Secrets yet (US-6.3).

### Fixed

- One tenant's slow or hung relay could hold every SMTP relay slot
  (`smtp.maxConcurrentMessages`, shared across tenants) and stall every
  other tenant. A per-tenant cap (`smtp.maxConcurrentPerTenant`, default
  half the global cap) now bounds the messages one namespace relays at
  once, acquired before the global slot so a tenant at its cap holds no
  global slot others need. The new `sigillum_smtp_messages_in_flight`
  gauge reports it per namespace (#73).
- The backend health probe never checked authentication, so a relay that
  does not offer the configured SASL mechanism (for example `CRAM-MD5`
  against a relay that only offers `PLAIN`/`LOGIN`) showed `Ready=True`
  while every send failed. The probe now checks the relay advertises the
  configured `authType` in its `EHLO` `AUTH` list and reports
  `Ready=False` otherwise. It does not authenticate (a wrong password
  would otherwise risk locking the account out every probe interval); a
  wrong or rotated password now increments the new
  `sigillum_upstream_auth_failures_total` counter when sends fail (#58).
- A relay that caps the recipients of one transaction (`452 4.5.3 Too many
  recipients`: Exchange Online, Amazon SES, Postfix `smtpd_recipient_limit`)
  was treated as a transient error, so the message was retried forever and
  never delivered. It is now permanent: REST `422 upstream-rejected`, SMTP
  `554`, so the caller stops and sees the cause. Splitting the recipients
  into several transactions is left to the sender (#62).
- A namespace in `rbac.allowedSecretNamespaces` that does not exist (an
  offboarded team's namespace, or one listed before it is created) no longer
  fails `helm install`/`upgrade` with `namespaces "x" not found`. The
  per-namespace Secret-reader Role is skipped while the namespace is absent
  and created once it exists and the chart is upgraded; NOTES lists the
  skipped ones. `helm template` (no cluster connection) still renders every
  entry (#77).
- A relay endpoint that accepts connections but never answers no longer
  blocks failover. `connectionTimeoutSeconds` now bounds the dial and the
  handshake (banner, `EHLO`, `STARTTLS`, `AUTH`) of each endpoint, as its
  description said; before, only the dial was bounded and the rest ran
  under the whole 60 s send budget, so the next endpoint never got its
  turn over SMTP and every REST send took 60 s. Endpoints the last probe
  found unready are tried last. REST sends now finish within 50 s, below
  the server's 60 s write timeout: before, a message delivered after the
  timeout left the client with an empty reply, and a client that retried
  sent it twice (Graph backends too). A send still running at the deadline
  answers `502 upstream-error` (#61).
- The api-server and the SMTP proxy now pick up a renewed TLS certificate
  (`api.tls.secretName`, `smtp.tls.secretName`) within about a minute,
  without a restart. Before, they read it once at startup and kept
  serving the old certificate until it expired, so every certificate
  renewal (cert-manager renews after 60 of 90 days by default) ended in
  failed TLS handshakes unless the pods had been restarted (#75).
- Without the admission webhook (`webhook.enabled: false`, as in the
  local-dev profile), a `MailPolicy`, `MailBackend` or `ClusterMailBackend`
  that the webhook would reject was admitted, shown as Ready and enforced
  with whatever its malformed entries matched: `allowedRecipients: ["*"]`
  allowed every recipient. The controller now applies the webhook's rules
  and reports violations as `Ready=False` (`InvalidConfiguration`); the
  gateway refuses a request whose matching policy is invalid with
  `503 policy-invalid` (SMTP `451`, reason `policy_invalid`) instead of
  enforcing it, and treats an invalid backend as not ready, naming the
  field errors (#41).
- A message now leaves a rate-limit window the moment it is as old as the
  window. Before, a caller retrying exactly after `Retry-After` could be
  rejected once more.

## [0.3.1] - unreleased

### Fixed

- REST: display names in `from`, `to` and `cc` are quoted (or encoded)
  when relayed. A name containing `"`, `<` or `,` could end early and show
  an address in the `To` or `Cc` header that was never a recipient, or
  produce a header mail clients cannot parse.

### Added

- Continuous fuzzing of the SMTP, REST, address and credential parsers
  with Go's native fuzzer (`make fuzz`, `fuzz` workflow on PRs and daily).
- Static analysis of the GitHub Actions workflows and local actions with
  actionlint and zizmor (`make lint-actions`, `lint-actions` workflow on
  PRs and weekly).

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

[0.3.1]: https://github.com/se-wo/sigillum/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/se-wo/sigillum/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/se-wo/sigillum/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/se-wo/sigillum/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/se-wo/sigillum/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/se-wo/sigillum/releases/tag/v0.1.0

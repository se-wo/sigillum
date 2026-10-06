# Sigillum — Specification

*Policy-enforced mail gateway for Kubernetes*

| Field | Value |
|---|---|
| **Name** | Sigillum |
| **Spec version** | 0.3.0 (matches release v0.3.0) |
| **Status** | Living document. Each requirement carries its implementation status; the roadmap (§8) is prioritized for individuals and small and medium organizations. |
| **Author** | Sebastian (private OSS project) |
| **Audience** | Platform engineering (fictional). Private OSS project, inspired by real requirements. |
| **Purpose** | Functional and technical basis for implementation and review |

**Status markers.** Every user story and major section is tagged:

- **[v0.1.0]**, **[v0.2.0]**, **[v0.2.1]**, **[v0.3.0]**: implemented in that release. **[v0.4.0]**: implemented on `main` for the upcoming release.
- **[planned vX]**: scheduled on the roadmap (§8).
- **[backlog]**: candidate feature, not scheduled. Picked up when users ask for it (§8.8).
- **[future]**: architecturally anticipated for after 1.0, not scheduled.
- **[gap]**: specified behavior that the current release does not meet yet. All gaps are collected in §9.3.

---

## 1. Product vision

### 1.1 Problem statement

Many workloads in a Kubernetes cluster send mail: applications, CronJobs, operators, the monitoring stack. Typical content is transactional mail, notifications and reports. The status quo has three structural weaknesses:

1. **Credential sprawl.** Every workload carries its own SMTP credentials as a Secret. Rotation, audit and revocation are expensive and error-prone.
2. **No policy enforcement.** The central mail server accepts any sender address within the organization's domain. A compromised workload can send phishing mail under any internal identity.
3. **No observability or rate control.** There is no central view of mail volume per workload and no protection against runaway loops (for example, broken retry logic generating thousands of messages).

### 1.2 Vision

> **Sigillum is a Kubernetes-native mail gateway that provides secure, policy-controlled mail delivery for cluster workloads, without developers having to manage SMTP credentials.**

The gateway offers a REST API as its primary interface and an SMTP submission proxy for legacy integration. Policies are managed declaratively as custom resources and follow established Kubernetes conventions (GitOps, RBAC, namespaces). Authentication is Kubernetes-native, via ServiceAccount tokens (and, in future, Istio mTLS), not via separate API keys.

### 1.3 Business goals

| Goal | Measured as |
|---|---|
| Fewer managed mail credentials | One central credential configuration instead of N per workload |
| Compliance (BSI / NIS2) | Auditable sender attribution per message, complete audit log |
| Operational safety | Rate-limit enforcement prevents runaway sending |
| Developer experience | No credential management in workload code |

### 1.4 Non-goals

The following are explicitly **not** part of this product, now or later:

- **Mail storage or mailboxes on the Sigillum side.** Sigillum hosts no mailboxes. Read functionality (see §1.5) always goes through the backend, never through local storage.
- **Template engine.** Rendering is the workload's job.
- **Address resolution / distribution lists.** Recipient lists are the caller's responsibility.
- **DKIM / DMARC signing.** Done by the backend, not by Sigillum.
- **Relay for external senders.** Only in-cluster workloads are users.
- **Anti-spam / content filtering.** Out of scope.
- **Judging policy content.** Sigillum enforces `MailPolicy` objects; it does not decide whether a policy is appropriate. That is governance, owned by the platform team (see §4.9).

### 1.5 Not before 1.0, but architecturally anticipated **[future]**

These capabilities are not planned before 1.0, but the architecture must allow them without breaking changes to CRDs or the API:

- **Read path.** Mailbox access via backend-native APIs (IMAP, Microsoft Graph `Mail.Read`, Gmail API). Read support stays optional per backend.
- **Backend diversity.** Besides SMTP, API-based backends: Microsoft Graph (`Mail.Send` / `Mail.Read`), SendGrid, Gmail API. Each backend declares its capabilities; policies and the API surface respect them. Sending through Microsoft Graph and the Gmail API is pulled forward to v0.4.0 (US-6.1, US-6.2); reading stays after 1.0.
- **IMAP proxy for legacy readers.** Analogous to the SMTP proxy on the send path, an IMAP proxy could let legacy workloads read mailboxes whose backend is actually Graph or Gmail.

Consequence for the architecture today: CRDs, the driver interface and the capability model are shaped so these extensions are *additive*. No migration path and no new API groups are needed.

---

## 2. Personas

| Persona | Responsibility | Primary interaction |
|---|---|---|
| **Application developer (Dev)** | Builds workloads that send mail | REST API / SMTP client library |
| **Platform engineer (PE)** | Operates Sigillum, maintains backends, decides who may author policies | CRDs, Helm chart, RBAC / admission policy, metrics |
| **Security / compliance officer (SCO)** | Defines policy guardrails, audits usage | `MailPolicy`, admission rules, audit log |
| **Namespace owner / tenant admin** | Owns team namespaces | `MailPolicy` in their own namespace, **if** the platform team delegates that right (§4.9) |

---

## 3. User stories

User stories are grouped by epic. Each follows **As a \<role\> I want \<capability\>, so that \<benefit\>** and lists acceptance criteria.

### Epic 1 — Sending mail from workloads

#### US-1.1 — Send via REST **[v0.1.0]**
**As a** developer **I want** to send mail with an HTTP POST to Sigillum, **so that** I need neither an SMTP library nor credential handling.

*Acceptance criteria:*
- `POST /v1/messages` accepts a JSON payload with `from`, `to`, `cc`, `bcc`, `subject`, `body` (`text` / `html`), `attachments` and `headers` (§4.4.1).
- The response carries a `messageId` for correlation.
- The call is **synchronous**: `202 Accepted` means the upstream backend accepted the message (for SMTP: the relay answered `250` to `DATA`). Final delivery to the recipient happens asynchronously in the backend. Sigillum has no queue of its own (§4.7).
- Status codes follow the table in §4.4.3.

#### US-1.2 — SMTP proxy for legacy workloads **[v0.2.0]**
**As a** developer **I want** to keep using my legacy application's SMTP client, **so that** I don't have to refactor code, but with Kubernetes-native authentication instead of trusting pod IPs.

*Acceptance criteria:*
- The proxy accepts SMTP submission cluster-internally on Service port 587 (container port 2587, since the container runs unprivileged).
- It supports the submission flow (`MAIL FROM`, `RCPT TO`, `DATA`).
- Caller identification modes, configured per deployment (`--auth-modes`), in order of strength:
  1. **Istio mTLS**: identity from the SPIFFE ID (US-3.3). **[backlog]**
  2. **SASL OAUTHBEARER** (RFC 7628): ServiceAccount token over SASL (US-3.4). Default.
  3. **SASL PLAIN / LOGIN with a Sigillum-issued credential** (US-3.7), for clients that only support username and password. **[v0.3.0]**
  4. **Pod-IP lookup**: fallback, only effective for policies that opt in (US-3.5).
- STARTTLS is offered when a TLS secret is configured. Inside a service mesh, plain SMTP with mesh mTLS is the recommended setup.
- The proxy is a separate, optional deployment (`--mode=smtp`, chart value `smtp.enabled`) and can be left out of REST-only installations.
- Behavior details: §4.6.

#### US-1.3 — Attachments **[v0.1.0]**
**As a** developer **I want** to send attachments, **so that** I can mail reports as PDF.

*Acceptance criteria:*
- REST: attachments as Base64 in JSON, or as `multipart/form-data`.
- Size limit configurable per policy (`messageLimits.maxSizeBytes`, default 10 MiB). Counting rules: §4.4.4.
- Content type, file name and disposition (`attachment` or `inline`) are preserved.

#### US-1.4 — Transparent errors **[v0.1.0]**
**As a** developer **I want** clear error messages, **so that** I know whether to retry or whether my payload is wrong.

*Acceptance criteria:*
- Errors use RFC 7807 Problem Details (`application/problem+json`).
- Whether a request may be retried is defined per status code in §4.4.3. It is **not** "4xx = never retry, 5xx = always retry": `429` is retryable. Upstream failures are split since v0.3.0: `502 upstream-error` is transient (retry), `422 upstream-rejected` is a permanent rejection of this message by the relay (do not retry unchanged).
- Policy denials name the policy that denied the request (`policy` field).

#### US-1.5 — SMTPS (implicit TLS) on the proxy **[planned v0.5.0]**
**As a** developer **I want** the SMTP proxy to accept implicit TLS on port 465, **so that** applications that only offer "SSL/TLS" (not STARTTLS) can use it.

*Acceptance criteria:*
- Optional second listener with implicit TLS, using the same certificate as STARTTLS (`smtp.tls.secretName`); Service port 465.
- Same authentication, policy and reply behavior as port 587.

#### US-1.6 — Idempotent submission **[planned v0.6.0]**
**As a** developer **I want** to retry a send safely after a timeout or `502`, **so that** recipients don't get the same message twice.

*Acceptance criteria:*
- `POST /v1/messages` accepts an `Idempotency-Key` header (at most 255 characters).
- For a configurable window (default 24 h), a repeated key from the same caller returns the original result (`202` with the same `messageId`) without sending again. A request with the same key but a different payload is rejected with `422`.
- Keys are stored in the rate-limit store (Redis for multi-replica installs; in memory otherwise).
- SMTP is out of scope: SMTP clients have no equivalent, and the upstream relay deduplicates by `Message-ID` where it supports that.

---

### Epic 2 — Policy management via CRDs

#### US-2.1 — Mail backend as CRD **[v0.1.0]**
**As a** platform engineer **I want** to define mail backends as CRDs (`MailBackend` / `ClusterMailBackend`), **so that** I can manage them via GitOps and add backend types without an API migration.

*Acceptance criteria:*
- Namespace-scoped CRD `MailBackend` and cluster-scoped CRD `ClusterMailBackend`.
- The spec has a `type` discriminator (`smtp` implemented, `microsoftGraph` **[v0.4.0]**; `gmail` planned for v0.4.0, `sendgrid` reserved in the schema enum).
- For `type: smtp`: an `endpoints` list (at least one entry), `authType`, and `credentialsRef` (required unless `authType: NONE`).
- `endpoints` is an ordered failover list; sends use the first Ready endpoint.
- The validating webhook checks the spec **statically**: it rejects types without a registered driver, missing `smtp` block, empty endpoints, `insecureSkipVerify: true`, a missing `credentialsRef` when auth is required, a missing `credentialsRef.namespace` on `ClusterMailBackend`, and a cross-namespace `credentialsRef` on `MailBackend`.
- The webhook does **not** probe reachability. Network calls during admission are slow, flaky, and break GitOps apply ordering (a backend could not be applied before its relay exists). Reachability is the controller's job and shows up in status.
- The status subresource reflects: `Ready` condition (True if at least one endpoint is Ready), `capabilities` (declared by the driver), `endpointStatus` per endpoint, `lastProbeTime`, `observedGeneration`.

#### US-2.2 — Rate limiting **[v0.1.0 memory, v0.2.0 Redis]**
**As a** platform engineer **I want** to cap how much mail a workload can send, **so that** one broken workload cannot disrupt mail for everyone.

*Acceptance criteria:*
- Configured in `MailPolicy.spec.rateLimits` as `messagesPerMinute`, `messagesPerHour` and `messagesPerDay` **[v0.4.0]** (0 or unset = no cap on that window).
- **Counting unit is the policy** (`<namespace>/<policy-name>`), not the namespace or the ServiceAccount. All subjects matched by one policy share one budget.
- True sliding-window counting (timestamp log per key; Redis uses a sorted set, trimmed and counted atomically in a Lua script with Redis server time). A message leaves a window the moment it is as old as the window. Hits are kept for the longest capped window: one hour, or one day when the policy has a daily cap.
- A request is charged only after it passed policy evaluation and its backend resolved. A transient upstream failure refunds the charge, so callers retrying through an outage don't exhaust their budget. A permanent upstream rejection stays charged.
- When exceeded: HTTP `429` with a `Retry-After` header: seconds until every full window has room again, so a caller that waits that long is not rejected by a longer window right after (before v0.4.0 it named the shortest full window). SMTP: `421 4.7.0`.
- State store: see §4.7. With the in-memory store every replica counts on its own.

#### US-2.3 — Sender address validation **[v0.1.0, hardened v0.2.1]**
**As a** security officer **I want** to allowlist sender addresses per policy, **so that** workloads send only under authorized identities.

*Acceptance criteria:*
- `senderRestrictions.allowedSenders` holds exact addresses and glob patterns (for example `*@noreply.example.com`).
- Semantics of the block:

  | Policy content | Effect |
  |---|---|
  | `senderRestrictions` omitted | **No sender restriction.** Any sender is accepted, like a mail relay without sender checks. |
  | `senderRestrictions: {}` or `allowedSenders: []` | **Every sender is denied.** Almost always an authoring mistake. |
  | `allowedSenders` with entries | Only matching senders are accepted. |

- Matching is case-insensitive. Entries without `*`, `?` or `[` match exactly. Entries with them use Go `filepath.Match` glob syntax against the whole address, so `*` also matches `@`: `*example.com` matches `x@evilexample.com`. Always anchor on the domain: `*@example.com`.
- Checked addresses: header `From`, SMTP envelope sender (`MAIL FROM`), and the `Sender` header if present. All must match.
- On violation: `403` with problem type `sender-not-allowed` (audit and metric reason `sender_not_allowed`).
- Display names, comments and encoded-words in `From`, `Sender` and `Reply-To` must not contain `@` (otherwise `invalid_payload`). Without this rule an arbitrary address could be *displayed* as sender while only the addr-spec is checked.

#### US-2.4 — Recipient allow/denylist **[v0.2.0, hardened v0.2.1, per-address allowlist v0.3.0]**
**As a** security officer **I want** to restrict recipient domains, **so that** development workloads cannot mail external addresses.

*Acceptance criteria:*
- `recipientRestrictions.allowedDomains` and `allowedRecipients` (allowlists) and `blockedDomains` (denylist), all optional. Omitted block = no recipient restriction.
- The denylist wins over both allowlists. A recipient passes if its domain is in `allowedDomains` **or** the address matches an `allowedRecipients` entry. With both allowlists empty, any domain that is not blocked passes.
- Domains match exactly and case-insensitively; subdomains must be listed separately. The webhook requires bare domains (no `@`, no wildcards).
- `allowedDomains: [example.com]` allows every mailbox `@example.com`. `allowedRecipients` **[v0.3.0]** narrows this to single mailboxes (least privilege: a workload that only notifies `alerts@example.com` cannot mail the rest of the company, even when compromised). Entries are exact addresses or globs, matched case-insensitively like `allowedSenders` (shared matcher). The webhook requires plain addresses without display name and routing local parts, and globs of the form `<local-part pattern>@<bare domain>` (for example `*@oncall.example.com`); `*`, `*@*`, wildcard domains and bare domains are rejected, since whole domains belong in `allowedDomains`.
- Checked addresses: all recipients (`to`, `cc`, `bcc` on REST; `RCPT TO` on SMTP) and all `Reply-To` addresses, since replies go there.
- Local parts with routing semantics (`%`, `!`, quoted local parts such as `"user@other"@example.com`) are rejected as `invalid_payload`. The domain check only looks at the part after the last `@`; an upstream MTA that honors the percent hack or bang paths could otherwise deliver to a foreign domain.
- On violation: `403` with problem type `recipient-not-allowed`.

#### US-2.5 — Multi-backend routing **[v0.1.0]**
**As a** platform engineer **I want** to pick a different backend per policy, **so that** for example test workloads send into Mailpit and production workloads into the corporate relay or (later) Microsoft Graph.

*Acceptance criteria:*
- `MailPolicy.spec.backendRef` points at a `MailBackend` (same namespace) or a `ClusterMailBackend`; `kind` distinguishes them and defaults to `ClusterMailBackend`.
- If no policy matches, or the backend does not exist or is not Ready, the message is rejected. There is no default backend.
- The referenced backend's `status.capabilities` must cover the operation (for example `send` for `POST /v1/messages`). **[gap G-2]**: not enforced; only `Ready` is checked.

#### US-2.6 — Policy precedence **[v0.1.0]**
**As a** platform engineer **I want** deterministic behavior when policies overlap, **so that** configurations are predictable.

*Acceptance criteria:*
- A caller only ever matches policies in **its own namespace**.
- Among matching policies the highest `spec.priority` wins (default 0); ties go to the alphabetically first `metadata.name`.
- The subject type (explicit ServiceAccount vs. selector) does **not** influence precedence today. Whether it should become a secondary key is open question Q-6 (§9.2).
- A request no policy matches is rejected with `403 no-policy-matched` (default deny).

#### US-2.7 — Daily limit **[v0.4.0]**
**As a** platform engineer **I want** a per-day cap in addition to per-minute and per-hour limits, **so that** one workload cannot exhaust the upstream provider's daily sending quota for the whole organization.

*Acceptance criteria:*
- `rateLimits.messagesPerDay`, counted like the other windows (per policy, sliding window over the last 24 hours, not a calendar day, US-2.2).
- It counts messages, not recipients. Providers that cap recipients per day (Microsoft 365, personal Gmail) need a cap of their quota divided by the typical recipients per message, bounded by `messageLimits.maxRecipients`.
- A daily cap added to an existing policy counts only the messages of the last hour before the change, because shorter windows keep no more history. It is fully in effect after one day. The same holds after an upgrade from 0.3: 0.3 replicas keep only the last hour, so the cap is fully in effect one day after the last 0.3 replica is gone.
- A replica that has not seen a daily cap yet, or a cap briefly set to 0, keeps the day of history a daily cap set up, so it does not reset the daily count. Once the cap is removed, the history shrinks back to an hour within a day.
- Memory: the in-memory store keeps one timestamp per message for 24 hours (up to `messagesPerDay` per policy) and removes a policy's timestamps once they stop counting, also for idle and deleted policies. Redis keeps the counter key for a day.
- The startup CRD check (US-5.1) requires the field, so a 0.3 CRD cannot silently drop a daily cap.
- Motivation: hosted mailboxes enforce daily quotas (for example Microsoft 365 and Google Workspace cap recipients per day and mailbox); exceeding them blocks the sending account for everyone, not just the runaway workload.
- A namespace-wide quota across policies (`MailQuota`, §4.3.3) stays in the backlog until users ask for it.

#### US-2.8 — Sender allowlist on the backend **[v0.4.0 for `smtp`; API backends planned v0.4.0]**
**As a** platform engineer or an individual **I want** a backend to state which sender addresses it sends for, **so that** a backend that can send as many mailboxes never sends as one it was not meant for, and a personal account is used only with its own address.

*Acceptance criteria:*
- `MailBackend.spec.allowedSenders` and `ClusterMailBackend.spec.allowedSenders`: exact addresses and glob patterns with the matching rules of US-2.3 (for example `*@example.com`, or a single `me@outlook.com`). Since the list bounds every policy that uses the backend, the webhook validates entries like `allowedRecipients` (US-2.4): plain addresses, and globs anchored on a bare domain; `*`, `*example.com` and wildcard domains are rejected.
- Checked on every send in addition to the policy's `senderRestrictions`, against the same addresses (`From`, envelope sender, `Sender`). Both must match, so a policy can narrow the backend's list but never widen it. On violation: `403 sender-not-allowed` (SMTP: the same reply as a policy's sender rejection), audit and metric reason `sender_not_allowed` with the backend in the audit record; the log line names the backend as the restriction that failed (`restriction=backend`). The answer to the caller says that the backend refused the sender, without naming it.
- The check runs once the backend is resolved and before the rate limit, so a refused message is not charged. An unready backend answers `backend_not_ready` first.
- An empty list and an omitted one differ (deny all, allow all), so the field has no `omitempty`: an empty list survives every round trip through the Go types, and a missing one is never stored as `null`. The startup CRD check (US-5.1) requires the field, so a 0.3 CRD cannot drop a backend's list silently.
- The mailbox an API backend sends as is the `From` address: Graph app-only posts to `/users/{From}/sendMail`, a Gmail service account impersonates `From`. The backend's list therefore bounds which mailboxes Sigillum can use.
- Defaults per backend kind (the webhook enforces them):

  | Backend | `allowedSenders` omitted | Why |
  |---|---|---|
  | `smtp` (company relay, provider SMTP) | No backend restriction; the relay forwards as `From` states, as today | Non-breaking; the relay and the policy already decide |
  | `microsoftGraph` app-only, `gmail` service account | **Rejected by the webhook**; at least one entry is required | The grant can send as any mailbox in the tenant or domain |
  | Delegated (`XOAUTH2`, `gmail`; US-6.3) | Only the signed-in account (`status.oauth.account`) | A personal account has one address; add its send-as aliases explicitly |

- `allowedSenders: []` denies every sender, as in US-2.3. The webhook warns on it.
- The platform owner of a `ClusterMailBackend` can pin its sender domains without an admission policy; the `sigillum.dev/sender-domain` recipe (US-5.7) stays for per-namespace domains.

---

### Epic 3 — Kubernetes-native authentication

#### US-3.1 — ServiceAccount token authentication **[v0.1.0]**
**As a** developer **I want** to authenticate with my pod's ServiceAccount token, **so that** I have no separate credentials to manage.

*Acceptance criteria:*
- The REST API accepts `Authorization: Bearer <token>`.
- The token is validated via the Kubernetes `TokenReview` API with `spec.audiences: [sigillum]` (configurable via `--token-audience`). Sigillum also verifies that `status.audiences` contains the expected audience; an audience-unaware authenticator would otherwise accept a kube-apiserver token.
- Only ServiceAccount identities are accepted (`system:serviceaccount:<ns>:<name>`); namespace and SA name drive policy matching.
- Missing, invalid or expired tokens are rejected with `401` and problem type `invalid-token`. If the TokenReview itself fails (kube-apiserver unreachable), the answer is `503 unavailable` with `Retry-After: 5`, audited and counted as `auth_unavailable` **[v0.3.0]**.
- Results (positive and negative) are cached by token hash. See §5.3 for cache TTL and revocation latency.

#### US-3.2 — Policy subject matching **[v0.1.0; selectors fixed v0.2.0]**
**As a** security officer **I want** to bind policies to specific ServiceAccounts or labels, **so that** policies apply at fine granularity.

*Acceptance criteria:*
- `MailPolicy.spec.subjects` is a list; each entry has **exactly one** matcher:
  - `serviceAccount: {name}`: exact SA name in the policy's namespace. The optional `namespace` field is informational and ignored, because policies never match across namespaces.
  - `serviceAccountSelector: {matchLabels, matchExpressions}`: label selector on the caller's ServiceAccount object.
  - `podSelector: {matchLabels, matchExpressions}`: label selector on the source pod. Only consulted for pod-IP legacy callers (US-3.5).
- A policy matches if **any** subject matches.
- Empty selectors never match (the webhook rejects them), so a policy cannot accidentally bind every SA.
- If the ServiceAccount lookup fails, selector subjects do not match (fail closed). A selector built only from `NotIn` / `DoesNotExist` would otherwise match an empty label set.

#### US-3.3 — Istio mTLS authentication **[backlog]**
**As a** platform engineer **I want** to use the SPIFFE identity when Istio is active, **so that** token handling disappears and authentication is cryptographically bound to the workload identity.

*Priority note:* token authentication already works inside a mesh, so this is a convenience, not a blocker. It moves up if users ask for it.

*Acceptance criteria:*
- Optional auth mode `istio`.
- REST: evaluate the `X-Forwarded-Client-Cert` header injected by the sidecar. SMTP: the peer identity of the mTLS connection.
- Parse the SPIFFE ID (`spiffe://<trust-domain>/ns/<ns>/sa/<sa>`) and map it to namespace and SA.
- **Header trust:** the mode may only be enabled when a client-supplied `X-Forwarded-Client-Cert` header cannot reach Sigillum, i.e. the Sigillum pod's sidecar sanitizes it (`forwardClientCertDetails: SANITIZE_SET`, and a `PeerAuthentication` in `STRICT` mode for the Sigillum workload). Otherwise a pod without a sidecar could claim any identity. The installation docs must state this, and Sigillum should refuse the header on connections that did not arrive through the sidecar.
- The configured trust domain must match; foreign trust domains are rejected.

#### US-3.4 — SASL OAUTHBEARER for SMTP **[v0.2.0]**
**As a** developer **I want** to authenticate my SMTP client with my ServiceAccount token, **so that** SMTP auth has the same trust basis as REST instead of weak pod-IP trust.

*Acceptance criteria:*
- The SMTP proxy offers `AUTH OAUTHBEARER` (RFC 7628).
- Token extraction from the SASL payload (`n,a=<user>,^Aauth=Bearer <token>^A^A`). The `a=` authzid is ignored; identity comes from the token only.
- Token validation as on the REST path: `TokenReview` with audience `sigillum`, sharing the same cache rules.
- SA name and namespace from the `TokenReview` drive policy matching exactly as on REST.
- Invalid or expired tokens are rejected with `535 5.7.8 Authentication credentials invalid`.
- The projected ServiceAccount token (typically at `/var/run/secrets/tokens/sigillum`) is the standard delivery path; the README shows an example.
- AUTH without STARTTLS is allowed by default only when no TLS secret is configured (chart `smtp.allowInsecureAuth: null` follows `smtp.tls.secretName`). It is meant for meshes that encrypt pod-to-pod traffic.

#### US-3.5 — Pod-IP authentication as explicit legacy fallback **[v0.2.0]**
**As a** platform engineer **I want** pod-IP identification only for workloads that cannot do SASL, **so that** the weak mode does not implicitly apply to every workload.

*Acceptance criteria:*
- Two opt-ins are required: the SMTP deployment enables mode `podip` (`--auth-modes=oauthbearer,podip`), **and** the policy sets `spec.legacyAuth.podIPFallback: true`. A pod-IP caller never matches any other policy.
- Clients that authenticated via SASL are never identified by pod IP (the stronger mode wins).
- Lookup: source IP → Running, non-terminating pod → its ServiceAccount and labels. An IP shared by more than one such pod (for example host-network pods) is ambiguous and rejected.
- The proxy must see the caller's real pod IP (no SNAT or masquerading between caller and proxy). With `podip` enabled the proxy needs cluster-wide `list`/`watch` on pods.
- Policies with the fallback enabled carry a `UsingLegacyAuth=True` condition so security scans can find them.
- Rationale: pod IPs are unreliable under NAT, meshes and some CNIs, and not cryptographically bound to an identity.

#### US-3.6 — API server RBAC for CRDs **[v0.1.0]**
**As a** platform engineer **I want** CRD access governed by standard Kubernetes RBAC, **so that** no separate permission model appears.

*Acceptance criteria:*
- The CRDs are regular Kubernetes resources and respect RBAC.
- Sigillum components run with least privilege (§4.10).
- The chart ships aggregated ClusterRoles (`rbac.aggregateClusterRoles`, default `true`):
  - `sigillum-view` → aggregated into `view`: read `MailBackend`, `ClusterMailBackend` and `MailPolicy`. Not `MailCredential`: a bring-your-own `spec.passwordHash` would allow offline guessing of a weak password.
  - `sigillum-edit` → aggregated into `edit`: write `MailBackend`, `MailPolicy` and `MailCredential`, read `ClusterMailBackend`.
  - `sigillum-admin` → aggregated into `admin`: write all four.
  - No aggregated role grants `mailcredentials/status`: the password hashes there are written by the controller only.
- With the default, **everyone holding `edit` in a namespace can author `MailPolicy` there.** Platforms that reserve policy authoring for the platform or security team set `rbac.aggregateClusterRoles: false` and bind their own roles (§4.9).

#### US-3.7 — Sigillum-issued SMTP credentials **[v0.3.0]**
**As a** developer running off-the-shelf software (Grafana, Alertmanager, Gitea, Nextcloud, Keycloak, Argo CD notifications, …) **I want** to authenticate to the SMTP proxy with a username and password, **so that** apps that support nothing but `AUTH PLAIN` / `LOGIN` can send through Sigillum without falling back to pod-IP trust.

*Acceptance criteria:*
- A namespace-scoped `MailCredential` (§4.3.4) binds a username to one ServiceAccount in its namespace. Authenticating with it gives exactly the identity of that ServiceAccount; policy matching, rate limits and audit are unchanged. Policies need no opt-in for credential callers.
- Two mutually exclusive modes:
  - **Generated (default).** The controller generates a 256-bit random password, writes it to a Secret in the credential's namespace (`spec.secretName`), and records only a SHA-256 hash in `status`. Nothing secret is committed to Git; the team only commits the `MailCredential`.
  - **Bring your own hash.** The user sets `spec.passwordHash` (argon2id) and delivers the Secret themselves (Vault, External Secrets, `kubectl sigillum credential create` from v0.5.0). The controller touches no Secret. For teams that do not want Sigillum to write Secrets in their namespace.
- Generated credentials are available in **all namespaces except excluded ones** (chart `credentials.excludeNamespaces`, default `kube-*`; the Sigillum release namespace is always excluded). Details and the guard that keeps this safe: §4.10.
- The SMTP proxy offers `AUTH PLAIN` and `AUTH LOGIN` when mode `credential` is enabled (`--auth-modes`, chart `smtp.authModes`). Credential authentication **requires TLS** (STARTTLS, or implicit TLS from v0.5.0): on a plaintext connection PLAIN and LOGIN are not advertised and answer `538 5.7.11`. Plaintext is only possible with an explicit `smtp.allowInsecureAuth: true` (flag `--allow-insecure-credential-auth`), for example with mesh mTLS; the default `null` enables plaintext AUTH for tokens only. Unlike tokens, a static password can be replayed for months.
- The proxy verifies credentials from its informer cache of `MailCredential` objects and needs no Secret access. It only accepts a credential whose `Ready` condition is `True` and whose `status.serviceAccountName` (and, for bring-your-own hashes, `status.current.hash`) match the spec: a changed ServiceAccount or hash takes effect once the controller has accepted it, and the old one stops working at once. Other spec edits, such as the rotation interval, do not interrupt logins while the controller catches up. For a PLAIN authorization identity, only empty or the username itself is accepted.
- **Rotation (generated mode):** on `spec.rotation.interval` (Go duration or days, for example `90d`; at least `1h`) or on demand (any new value of the annotation `sigillum.dev/rotate`, or `kubectl sigillum credential rotate` from v0.5.0), the controller writes a new password to the Secret and keeps the old hash valid for `spec.rotation.gracePeriod` (default 24 h). Apps that read the password only at startup are restarted by [Stakater Reloader](https://github.com/stakater/Reloader) (recipe in `examples/reloader/`). The audit record carries `credential_previous: true` when the previous password was used, and the proxy logs a warning, so stragglers can be found before the grace period ends.
- **Revocation:** delete the `MailCredential` (the owned Secret is garbage-collected). Takes effect as soon as the proxy's informer sees the deletion; there is no additional cache. Open SMTP sessions are re-checked at every `MAIL FROM` and again before a message is relayed at the end of `DATA`, and answer `454 4.7.0` once the credential is gone or its password has been rotated out. The reply is temporary so that a message queued before a rotation is retried on a new connection with the new password rather than bounced; a deleted credential then fails `AUTH` with `535`. The session stays refused (no fallback to pod-IP identification). A failed lookup answers `454 4.7.0` and the session goes on. After a rotation, a session that logged in with the rotated-out password is audited with `credential_previous: true`.
- Log and audit `auth_method`: `smtp_credential`, plus the credential's username (`credential`). Failed attempts answer `535 5.7.8`, are audited (reason `invalid_credentials`) and counted in `sigillum_auth_failures_total`. Only bring-your-own-hash credentials are throttled, per replica: after `--auth-failures-per-user-ip` (default 10) failures per username and source IP within `--auth-failure-window` (default 5 min), further attempts with that username from that IP answer `454 4.7.0` without checking the password (reason `auth_rate_limited`). Attempts with the same username from the same source IP are checked one at a time, so parallel connections cannot pass the limit while their checks wait for an argon2id slot, and parallel logins with the right password are not throttled (after the first, the success cache answers them). User-chosen passwords may be weak and every attempt costs an argon2id computation; generated 256-bit passwords cannot be guessed, so throttling them would only let anyone who reaches the proxy lock out the real app. Nothing is counted per username or per source IP alone: behind a mesh sidecar or SNAT all callers share one source IP, and one misbehaving client must not block the others. In that setup a client that can reach the proxy can still exhaust a bring-your-own credential's bucket for the shared IP; prefer generated credentials there, or set `--auth-failures-per-user-ip=0`. The failure tracker is an LRU of 100,000 keys, so a flood of new usernames or addresses cannot evict an active block. Bring-your-own argon2id verifications run at most two at a time per replica, and successes are cached for 5 min.
- No privilege escalation: whoever can create a `MailCredential` for a ServiceAccount could already run a pod as that ServiceAccount (`edit` role).
- Priority rationale: without this, the most common SMTP clients in a cluster can only use the weakest mode (US-3.5). There is no workaround outside Sigillum.

*Workflow (generated mode):*
1. Platform team, once: enable mode `credential` and STARTTLS in the chart. All namespaces except the excluded ones can use credentials immediately.
2. Team commits a `MailCredential` (and its `MailPolicy`) to Git.
3. The controller creates the Secret (`username`, `password`, `host`, `port`) in the team's namespace and records the hash.
4. The app references the Secret the same way as any SMTP Secret, for example Grafana's `smtp.existingSecret`.
5. On `AUTH PLAIN`, the proxy maps the username to the `MailCredential`, checks the hash, and continues as that ServiceAccount.

---

### Epic 4 — Operations and observability

#### US-4.1 — Prometheus metrics **[v0.1.0]**
**As a** platform engineer **I want** metrics on mail throughput, latency and errors, **so that** I can define SLOs.

*Acceptance criteria:*
- `/metrics` in Prometheus format on a dedicated port (default `:9090`) in every component.
- Metrics and labels:

  | Metric | Type | Labels | Counts |
  |---|---|---|---|
  | `sigillum_messages_total` | Counter | `namespace`, `policy`, `backend`, `result` (`ok`, `upstream_error`, `upstream_rejected`) | Messages that reached a backend |
  | `sigillum_message_size_bytes` | Histogram | `namespace`, `policy`, `backend` | Accepted messages only, size as in §4.4.4 |
  | `sigillum_backend_duration_seconds` | Histogram | `namespace`, `policy`, `backend`, `result` | Duration of the upstream send |
  | `sigillum_ratelimit_rejected_total` | Counter | `namespace`, `policy` | `429` / `421` rejections |
  | `sigillum_policy_denied_total` | Counter | `namespace`, `policy`, `reason` | Policy denials, plus `reason="backend_not_ready"` |
  | `sigillum_auth_failures_total` **[v0.3.0]** | Counter | `transport`, `auth_method`, `reason` (`invalid_token`, `invalid_credentials`, `auth_rate_limited`, `auth_unavailable`) | Failed authentication attempts |
  | `sigillum_credential_guard_ok` **[v0.3.0]** | Gauge (controller) | — | 1 while the credential Secret guard is verified (§4.10), 0 while the controller refuses to write credential Secrets |
  | `sigillum_backend_authorized` **[v0.4.0]** | Gauge (controller) | `backend` | 1 while a delegated backend (US-6.3) holds a working refresh token, 0 while it needs a new sign-in |

- Payload errors (before policy evaluation) are not counted in metrics; they appear in the audit stream. Authentication failures are counted in `sigillum_auth_failures_total` only; no namespace label, since the claimed identity is client-supplied.
- `ServiceMonitor` in the Helm chart (`serviceMonitor.enabled`).

#### US-4.2 — Structured logs **[v0.1.0]**
**As a** platform engineer **I want** structured JSON logs, **so that** I can search and correlate mail activity.

*Acceptance criteria:*
- JSON via Go `log/slog` on stdout.
- Log level via env `SIGILLUM_LOG_LEVEL` (`debug`, `info`, `warn`, `error`; chart value `logLevel`).
- Fields per mail log line: `time`, `level`, `msg`, `message_id`, `namespace`, `service_account`, `authMethod` (`oauth_bearer` | `smtp_credential` | `pod_ip_legacy`; `istio` once US-3.3 lands), `transport`, `policy`, `backend`, `result`, plus `reason`, `upstream_id`, `trace_id`, `credential` (and `credential_previous`) and `cluster` where applicable.
- No mail content in logs (metadata only), no tokens, no passwords.

#### US-4.3 — Audit log stream **[v0.2.0]**
**As a** security officer **I want** a separate audit log stream, **so that** compliance requirements (BSI, NIS2) are met.

*Acceptance criteria:*
- A separate writer with a fixed record shape (§4.8), one JSON object per line. Sink: `stdout` (default), `stderr`, `none`, or a file path (`--audit-log`, chart `audit.output`).
- Exactly one record per mail request, including rejections at any stage (authentication, payload, policy, rate limit, backend, upstream). SMTP `MAIL` / `RCPT` rejections produce a record per refused command.
- Records are tagged `"stream":"audit"` so aggregators can split them from the operational log on the same stdout.
- No subject, body or attachment content.

#### US-4.4 — OpenTelemetry tracing **[v0.2.0]**
**As a** platform engineer **I want** traces from the REST call to the upstream send, **so that** I can debug latency.

*Acceptance criteria:*
- OTLP export (HTTP/protobuf by default), configured through the standard `OTEL_*` environment variables (chart: `tracing.endpoint`, `tracing.sampler`, …). Tracing is a no-op while no endpoint is set.
- Span structure (children are siblings, in execution order):
  - REST: `http.request` → `auth.tokenreview`, `policy.evaluate`, `ratelimit.allow`, `backend.send`
  - SMTP: `auth.tokenreview` during `AUTH`; `smtp.data` → `policy.evaluate`, `ratelimit.allow`, `backend.send`
- W3C Trace Context: an incoming `traceparent` header is continued. Only `/v1/*` is traced, not probes or scrapes.

#### US-4.5 — Cluster identity in telemetry **[v0.3.0]**
**As a** platform engineer running staging and production clusters **I want** every audit record, log line and metric to say which cluster it came from, **so that** one log backend and one Prometheus can serve all clusters.

*Acceptance criteria:*
- `--cluster-name` flag on all three components (chart value `clusterName`, empty by default).
- When set: audit field `cluster`, log field `cluster` (the controller's log lines too), and a `cluster` target label on the ServiceMonitor (a relabeling, not an extra label on every series, so single-cluster setups are unchanged).

#### US-4.6 — Dashboards and alerts **[planned v0.5.0]**
**As a** platform engineer **I want** a ready-made dashboard and alert rules, **so that** I notice problems without writing PromQL first.

*Acceptance criteria:*
- Grafana dashboard JSON (chart `ConfigMap` with the Grafana sidecar label, opt-in).
- `PrometheusRule` (opt-in) with at least: backend not Ready, upstream error ratio, rate-limit rejections rising, policy denials rising, Redis unavailable, controller not reconciling.
- Works with kube-prometheus-stack defaults.

---

### Epic 5 — Platform operations

#### US-5.1 — GitOps-compatible deployment **[v0.1.0]**
**As a** platform engineer **I want** to deploy Sigillum with Helm or Kustomize, **so that** it fits our Argo CD flow.

*Acceptance criteria:*
- Official Helm chart with sensible defaults; every setting available via `values.yaml`.
- CRDs ship in the chart's `crds/` directory; the generated manifests also live in `config/crd/bases/` for separate installation.
- **CRD upgrades:** Helm installs `crds/` on first install only and never upgrades or deletes them. Upgrades apply `config/crd/bases/` (or the chart's `crds/`) explicitly, for example with `kubectl apply --server-side` or an Argo CD application. The CRD-migration runbook (§5.7) documents this.
- **CRD version check [v0.3.0]:** an outdated CRD makes the API server prune fields it does not know, which only warns a server-side apply. A MailPolicy restricted by `allowedRecipients` alone would then allow every recipient that is not blocked, and one with `messagesPerDay` **[v0.4.0]** would have no daily cap, and a backend's `allowedSenders` **[v0.4.0]** would no longer bound its senders. Every component therefore reads the published OpenAPI v3 schemas at startup (readable by every authenticated client, no RBAC) and exits with an error naming the missing kinds and fields if a field the version relies on is absent. It retries for 30 s because the API server publishes a changed CRD a few seconds late. A failed rollout leaves the old pods serving. `--skip-crd-check` turns the check off for clusters that hide the OpenAPI endpoint.
- No runtime configuration outside Kubernetes resources (no init scripts).
- The admission webhook needs a serving certificate: either cert-manager (`webhook.certificate.useCertManager=true`) or an existing secret.

#### US-5.2 — High availability **[v0.2.0]**
**As a** platform engineer **I want** to run Sigillum highly available, **so that** a pod failure does not interrupt mail.

*Acceptance criteria:*
- Stateless api-server and SMTP proxy; horizontal scaling via replicas.
- Rate-limit state is shared only with the Redis store (§4.7). The chart defaults to 2 api-server replicas **and** the in-memory store, so each replica enforces the full limit and the effective limit doubles. Production installs with more than one replica set `rateLimit.backend=redis`.
- PodDisruptionBudgets in the chart (api and SMTP enabled by default with `minAvailable: 1`; controller disabled by default because it runs one replica).
- Leader election for the controller (default on), not for the api-server or SMTP proxy.

#### US-5.3 — Graceful shutdown **[v0.1.0]**
**As a** platform engineer **I want** in-flight mail requests to finish on pod termination, **so that** no mail is lost.

*Acceptance criteria:*
- SIGTERM first fails `/readyz` (`503`) while requests and SMTP sessions are still served normally, for `--shutdown-delay` (default 5 s, chart `api.shutdownDelay` / `smtp.shutdownDelay`) **[v0.3.0]**. Endpoint removal lags behind SIGTERM; the delay lets the pod leave the Service endpoints before its listener closes. It is the in-process equivalent of a `preStop` sleep, which the distroless image (no shell) cannot run.
- Then draining starts: the listener closes and in-flight requests may finish within `--shutdown-timeout` (default 25 s). The chart's `terminationGracePeriodSeconds` is 35 so delay and timeout fit.
- Requests that still arrive while draining are refused with `503 shutting-down`.

#### US-5.4 — Health and readiness probes **[v0.1.0]**
**As a** platform engineer **I want** standard Kubernetes probes, **so that** self-healing works.

*Acceptance criteria:*
- `/healthz` (liveness): the process is up.
- `/readyz` (readiness): the informer cache is synced and the pod is not draining.
- Readiness deliberately does **not** check upstream reachability. An upstream outage would otherwise take every replica out of the Service, and callers would get connection errors instead of meaningful `503 backend-not-ready` / `502` responses. Upstream health is visible in backend status and metrics.

#### US-5.5 — Resource limits and security context **[v0.1.0]**
**As a** platform engineer **I want** defined resource requests/limits and a hardened security context, **so that** the deployment meets our baseline policies.

*Acceptance criteria:*
- Non-root (UID 65532), read-only root filesystem, all capabilities dropped, `seccompProfile: RuntimeDefault`, no privilege escalation.
- Default resources in the chart, overridable.
- Compatible with the Pod Security Standard `restricted`.

#### US-5.6 — Install without cert-manager **[planned v0.5.0]**
**As a** platform engineer of a small cluster **I want** to install Sigillum without cert-manager, **so that** a single `helm install` is enough.

*Acceptance criteria:*
- New default-off chart option in which the controller creates a self-signed CA and serving certificate for its webhook, rotates it before expiry, and patches the `caBundle` of its `ValidatingWebhookConfiguration`.
- cert-manager and an existing secret remain supported.
- Workaround until then: cert-manager or a manually created secret (US-5.1).

#### US-5.7 — Enforcement recipes **[v0.3.0, documentation]**
**As a** platform engineer **I want** tested recipes that make Sigillum the only way out for mail, and guardrails for policy authors, **so that** policies cannot be bypassed or loosened by accident.

*Acceptance criteria:*
- Egress: `NetworkPolicy` examples (plus `CiliumNetworkPolicy` with FQDN rules) that deny ports 25 / 465 / 587 cluster-wide and allow them only for Sigillum pods. Without this, a workload can talk to the relay directly and Sigillum enforces nothing.
- Admission: Kyverno and `ValidatingAdmissionPolicy` examples, for example: only listed namespaces may reference a given `ClusterMailBackend`; `allowedSenders` must stay within a namespace's domain (from a namespace label); `legacyAuth.podIPFallback` is forbidden in production namespaces; `senderRestrictions` is required; no workload Secrets named like SMTP credentials.
- The recipes live in the repository (`examples/egress/`, `examples/admission/`). CI parses every example; the `ValidatingAdmissionPolicy` recipes are applied to a real API server (envtest) and checked against compliant and violating policies, and E2E applies `require-sender-restrictions` in kind. The `ClusterMailBackend` restriction uses a namespace label `backends.sigillum.dev/<name>: "true"`, the sender-domain rule the label `sigillum.dev/sender-domain`.
- These are deliberately recipes, not features (§8.0): standard tools already do this well.

---

### Epic 6 — Extensibility and more backends

This epic describes *architectural constraints*, not features to build now. The current architecture must allow these extensions without breaking changes.

#### US-6.1 — Microsoft 365 and Outlook.com as upstream **[planned v0.4.0]**
**As a** platform engineer or an individual running a small cluster **I want** to send through Microsoft 365 or a personal Outlook.com account without a password, **so that** Sigillum keeps working once Microsoft switches off Basic authentication for SMTP AUTH.

*Why this comes first (§8.0 rule 1):*
- Exchange Online (timeline of January 2026): Basic authentication for SMTP AUTH is disabled by default for existing tenants at the end of December 2026 (admins can re-enable it), is unavailable to new tenants, and gets a final removal date in the second half of 2027.
- App passwords are no way out. They are Basic authentication too: personal Microsoft accounts (Outlook.com) no longer have them, and for work and school accounts they stop working with the December 2026 switch. Every password-based path into a Microsoft 365 mailbox ends; only OAuth remains.
- Personal Outlook.com accounts cannot use Sigillum at all today: Microsoft already removed Basic authentication and app passwords for them, and the SMTP driver has no OAuth.
- Microsoft 365 is the most common hosted mailbox among small organizations, and Outlook.com among individuals (§8.0).

Two paths, one per kind of account:

| Account | Path | Why |
|---|---|---|
| Microsoft 365 work or school account | Graph driver, app-only (stage 1) | Needs no SMTP AUTH, which new tenants have switched off and admins often disable per mailbox |
| Personal Microsoft account (Outlook.com, Microsoft 365 Personal / Family) | SMTP driver with `XOAUTH2`, delegated (stage 2) | Outlook.com keeps SMTP with OAuth. The existing SMTP driver relays the message byte for byte with its envelope, so there is no header-recipient problem (below) and no 4 MB request limit, and the change is much smaller than a second Graph mode |

*Stage 1 — Graph driver* **[v0.4.0]**, for work and school accounts:
- `type: microsoftGraph`, send only. It does not depend on SMTP AUTH being enabled for tenant or mailbox.
- App-only: OAuth2 client-credentials flow against Entra ID, `POST /users/{mailbox}/sendMail` with the application permission `Mail.Send`. Tenant ID and client ID in the spec, `client_secret` in the credentials Secret. The driver caches the access token and refreshes it before expiry. Certificate credentials and workload identity federation stay in the backlog (§8.8, cloud workload identity). Delegated Graph sign-in is in the backlog too (§8.8); personal accounts use stage 2.
- App-only `Mail.Send` can send as any mailbox in the tenant. The backend sends as the `From` mailbox and requires its own `allowedSenders` (US-2.8); the recipe (`examples/providers/`) additionally confines the Entra application to those mailboxes with Exchange Online RBAC for Applications.
- Implements `RawSender`: the message the SMTP proxy relays goes to `sendMail` as Base64 MIME, and REST messages are assembled to MIME as for SMTP. Both transports therefore work with a Graph backend.
- **Recipients are the envelope, never the headers.** Graph and the Gmail API (US-6.2) take the recipients from the `To`, `Cc` and `Bcc` header fields of the MIME message; there is no envelope. The policy, however, checks the envelope recipients (§4.6). Without a rule, an SMTP client could pass the check with an allowed `RCPT TO` and deliver to any address it writes into `To`. The API drivers therefore make the delivered set equal the checked set:
  - every address in `To` and `Cc` must be one of the envelope recipients; otherwise the message is rejected with a permanent error (`550 5.7.1` on SMTP, audit reason `recipient_not_allowed`), before any API call;
  - envelope recipients that appear in neither header (blind copies; the SMTP proxy strips `Bcc` before relaying) are added as a `Bcc` field to the MIME message sent to the API. Both providers remove `Bcc` from the delivered copies.
  - REST messages are built from the checked `to`, `cc` and `bcc` lists, so they already match.
- Graph limits one request to 4 MB, Base64 MIME included. Larger messages **[planned v0.4.0, opt-in]** go through a draft: the driver parses the MIME message, creates the draft with body, recipients and `X-` headers, uploads each large attachment through an upload session, and sends the draft. This path needs the additional permission `Mail.ReadWrite` (read access to the whole mailbox), so it is off unless `microsoftGraph.largeMessages: true`. It cannot keep the MIME structure byte for byte: headers other than the standard ones and `X-` headers are dropped, and signed or encrypted messages (S/MIME, PGP/MIME) above 4 MB are rejected with a permanent error. Without the opt-in, larger messages are rejected with a permanent error that names the limit. The mailbox's own send size limit still applies (Exchange Online default 35 MB).
- Error mapping: `429`, `503` and other `5xx` are `ErrUpstreamTransient` (honoring `Retry-After`); `400`, `403` and `404` (unknown mailbox, missing permission) are `ErrUpstreamPermanent`.
- Implementation notes (row 4a): REST messages are assembled to MIME like for SMTP; the request is `POST {base}/users/{From}/sendMail` with the Base64 MIME as `text/plain`, and `202` is success (the response's `request-id` is the upstream ID). A `401` drops the token and retries once with a new one; a second `401` is permanent. Graph's `Retry-After` is not passed on yet: driver errors carry no delay, so a throttled send answers like any transient upstream error (`502`, SMTP `451`) and the client retries on its own schedule. A failed token request is permanent for `invalid_client` and the other permanent token errors (§4.5), transient otherwise. Because the gateway builds a driver per send, the token cache is shared by every driver of the same tenant endpoint, client and secret, and by the health check. The envelope rule refuses a message that still carries `Bcc` (the SMTP proxy strips it, REST never writes it) and validates every envelope recipient as a bare address before writing the `Bcc` field; `FuzzBindToEnvelope` checks that the delivered set equals the envelope. The rule is `driver.BindToEnvelope`, shared with the Gmail API driver (US-6.2).
- The health check acquires a token, so a wrong tenant, client ID or secret shows up as `Ready=False` instead of on the first send. `status.endpointStatus` has a single entry for the Graph endpoint.
- Exchange Online's daily limit (10,000 recipients per mailbox) applies to Graph as well; the daily limit (US-2.7) ships in the same release.
- Spec: `spec.microsoftGraph` with `tenantID` (tenant ID or verified domain, lower case, since it becomes part of the token URL), `clientID` (a GUID) and `credentialsRef` (key `client_secret`). The webhook requires the block for `type: microsoftGraph`, refuses it on other types and refuses `spec.smtp` on Graph backends, and requires a non-empty `allowedSenders` (US-2.8). The recipe `examples/providers/microsoft-365-graph.yaml` confines the app to its mailboxes with RBAC for Applications in Exchange Online and warns against also granting `Mail.Send` with admin consent in Entra, which would apply to every mailbox.
- A header recipient outside the envelope is a policy refusal: `403 recipient-not-allowed` on REST, `550 5.7.1` on SMTP, audit and metric reason `recipient_not_allowed` with the backend in the audit record, not charged to the rate limit.

*Stage 2 — XOAUTH2 for the SMTP driver* **[planned v0.4.0]**, the path for personal accounts:
- New `authType: XOAUTH2` for SMTP backends, with two Microsoft token sources:
  - **Delegated** (personal Outlook.com accounts): a user signs in once (device code, US-6.3) and grants `https://outlook.office.com/SMTP.Send` and `offline_access`; the backend sends through `smtp-mail.outlook.com:587` with STARTTLS. This is the supported path for Outlook.com. It also works for a work account whose mailbox has SMTP AUTH enabled.
  - **App-only** (work accounts that must stay on SMTP): client credentials with `SMTP.SendAsApp` against `smtp.office365.com`. It needs SMTP AUTH enabled per mailbox, so the Graph driver is the recommended path for work accounts.
- Everything else is the existing SMTP driver: envelope, raw relay, endpoint failover, health checks. Personal Outlook.com accounts have far lower daily limits than business mailboxes; the daily limit (US-2.7) protects them.
- The SASL `user=` value is the mailbox address, set in the backend spec. It is required for `XOAUTH2`; the ID token's `preferred_username` is only a display hint. Microsoft access tokens are issued for one resource, so a token for Graph cannot authenticate SMTP and the reverse; a backend uses one of the two.
- The same `authType` serves Google (US-6.2 stage 2) with a Google token source.

*Workarounds until v0.4.0* (recipes in `examples/providers/`): a Microsoft 365 inbound connector for SMTP relay (static egress IP, outbound port 25); Azure Communication Services Email over SMTP, authenticated with an Entra application's client secret; High Volume Email (`smtp-hve.office365.com`, Basic auth until September 2028, internal recipients only); or a mailbox with SMTP AUTH still enabled, as a bridge until the end of December 2026.

#### US-6.2 — Gmail and Google Workspace as upstream **[planned v0.4.0]**
**As a** platform engineer or an individual running a small cluster **I want** to send through Google Workspace or a personal Gmail account with OAuth instead of an app password, **so that** sending does not depend on a static secret that grants full mailbox access, 2-Step Verification settings and an admin setting that may disable app passwords.

*Status quo:*
- Google app passwords still work for SMTP (`smtp.gmail.com`, `smtp-relay.gmail.com`) as long as 2-Step Verification is active on the account and the Workspace admin has not disabled them. The existing recipe (`examples/providers/google-workspace.yaml`) relies on them, and no cut-off date is announced, so Gmail is less urgent than Microsoft 365.
- An app password is still a static secret tied to a user: it is revoked when that user changes their Google password, it disappears with the user's account, and it grants full access to the mailbox rather than just sending.

*Stage 1 — Gmail API driver* **[planned v0.4.0]**:
- `type: gmail`, send only, through `users.messages.send` with the raw RFC 5322 message. Implements `RawSender` like the Graph driver, so REST and SMTP both work, with the same recipient rule (US-6.1: recipients are the envelope, never the headers).
- Two ways to authenticate, chosen in the spec, both limited to the scope `https://www.googleapis.com/auth/gmail.send`:
  - **Service account** (Google Workspace): domain-wide delegation. The driver signs the JWT assertion (RFC 7523) with the key from `service_account.json` in the credentials Secret and impersonates the `From` mailbox, bounded by the backend's `allowedSenders` (US-2.8). It caches the access token and refreshes it before expiry.
  - **Delegated** (personal Gmail accounts, and Workspace accounts without domain-wide delegation): a user signs in once with an OAuth client of their own Google Cloud project. Sign-in, token storage and refresh are described in US-6.3.
- Gmail replaces a `From` that is neither the mailbox nor one of its verified send-as aliases, so a delegated backend's `allowedSenders` should list only the account and those aliases.
- Messages up to 35 MB go through the upload endpoint; Gmail's own message size limit applies.
- Error mapping: `429` and `5xx` are `ErrUpstreamTransient`; `400` and `403` (delegation missing, scope not granted) are `ErrUpstreamPermanent`.
- The health check acquires a token, so a broken key or missing delegation shows up as `Ready=False`.
- Implementation notes (row 9b): `oauth.GoogleServiceAccount` signs the RFC 7523 assertion (RS256, `iss` the account, `aud` the token endpoint, one hour, `sub` the mailbox) with the PKCS #8 RSA key of `service_account.json`; a key file whose `token_uri` is not Google's token endpoint is refused, since the signed assertion goes there. The driver sends `POST https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/send?uploadType=media` with the MIME message as `message/rfc822`, as the `From` mailbox, after `driver.BindToEnvelope` (row 9a); `200` is success and the message ID is the upstream ID. Tokens are cached per key file and mailbox and shared by every driver. A `401` drops the token and retries once; `429`, `408` and `5xx` are transient, other answers permanent with Gmail's status and message reduced to printable ASCII. A token request refused with `unauthorized_client` (no domain-wide delegation for the mailbox) is permanent. Messages above 35 MB are refused before any request. The health check acquires a token for the service account itself, so a broken or deleted key shows as `Ready=False`; a mailbox without delegation shows on its first send.
- Spec (row 9c): `type: gmail` with `spec.gmail.credentialsRef` (key `service_account.json`). The webhook requires the block for `type: gmail` and refuses it on other types, refuses `spec.smtp` and `spec.microsoftGraph` on gmail backends, applies the usual `credentialsRef` namespace rules, and requires a non-empty `allowedSenders`: domain-wide delegation can act as any user of the domain, and the list is what bounds it (US-2.8). The recipe `examples/providers/google-workspace-gmail-api.yaml` limits the delegation to `gmail.send`.
- Workspace caps sending at 2,000 messages per user and day, a personal Gmail account at about 500 recipients per day; the daily limit (US-2.7) protects both.
- `MailBackend.spec.type` already accepts `gmail`; no CRD redesign is needed.

*Stage 2 — XOAUTH2 for SMTP with Google* **[planned v0.4.0]**: `authType: XOAUTH2` (US-6.1 stage 2) gets Google token sources, the service-account assertion and delegated sign-in, for `smtp.gmail.com`. Gmail's SMTP accepts only the scope `https://mail.google.com/` (full mailbox access), so the recipes recommend the Gmail API driver and keep XOAUTH2 for software that must stay on SMTP.

*Until v0.4.0*, personal Gmail accounts use `smtp.gmail.com` with an app password (`examples/providers/gmail.yaml`).

#### US-6.3 — Delegated sign-in for personal accounts **[planned v0.4.0]**
**As an** individual running Sigillum on a home lab or small cluster **I want** to connect my personal Outlook.com or Gmail account once through the provider's sign-in page, **so that** Sigillum can send as me without a password and keeps working without further logins.

Personal accounts have no app-only access: no client credentials for Outlook.com, no service accounts with domain-wide delegation for Gmail. A person has to sign in and consent once; Sigillum then works with the refresh token it receives.

*Acceptance criteria:*
- **Own OAuth client.** The user registers an OAuth client with the provider; Sigillum ships no shared client ID for now (Q-13). Its client ID goes into the backend spec; a client secret, where the provider requires one, into the credentials Secret. The recipes walk through the registration:
  - Microsoft: an app registration for personal Microsoft accounts with public client flows enabled and the delegated permissions `SMTP.Send` and `offline_access`. Registering an app requires a Microsoft Entra tenant. Someone with only an Outlook.com account has none and must first sign up for an Azure account to get one. This is the largest hurdle for personal Outlook.com users; see Q-13.
  - Google: a project with the Gmail API enabled (any Google account can create one), an OAuth client of type "Desktop app", and the consent screen set to **In production**. Google does not verify an app used only by its owner, so the owner clicks through the "unverified app" warning once. A consent screen left in **Testing** issues refresh tokens that expire after seven days; the controller warns about it when it can tell (a refresh token that stops working after seven days).
- **Sign-in:**
  - Microsoft uses the device authorization grant (RFC 8628), run by the controller. When a delegated backend has no valid refresh token, or on any new value of the annotation `sigillum.dev/authorize`, the controller requests a device code and sets `Authorized=False`, reason `AuthorizationPending`, with the verification URL and the user code in the condition message (`kubectl describe cmb <name>`). The controller polls until the user has signed in or the code expires (15 minutes; then reason `AuthorizationExpired` until the next annotation value).
  - Google does not allow Gmail scopes in its device flow. A subcommand `sigillum oauth login --provider google|microsoft` runs the authorization code flow with PKCE and a loopback redirect (RFC 8252) on a workstation with a browser and prints the refresh token, or writes it into the credentials Secret with the user's own kubeconfig. It ships in the Sigillum binary and image; the `kubectl sigillum` plugin (US-7.2) gets the same command later. It also works for Microsoft, for users who prefer it.
- **Token broker [v0.4.0, not wired to a backend type yet].** The controller is the only component that redeems the refresh token, so replicas never race and Microsoft's rotating refresh tokens are not lost:
  - It keeps the newest refresh token and the current access token with its expiry in a Secret it owns (`sigillum-oauth-<backend>`, in the backend's credentials namespace, owner reference to the backend). On start it reads that Secret and the credentials Secret and uses the newer refresh token.
  - It refreshes the access token at half its lifetime (Microsoft and Google issue access tokens for about an hour). The api-server and the SMTP proxy read the access token from the Secret through the Secret informer they already have and never see the refresh token's rotation.
  - The periodic health check refreshes the tokens even when no mail is sent, so they do not lapse from inactivity (Microsoft: refresh tokens last 90 days and rotate on use; Google: a refresh token unused for six months expires).
  - When a refresh fails permanently (revoked consent, a changed Google password, expiry), the backend goes `Ready=False` with reason `AuthorizationRequired` and the metric `sigillum_backend_authorized` drops to 0, so the alert rules (US-4.6) can page the owner; a Microsoft backend immediately starts a new device code (above).
  - Implementation (`internal/controller/oauth_broker.go`, `TokenBroker.Ensure`, called on every reconcile and health check of a delegated backend):
    - The token Secret is `sigillum-oauth-mb-<name>` for a `MailBackend` and `sigillum-oauth-cmb-<name>` for a `ClusterMailBackend` (both may keep credentials in one namespace), shortened with a hash beyond 253 characters. Besides the three keys it carries the annotations `sigillum.dev/oauth-seed` (a hash of the credentials Secret's `refresh_token` that the stored chain descends from) and `sigillum.dev/oauth-refresh-at`.
    - "The newer refresh token" is decided by the seed: while the credentials Secret holds the refresh token the stored chain started from, the stored (possibly rotated) one is used; a different one there is a new sign-in and replaces the chain. A refresh token written straight into the token Secret (the device code flow) has an empty seed.
    - It refreshes when `oauth-refresh-at` (half the access token's lifetime) has passed and the credential Secret guard is verified: a refresh may rotate the refresh token, so it is only redeemed while the result can be stored. A rotated token is kept in memory first, so a failed write is retried without redeeming it again.
    - Results, for the backend's `Authorized` condition: `Authorized`; `AuthorizationRequired` (no refresh token, or the provider rejected it, as a permanent error such as `invalid_grant`; metric 0; retried every 10 minutes and on the next reconcile, which a new sign-in triggers); `TokenRefreshFailed` (a temporary error; retried after 30 s, still authorized); `GuardMissing`, `SecretConflict`, `SecretWriteFailed` as for `MailCredential`.
    - The api-server and the SMTP proxy read the access token with `AccessTokenFromSecret`.
- **Secret guard [v0.4.0].** Writing the token Secret extends the credential Secret guard (§4.10): the controller may `create` and `patch` only Opaque Secrets labelled `sigillum.dev/oauth-token`, with the backend's UID in the annotation `sigillum.dev/oauth-token-uid`, a controller owner reference to that backend, and only the keys `refresh_token`, `access_token` and `expires_at`. This is also allowed in the release namespace, for this label only. The chart grants the permission together with the guard.
- **Usable means tested end to end.** A personal Outlook.com account and a personal Gmail account are supported once a person can go from the recipe (`examples/providers/outlook-com.yaml`, `examples/providers/gmail-oauth.yaml`) to a delivered message through REST and through the SMTP proxy without reading code. CI tests the flows against fake token, Graph and Gmail endpoints; before each release a maintainer runs the recipes against a real Outlook.com and a real Gmail account (a short checklist in `docs/RELEASE-CHECKS.md`), because the providers' consent screens and limits cannot be tested in CI.
- **Identity in status.** `status.oauth.account` shows the signed-in account (from the ID token or the provider's profile call), so a sign-in with the wrong account is visible. Without `spec.allowedSenders` the backend sends only as that account (US-2.8).

#### US-6.4 — API-based send backends **[backlog]**
**As a** platform engineer **I want** to use SendGrid, Amazon SES or Mailgun through their HTTP APIs.

*Priority note:* every one of these providers also offers SMTP with an API key as password, which works with the SMTP driver today. API drivers become worth their cost mainly together with cloud workload identity (no static secret at all, for example SES with IRSA / EKS Pod Identity), which is a larger-organization concern. Microsoft Graph and the Gmail API are the exception and are planned (US-6.1 to US-6.3), because their providers are retiring or discouraging password logins.

*Architectural constraint:*
- Different auth mechanisms per backend type (API key, service-account JSON, OAuth2 client credentials) must be expressible as type-specific Secret layouts without changing the central secret handling (§4.3.1).

#### US-6.5 — Reading mail via REST **[future]**
**As a** developer **I want** to read mailboxes via REST (list, fetch, search), **so that** workloads can process incoming mail without an IMAP library.

*Architectural constraint:*
- `Read()` and `Subscribe()` are added to the driver interface (or as optional interfaces, like `RawSender`) when the first read-capable driver lands.
- The API is versioned; `/v1/messages` stays the send path and read endpoints are added under `/v1/mailboxes/...`.

#### US-6.6 — IMAP proxy for legacy readers **[future]**
**As a** developer of a legacy application **I want** to read mailboxes over IMAP, even when the backend is Microsoft Graph.

*Architectural constraint:*
- Protocol adapters are separate, optionally enabled components (the SMTP proxy already runs as its own `--mode=smtp` deployment on the shared gateway pipeline).

#### US-6.7 — Webhook push for backend events **[future]**
**As a** developer **I want** events such as bounces, delivery confirmations or incoming mail pushed to my workload.

*Architectural constraint:*
- The controller can later host a webhook-receiver component without architectural changes.

*Priority note:* bounces, delivery status and suppression lists are handled by the upstream provider (§7). This story only matters if users need these events inside the cluster.

---

### Epic 7 — Developer experience

#### US-7.1 — Local development recipe **[v0.3.0, documentation]**
**As a** developer with a local cluster (kind, k3d, minikube, Docker Desktop) **I want** a copy-paste setup that captures mail instead of sending it, **so that** I can test mail flows in minutes.

*Acceptance criteria:*
- A documented profile (`examples/local-dev/`): one replica, in-memory rate limits, no admission webhook, Mailpit deployed next to Sigillum as a `ClusterMailBackend` (`authType: NONE`, `tls: none`), a permissive example policy, and a `MailCredential` for trying SMTP logins.
- A recipe to call the API from the laptop as a given ServiceAccount: `kubectl create token <sa> --audience sigillum` plus `kubectl port-forward`.
- A built-in capture driver is **not** planned: Mailpit already does this well (§8.0).

#### US-7.2 — Preflight and kubectl plugin **[planned v0.5.0]**
**As a** developer or policy author **I want** to test and explain policy decisions from the command line, **so that** I understand a `403` without reading controller logs.

*Acceptance criteria:*
- Preflight endpoint (§4.4.2).
- `kubectl sigillum` plugin (single static binary, also usable standalone):
  - `send`: send a test message as the current user or `--as-sa <sa>` (requests a token via the TokenRequest API with the user's own permissions).
  - `whoami`: show the resolved identity and the policy that would match.
  - `explain`: run preflight and print every candidate policy with the rule that accepted or rejected the message.
  - `credential create`: bring-your-own-hash mode; generate a password, then create the Secret and the `MailCredential` (US-3.7) with the user's own permissions.
  - `credential rotate`: trigger a rotation of a generated credential.

#### US-7.3 — OpenAPI description **[planned v0.5.0]**
**As a** developer **I want** a machine-readable API description, **so that** I can generate a client in my language.

*Acceptance criteria:*
- OpenAPI 3.1 document for `/v1`, including the problem types of §4.4.3, published with each release.
- Official client SDKs are **not** planned: the API is one call, and clients can be generated from the document.

---

## 4. Architecture

### 4.1 Component overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        Kubernetes cluster                        │
│                                                                  │
│  Caller workload          Sigillum (one image, three modes)      │
│  ┌─────────────┐          ┌──────────────────────────────────┐   │
│  │  App pod    │  HTTP(S) │ api-server   (--mode=api, N)     │   │
│  │             │ ────────▶│  REST handler ─┐                 │   │
│  │             │  Bearer  └────────────────┼─────────────────┘   │
│  │             │          ┌────────────────┼─────────────────┐   │
│  │             │  SMTP    │ smtp-proxy   (--mode=smtp, N,    │   │
│  │             │ ────────▶│  optional)     │                 │   │
│  └─────────────┘  587     │  SMTP handler ─┤                 │   │
│                           └────────────────┼─────────────────┘   │
│                                            ▼                     │
│                      shared gateway pipeline (in each process):  │
│                      auth ▸ policy ▸ backend ▸ rate limit ▸ send │
│                                            │                     │
│  ┌──────────────────────────────┐          │                     │
│  │ controller (--mode=controller│          │                     │
│  │  leader-elected)             │          │                     │
│  │  CRD reconcilers             │          │                     │
│  │  validating webhook          │          │                     │
│  │  backend probes              │          │                     │
│  └──────────────┬───────────────┘          │                     │
│                 ▼                          ▼                     │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Kubernetes API (CRDs, Secrets, ServiceAccounts, Pods,      │  │
│  │                 TokenReview)                               │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                            │                     │
│  ┌────────────────────────────┐            │                     │
│  │ Rate-limit store           │◀───────────┤                     │
│  │ (in-process or Redis)      │            │                     │
│  └────────────────────────────┘            │                     │
└────────────────────────────────────────────┼─────────────────────┘
                                             ▼
                               Backend (SMTP relay; future: Graph,
                                        SendGrid, Gmail)
```

### 4.2 Logical components

| Component | Responsibility | Deployment |
|---|---|---|
| **api-server** (`--mode=api`) | REST endpoint, token auth, gateway pipeline, upstream send | Deployment, horizontally scalable (chart default 2) |
| **smtp-proxy** (`--mode=smtp`) | SMTP submission endpoint, OAUTHBEARER / MailCredential (PLAIN, LOGIN) / pod-IP auth, gateway pipeline, raw relay | Optional Deployment, horizontally scalable (chart default 2 when enabled) |
| **controller** (`--mode=controller`) | Reconciles `MailBackend` / `ClusterMailBackend` / `MailPolicy` / `MailCredential`, status updates, validating webhook, periodic backend probes, credential Secrets and their guard check | Deployment with leader election (chart default 1) |
| **rate-limit store** | State for sliding-window counters | In-process memory (per replica) **or** external Redis (single node, Sentinel or Cluster) |

All three modes ship as one binary and one container image. The **gateway pipeline** (`internal/gateway`) is transport-agnostic: REST and SMTP only parse their wire format and map the pipeline result to their status codes, so policy, rate limiting, audit, metrics and tracing behave identically on both paths.

### 4.3 Custom resource definitions

API group and version: `sigillum.dev/v1alpha1`. Short names: `mb`, `cmb`, `mp`, `mc`; category `sigillum`.

#### 4.3.1 MailBackend / ClusterMailBackend

`MailBackend` (namespace-scoped) and `ClusterMailBackend` (cluster-scoped) represent a concrete mail system that Sigillum forwards messages to (send) and, in future, reads from. The pattern follows cert-manager's `Issuer` / `ClusterIssuer`:

- **`ClusterMailBackend`:** central backend provided by the platform (for example the corporate relay), referenceable from every namespace. `credentialsRef.namespace` is required.
- **`MailBackend`:** team-owned backend in the team's namespace, referenceable only from policies in that namespace. `credentialsRef` must stay in the backend's own namespace.

In both cases Sigillum components can only read the Secret if its namespace is the release namespace or listed in `rbac.allowedSecretNamespaces` (§4.10).

The spec is a **discriminated union**: `spec.type` selects which backend-specific block is read. Only `type: smtp` is implemented.

```yaml
apiVersion: sigillum.dev/v1alpha1
kind: ClusterMailBackend
metadata:
  name: corporate-smtp
spec:
  type: smtp                     # enum: smtp | microsoftGraph | sendgrid | gmail
  smtp:
    endpoints:                   # ordered failover list; first Ready one is used
      - host: smtp-primary.internal.example.com
        port: 587
        tls: starttls            # none | starttls (default) | tls
      - host: smtp-fallback.internal.example.com
        port: 587
        tls: starttls
    authType: PLAIN              # NONE (default) | PLAIN | LOGIN | CRAM-MD5; applies to all endpoints
    credentialsRef:              # required unless authType is NONE; applies to all endpoints
      name: corporate-smtp-credentials
      namespace: sigillum-system
    connectionTimeoutSeconds: 10 # 1–120, default 10
    heloDomain: sigillum         # optional, default "sigillum"
  allowedSenders:                # [v0.4.0] optional for smtp; the backend sends only for these (US-2.8)
    - "*@example.com"            # not subdomains: list each domain the policies use
    - "*@billing.noreply.example.com"
  healthCheck:
    enabled: true                # default true; false = assume Ready without probing
    intervalSeconds: 60          # minimum 10, default 60
status:
  capabilities:                  # declared by the driver at probe time
    - send
  endpointStatus:                # per endpoint, in spec order
    - host: smtp-primary.internal.example.com
      port: 587
      ready: true
    - host: smtp-fallback.internal.example.com
      port: 587
      ready: true
  conditions:
    - type: Ready                # True if at least one endpoint is Ready
      status: "True"
      reason: AtLeastOneEndpointReady   # or AllEndpointsDown, ProbeError, InvalidConfiguration, Ready
  lastProbeTime: "2026-04-18T09:05:00Z"
  observedGeneration: 1
```

`endpoints[].insecureSkipVerify` exists in the schema but the webhook rejects `true`.

With `healthCheck.enabled: false` the backend is reported Ready without probing, and `status.capabilities` stays empty.

**Secret layout per backend type** (keys in the referenced Secret):

| Type | Keys |
|---|---|
| `smtp` | `username`, `password` |
| `smtp` with `authType: XOAUTH2` [planned v0.4.0] | as the matching `microsoftGraph` or `gmail` mode below |
| `microsoftGraph` app-only [v0.4.0] | `client_secret` (plus tenant / client ID in the spec) |
| `gmail` service account [v0.4.0] | `service_account.json` |
| Delegated, Microsoft or Google [planned v0.4.0] | optional `refresh_token` from `sigillum oauth login`; `client_secret` for Google's desktop client (client ID in the spec). The controller keeps the current tokens in its own Secret `sigillum-oauth-<backend>` (US-6.3). |
| `sendgrid` [backlog] | `api_key` |

#### 4.3.2 MailPolicy (namespace-scoped)

```yaml
apiVersion: sigillum.dev/v1alpha1
kind: MailPolicy
metadata:
  name: billing-service-policy
  namespace: billing
spec:
  priority: 100              # higher wins; tie-break: name, alphabetically (default 0)
  subjects:                  # at least one; each entry has exactly one matcher
    - serviceAccount:
        name: billing-mailer
    - serviceAccountSelector:
        matchLabels:
          app.kubernetes.io/component: notifier
  backendRef:
    name: corporate-smtp
    kind: ClusterMailBackend # or MailBackend (same namespace); default ClusterMailBackend
  senderRestrictions:        # omitted = any sender; present with empty list = no sender
    allowedSenders:
      - billing@example.com
      - "*@billing.noreply.example.com"
  recipientRestrictions:     # omitted = any recipient
    allowedDomains:          # whole domains
      - example.com
      - customer.example.com
    allowedRecipients:       # single mailboxes or domain-anchored globs (v0.3.0)
      - qa@partner.example.org
      - "*@oncall.example.com"
    blockedDomains: []       # wins over both allowlists
  rateLimits:                # counted per policy, sliding window
    messagesPerMinute: 60
    messagesPerHour: 1000
    messagesPerDay: 5000     # below the mailbox's daily quota (v0.4.0)
  messageLimits:
    maxSizeBytes: 10485760   # 10 MiB (default)
    maxRecipients: 50        # default 50; counts to + cc + bcc (REST) or RCPT TO (SMTP)
  legacyAuth:
    podIPFallback: false     # true = SMTP pod-IP callers may match this policy
status:
  conditions:
    - type: Ready            # False if the backend is missing / not Ready / misconfigured
      status: "True"
      reason: Ready
    - type: UsingLegacyAuth  # True when legacyAuth.podIPFallback is set
      status: "False"
      reason: Disabled
  observedGeneration: 1
```

Webhook validation (in addition to the schema): at least one subject; exactly one matcher per subject; `serviceAccount.name` set; selectors non-empty and valid; `backendRef.name` set and `kind` known; no empty `allowedSenders` entries; recipient domains are bare domains; `allowedRecipients` entries are plain addresses without routing local parts, or globs anchored on a bare domain.

`status.matchedSubjects` exists in the schema but is never populated **[gap G-4]**. Its intended meaning (number of ServiceAccounts in the namespace the policy currently matches) needs a decision before it is implemented or removed.

#### 4.3.3 MailQuota (namespace-scoped) **[backlog]**

Namespace-wide quota, independent of individual policies. The per-policy daily limit (US-2.7) covers most needs; this resource is added only if users need one cap across all policies of a namespace:

```yaml
apiVersion: sigillum.dev/v1alpha1
kind: MailQuota
metadata:
  name: default
  namespace: billing
spec:
  messagesPerDay: 10000
```

#### 4.3.4 MailCredential (namespace-scoped) **[v0.3.0]**

A Sigillum-issued SMTP credential for clients that only support `AUTH PLAIN` / `LOGIN` (US-3.7).

Generated mode (default):

```yaml
apiVersion: sigillum.dev/v1alpha1
kind: MailCredential
metadata:
  name: grafana
  namespace: monitoring
spec:
  serviceAccountName: grafana     # identity the credential authenticates as (same namespace)
  secretName: grafana-smtp        # created and owned by the controller
  rotation:
    interval: 90d                 # optional; unset = rotate only on demand
    gracePeriod: 24h              # previous password stays valid this long (default 24h)
status:
  username: grafana.monitoring    # <name>.<namespace>, unique cluster-wide
  serviceAccountName: grafana     # ServiceAccount the controller accepted
  secretName: grafana-smtp        # Secret that holds the current password
  lastRotateRequest: ""           # last sigillum.dev/rotate value acted upon
  current:
    hash: "sha256:…"              # of a 256-bit random password; never the plaintext
                                  # (bring your own hash: the accepted spec.passwordHash)
    createdAt: "2026-10-01T08:00:00Z"
  previous:                       # present only during a rotation's grace period
    hash: "sha256:…"
    validUntil: "2026-10-02T08:00:00Z"
  conditions:
    - type: Ready                 # False: ServiceAccountNotFound, NamespaceExcluded,
      status: "True"              #   SecretConflict, SecretWriteFailed, GuardMissing,
                                  #   GeneratedModeDisabled, InvalidConfiguration
    - type: SecretsManaged        # generated mode: False while the credential
      status: "True"              #   Secret guard is missing or changed (§4.10)
```

The generated Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: grafana-smtp
  namespace: monitoring
  labels: { sigillum.dev/credential: grafana }
  annotations: { sigillum.dev/credential-uid: <uid of the MailCredential> }
  ownerReferences: [{ kind: MailCredential, name: grafana, uid: …, controller: true }]
type: Opaque
stringData:
  username: grafana.monitoring
  password: <256-bit random, base64url>
  host: sigillum-smtp.sigillum-system.svc
  port: "587"
```

Bring-your-own-hash mode: set `spec.passwordHash` (argon2id, PHC string format `$argon2id$v=19$m=<KiB>,t=<n>,p=<n>$<salt>$<hash>`) instead of `spec.secretName` and `spec.rotation`. The webhook rejects specs that set both, plaintext-looking values (without echoing them), and unknown hash formats. Parameters are bounded: memory 7–64 MiB, memory × passes ≥ 35 MiB (OWASP), passes ≤ 10, parallelism ≤ 16, salt ≥ 8 bytes. The upper bounds cap what one `AUTH` attempt can cost the proxy. User-chosen passwords may be weak, so this mode uses a deliberately slow hash; generated passwords are high-entropy, so a fast hash is safe and keeps authentication cheap.

A rotation interval below 1 h is rejected by the webhook and, if the webhook is disabled, reported by the controller as `InvalidConfiguration`. In generated mode the `MailCredential` name may have at most 63 characters, because it becomes the value of the Secret's `sigillum.dev/credential` label; the webhook rejects longer names and the controller reports `InvalidConfiguration`. Switching from bring your own hash to generated mode gives the old password no grace period: it is in no Secret, and generated mode cannot verify an argon2id hash.

Controller behavior in generated mode:
- The Secret is created; if it exists, its `data` is replaced with a JSON patch whose `test` operations require the `sigillum.dev/credential` label and `sigillum.dev/credential-uid` annotation of this `MailCredential`. The controller cannot read Secrets, so this is how it recognises a foreign Secret of the same name without reading it: such a Secret is not touched (reason `SecretConflict`, retried every minute: a recreated `MailCredential` usually just waits for the garbage collector to remove its predecessor's Secret). Missing RBAC is reported as `SecretWriteFailed`, not as a conflict. Both make the credential `Ready=False` only if it has no password yet; a password issued earlier stays valid in its Secret, also after `spec.secretName` changed, and the failure is reported in the `Ready` message. The credential Secret guard (§4.10) enforces the same rule independently.
- The controller decides on rotations from the `MailCredential` as read from the API server, not from its informer cache: a reconcile that started before the cache held the previous rotation's status would otherwise rotate again and leave a password in the Secret that status does not accept. For the same reason, once a new password is in the Secret, a failed status write is retried for about 12 s if the error is transient (conflict, timeout, throttling, unavailable API server). An unchanged status is not written again.
- The Secret is written before the status, and a conflicting status update is then retried against the latest object, so the hash of a password already in the Secret is not lost. If the status update still fails, the next reconcile issues another password; an issued hash therefore never lacks its Secret.
- A rotation with `gracePeriod: 0` also drops the previous hash of an earlier rotation.
- The controller cannot read Secrets (§4.10), so it neither notices nor restores a deleted Secret. A rotation (`sigillum.dev/rotate`) recreates it with a new password. The app's failing logins show up in the audit stream and the auth-failure metric.
- If a due rotation cannot be written (guard missing, write error), a previously issued password stays valid and `Ready` stays `True` with a message; only a credential that never got a password reports `Ready=False`.
- Changing `spec.secretName` issues a new password into the new Secret; the old Secret stays until the `MailCredential` is deleted.
- A `MailCredential` in an excluded namespace is rejected by the webhook, and ignored by the controller if it exists anyway (`Ready=False`, `NamespaceExcluded`).
- With generated mode disabled (chart `credentials.enabled: false`), the webhook rejects generated-mode credentials and the controller reports existing ones `Ready=False` (`GeneratedModeDisabled`).

### 4.4 REST API (v1)

**Base path:** `/v1`
**Content type:** `application/json`, or `multipart/form-data` for attachments (US-1.3)
**Auth:** `Authorization: Bearer <ServiceAccount token>` with audience `sigillum`
**Transport:** plain HTTP on port 8443 by default, expecting TLS from the mesh or a gateway. Native TLS when `SIGILLUM_TLS_CERT` / `SIGILLUM_TLS_KEY` are set (chart `api.tls.secretName`).

#### 4.4.1 POST /v1/messages **[v0.1.0]**

Request:
```json
{
  "from": "Billing <billing@example.com>",
  "to": ["customer@example.com"],
  "cc": [],
  "bcc": [],
  "subject": "Your invoice",
  "body": {
    "text": "Plain text version",
    "html": "<p>HTML version</p>"
  },
  "attachments": [
    {
      "filename": "invoice.pdf",
      "contentType": "application/pdf",
      "disposition": "attachment",
      "contentBase64": "JVBERi0xLjQK..."
    }
  ],
  "headers": {
    "X-Correlation-ID": "abc-123",
    "Reply-To": "support@example.com"
  }
}
```

Rules:
- At least one recipient across `to`, `cc`, `bcc`.
- Addresses are RFC 5322 (display names allowed, subject to US-2.3); local parts follow US-2.4.
- `disposition` is `attachment` (default) or `inline`.
- `headers`:
  - Keys and values must not contain CR, LF or NUL; values are at most 998 characters; each header at most once (case-insensitive).
  - `Resent-*` headers are rejected.
  - `From`, `To`, `Cc`, `Bcc`, `Subject`, `Date`, `Message-ID`, `MIME-Version`, `Content-Type` and `Content-Transfer-Encoding` are managed by Sigillum; values supplied here are **silently dropped**.
  - `Sender` and `Reply-To` are allowed and checked against the policy (US-2.3, US-2.4).
- Hard request ceiling: 32 MiB, independent of policy (`413`).

Response `202 Accepted`:
```json
{
  "messageId": "8f2e0c1a-…",
  "policyMatched": "billing-service-policy",
  "acceptedAt": "2026-04-18T09:10:00Z"
}
```

`messageId` also appears in the audit record and as the local part of the RFC 5322 `Message-ID` (`<messageId@sigillum.local>`).

Error responses follow RFC 7807, with the Sigillum extension members `policy` and `messageId`:
```json
{
  "type": "https://sigillum.dev/errors/sender-not-allowed",
  "title": "Sender address not allowed by policy",
  "status": 403,
  "detail": "sender 'evil@example.com' not in allowedSenders",
  "policy": "billing-service-policy",
  "messageId": "8f2e0c1a-…"
}
```

#### 4.4.2 POST /v1/policies/preflight **[planned v0.5.0]**

Dry run before sending:
- Request: identical to `POST /v1/messages`. (`POST`, not `GET`: the request carries a body.)
- Response: would-accept / would-reject with the matched policy and reason. No upstream call and no rate-limit charge.
- Purpose: debugging tool for developers and policy authors.

#### 4.4.3 Status codes

The problem `type` is `https://sigillum.dev/errors/<slug>`. The audit / metric `reason` uses the same word in snake_case.

| Status | Problem slug | Meaning | Retry? |
|---|---|---|---|
| `202` | — | Accepted by the backend | — |
| `400` | `invalid-payload` | Malformed JSON / multipart, invalid address or header, no recipient | No, fix the request |
| `401` | `invalid-token` | Missing, invalid, expired or wrong-audience token | No, fix the token |
| `403` | `no-policy-matched` | No policy matches the caller | No |
| `403` | `sender-not-allowed` | US-2.3 | No |
| `403` | `recipient-not-allowed` | US-2.4 (recipients or `Reply-To`) | No |
| `403` | `too-many-recipients` | Over `maxRecipients` | No |
| `413` | `message-too-large` | Over `maxSizeBytes` or the 32 MiB ceiling | No |
| `429` | `rate-limited` | US-2.2; `Retry-After` header | Yes, after `Retry-After` |
| `422` | `upstream-rejected` | The relay permanently rejected this message (`5xx` to `MAIL`, `RCPT` or `DATA`) **[v0.3.0]** | No, not unchanged |
| `502` | `upstream-error` | Upstream relay failed transiently (unreachable, `4xx`, or a handshake / TLS / relay-login problem on Sigillum's side) | Yes, with backoff |
| `503` | `backend-not-ready` | Backend missing, not Ready, or its config could not be resolved | Yes, with backoff |
| `503` | `unavailable` | Redis rate-limit store unreachable (fail closed), or the TokenReview failed (v0.3.0); `Retry-After: 5` | Yes |
| `503` | `shutting-down` | Replica is draining | Yes, immediately |
| `501` | `not-implemented` | Reserved for operations the backend's capabilities do not cover [future] | No |

#### 4.4.4 Size accounting

`maxSizeBytes` measures content **without transfer-encoding overhead**: an 8 MiB attachment counts as 8 MiB, not as its ~11 MiB Base64 form.

- **REST:** subject + custom header keys and values + `body.text` + `body.html` + decoded attachments.
- **SMTP:** the relayed message with Base64 / quoted-printable parts counted at their decoded size. Headers and MIME framing are included.

#### 4.4.5 GET /v1/capabilities **[future]**

Returns the capabilities available to the authenticated caller, computed from the matching policies and their backends. Not scheduled; see §4.5.

### 4.5 Backend drivers and capability model

**Driver interface.** Each backend is a driver implementing a common Go interface (`internal/driver`). It stays send-only until the first read-capable driver exists; read operations will be added then, without changing existing methods.

```go
type Driver interface {
    Type() Type                      // smtp | microsoftGraph | ...
    Capabilities() []Capability      // send, read, subscribeEvents, folders

    // HealthCheck probes every configured endpoint; results are written
    // to status.endpointStatus.
    HealthCheck(ctx context.Context) []EndpointHealth

    // Send delivers msg via the first Ready endpoint. Errors wrap
    // ErrNoReadyEndpoint, ErrUpstreamTransient or ErrUpstreamPermanent.
    Send(ctx context.Context, msg *Message) (*SendResult, error)

    io.Closer
}

// Optional: drivers that can relay an assembled RFC 5322 message unchanged.
// The SMTP proxy requires it so legacy clients' MIME structure, headers and
// signatures survive untouched.
type RawSender interface {
    SendRaw(ctx context.Context, envelopeFrom string, recipients []string, raw []byte) (*SendResult, error)
}

// future, when a read-capable driver lands (as methods or optional interfaces):
// Read(ctx, *ReadRequest) (*ReadResult, error)
// Subscribe(ctx, *SubscribeRequest) (<-chan *Event, error)
```

**OAuth token sources [v0.4.0, internal].** Drivers whose upstream takes no password (US-6.1 to US-6.3) get their access tokens from `internal/oauth`. A `Source` fetches a new token; the first one is the client credentials grant (`ClientCredentials`, client ID and secret in the request body), and later rows add the Google service-account assertion and refresh tokens. A `Cache` in front of it is what a driver calls on every send:

- Concurrent callers share one fetch, and a caller's cancellation does not end the fetch the others wait for.
- A token is replaced 5 minutes before expiry (at half its lifetime if it lives less than 10 minutes). Meanwhile callers get the current token without waiting; if the refresh fails, the current token is used until 30 s before its expiry.
- A failed fetch is answered from memory for 10 s, or the endpoint's `Retry-After` if longer, so a wrong secret does not hit the token endpoint on every send.
- `Invalidate` drops a token the upstream rejected with `401`, but only if it is still the cached one.
- Failures are classified for the drivers' error mapping: `429`, `408`, `5xx`, `temporarily_unavailable` and transport errors are transient; any other answer (`invalid_client`, `invalid_scope`, `404`, a redirect) is permanent, which makes the backend `Ready=False` through its health check.
- The token endpoint must be `https`, redirects are never followed (the secret goes only to the configured endpoint), and a Microsoft tenant must be a tenant ID or domain before it becomes part of the URL. The answer is limited to 1 MiB, the access token must be an RFC 6750 `b64token` (it ends up in `Authorization` headers and SASL `XOAUTH2` strings), `expires_in` is capped at 24 hours (5 minutes if missing), and the provider's error text is reduced to printable ASCII. `Token` values print without the token.
- `internal/oauth/oauthtest` is a fake token endpoint for the tests of the drivers that use it.

Drivers register a factory per type in a process-wide registry. The webhook rejects backend types without a registered factory. The SMTP driver supports STARTTLS and implicit TLS, `PLAIN` / `LOGIN` / `CRAM-MD5`, and MIME multipart assembly.

**Capability matrix** (target picture; implemented are the `smtp` row and `send` for `microsoftGraph` [v0.4.0]; `send` for `gmail` is planned for v0.4.0):

| Backend type | send | read | subscribeEvents | folders |
|---|---|---|---|---|
| `smtp` | ✓ | ✗ | ✗ | ✗ |
| `microsoftGraph` | ✓ | ✓ | ✓ | ✓ |
| `gmail` | ✓ | ✓ | ✓ (via Pub/Sub) | ✓ |
| `sendgrid` | ✓ | ✗ | ✓ (bounce webhook) | ✗ |
| `imap` (future) | ✗ | ✓ | ✓ (IDLE) | ✓ |

**Capability propagation:**
- The controller writes the driver's capabilities into `status.capabilities` on each probe.
- The gateway must refuse an operation the backend does not advertise **[gap G-2]**; once non-send operations exist, those requests return `501 not-implemented`.
- `GET /v1/capabilities` (§4.4.5) will expose capabilities up front **[future]**.

### 4.6 SMTP proxy behavior **[v0.2.0]**

- Listens on container port 2587; the Service exposes 587 (submission).
- **Authentication:** `AUTH OAUTHBEARER` (US-3.4) is offered whenever mode `oauthbearer` is enabled (default). `AUTH PLAIN` / `LOGIN` with a `MailCredential` (US-3.7) is mode `credential` **[v0.3.0]**, offered only after STARTTLS unless `allowInsecureAuth` is explicitly `true`. A client that sends `MAIL FROM` without authenticating is identified by pod IP only if mode `podip` is enabled (US-3.5); otherwise it gets `530 5.7.0 Authentication required`.
- STARTTLS is offered when `smtp.tls.secretName` is set. AUTH on plaintext connections follows `smtp.allowInsecureAuth` (US-3.4).
- **Envelope rules:** the null sender `<>` is refused (`550 5.7.1`). `MAIL FROM` and `RCPT TO` must be plain mailbox addresses (US-2.4 local-part rules); otherwise `553`.
- **Message rules** (checked at the end of `DATA`): exactly one `From` field holding exactly one address; at most one `Sender` field (holding exactly one address) and at most one `Reply-To` field; no `Resent-*` fields; display names per US-2.3. Violations answer `550 5.6.0`.
- **Policy input:** header `From`, envelope sender and `Sender` against `allowedSenders`; the envelope recipients (`RCPT TO`, not the `To`/`Cc` headers) and `Reply-To` against `recipientRestrictions`.
- **Relay:** the message is relayed byte-for-byte via the driver's `RawSender`, with a prepended `Received` header carrying the Sigillum message ID and the protocol per RFC 3848 (`ESMTP`, `ESMTPA` when authenticated, `ESMTPS`/`ESMTPSA` over STARTTLS). `Bcc:` header fields are removed before relaying.
- **Limits:** `--max-message-bytes` (default 32 MiB) and `--max-recipients` (default 100) are hard ceilings; policies enforce lower limits. `--max-concurrent-messages` (default 4) bounds memory use per pod; excess messages wait up to `--send-timeout` and then get `451 4.3.2`.
- Pod lookup for `podip` uses an informer cache of pods.
- Otherwise the same gateway pipeline as REST (§4.2).

**SMTP reply codes:**

| Situation | Reply |
|---|---|
| Accepted | `250` |
| AUTH failed | `535 5.7.8` |
| AUTH PLAIN / LOGIN without TLS | `538 5.7.11` |
| Too many failed logins, credential lookup or TokenReview failed, credential revoked since AUTH | `454 4.7.0` |
| Not authenticated, no pod-IP identity | `530 5.7.0` |
| Malformed sender / recipient path | `553 5.1.7` / `553 5.1.3` |
| Null sender, policy denial (no policy, sender, recipient) | `550 5.7.1` |
| Too many recipients for policy | `550 5.5.3` |
| Over policy size | `552 5.3.4` |
| Malformed message | `550 5.6.0` |
| Rate limited | `421 4.7.0` (see Q-7) |
| Upstream transient / backend not ready / limiter down / busy | `451` |
| Upstream permanent rejection | `554 5.0.0` |

Each reply after `DATA` carries the Sigillum message ID for correlation with the audit log.

### 4.7 State management

- **Stateless core:** api-server and SMTP proxy keep no persistent state.
- **Rate-limit state:** pluggable (`--ratelimit-backend`, chart `rateLimit.backend`):
  - `memory` (chart default): per-process sliding window. Correct only with one replica per mode; with N replicas the effective limit is up to N times the configured one.
  - `redis`: one shared sliding window. Single node, Sentinel (`masterName`) or Cluster (several addresses), optional TLS and password Secret. When Redis is unreachable, requests fail closed with `503 unavailable` unless `rateLimit.failOpen=true`.
- **Caches:** controller-runtime informer caches for Sigillum CRs (the SMTP proxy with mode `credential` also `MailCredential`), ServiceAccounts, Secrets (only the release namespace and `rbac.allowedSecretNamespaces`, flag `--secret-namespaces`; before v0.3.0 the Secret informer was cluster-wide and could not start with the chart's namespaced RBAC) and, with `podip`, Pods. TokenReview results are cached in an LRU (§5.3).
- **No mail queue:** on upstream failure the caller gets `502` / `451` and owns the retry. A retry queue is open question Q-3.

### 4.8 Audit record format **[v0.2.0]**

One JSON object per line. Field names are a public contract; SIEM pipelines key on them, so they change only with a version bump.

| Field | Type | Content |
|---|---|---|
| `stream` | string | Always `"audit"` |
| `timestamp` | string | RFC 3339, UTC |
| `message_id` | string | Sigillum message ID (also for rejected requests) |
| `namespace` | string | Caller namespace (omitted if unauthenticated) |
| `service_account` | string | Caller ServiceAccount (omitted if unauthenticated) |
| `auth_method` | string | `oauth_bearer`, `smtp_credential` (v0.3.0) or `pod_ip_legacy` (omitted if unknown) |
| `credential` | string | MailCredential username for `smtp_credential`, also on failed logins when the supplied username is well-formed (v0.3.0; omitted otherwise) |
| `credential_previous` | bool | `true` when the previous password of a rotation was used (v0.3.0; omitted otherwise) |
| `cluster` | string | Cluster name from `--cluster-name` (v0.3.0; omitted if unset) |
| `transport` | string | `rest` or `smtp` |
| `from` | string | Header `From` address (raw value if it failed to parse) |
| `to` | string[] | All recipients, including Bcc / envelope recipients; `[]` if none known |
| `policy` | string | Matched policy (omitted if none) |
| `backend` | string | `<ns>/<name>` for `MailBackend`, `/<name>` for `ClusterMailBackend` |
| `decision` | string | `accept` or `reject` |
| `reason` | string | Rejection reason (omitted on accept), see below |

Rejection reasons: `missing_token`, `invalid_token`, `invalid_credentials`, `auth_rate_limited`, `auth_unavailable`, `auth_required`, `pod_ip_unresolved`, `shutting_down`, `busy`, `null_sender`, `invalid_payload`, `message_too_large`, `no_policy_matched`, `sender_not_allowed`, `recipient_not_allowed`, `too_many_recipients`, `backend_not_ready`, `rate_limited`, `ratelimit_unavailable`, `upstream_error`, `upstream_rejected`. (`upstream_rejected` replaces `upstream_error` for permanent rejections since v0.3.0, on both transports.)

The record never contains subject, body, attachment content, header values other than addresses, tokens or passwords.

### 4.9 Trust model and policy governance

- **Sigillum enforces, the platform governs.** A `MailPolicy` is the authorization grant: whoever can write one in a namespace can let that namespace's ServiceAccounts send through any backend they may reference, under any sender they list. Sigillum does not second-guess policy content.
- **Who may author policies is the platform team's decision**, expressed with standard tools:
  - **RBAC.** The chart's aggregated roles (US-3.6) delegate `MailPolicy` authoring to every `edit` holder by default. Platforms that keep authoring central set `rbac.aggregateClusterRoles: false` and bind a dedicated role to the platform or security team, or to selected namespace owners.
  - **Admission policy** (Kyverno, OPA Gatekeeper, `ValidatingAdmissionPolicy`) for content guardrails (tested recipes: US-5.7), for example: only certain namespaces may reference a given `ClusterMailBackend`; `allowedSenders` must stay within a team's domain; `legacyAuth.podIPFallback` is forbidden; `senderRestrictions` is mandatory in production namespaces.
- **Backends.** `ClusterMailBackend` is platform-owned (`admin` only by default). Any namespace whose policy authors can write a `MailPolicy` may reference it. A native restriction on the backend (namespace selector, similar to Gateway API `allowedRoutes`) is not planned; the admission recipe in US-5.7 covers it (Q-8).
- **Credentials** never leave the Sigillum components. Callers authenticate with their own identity and never see relay credentials.

### 4.10 Component permissions

| Component | Kubernetes permissions |
|---|---|
| api-server | read Sigillum CRs and ServiceAccounts (cluster-wide); read Secrets in the release namespace and `rbac.allowedSecretNamespaces`; create `TokenReview` |
| smtp-proxy | as api-server; plus `list`/`watch` Pods cluster-wide when `podip` is enabled, and `get`/`list`/`watch` `MailCredential` objects for mode `credential`, never the credential Secrets. |
| controller | read/watch Sigillum CRs, update their status; read Secrets as above; read/watch ServiceAccounts (MailCredential); `get` the credential guard policy and binding by name; leader-election leases; create events; serves the webhook. With generated credentials: `create` and `patch` on Secrets cluster-wide, **without** `get`, `list` or `watch`, restricted by the credential guard below. |

The api-server and SMTP proxy read backend credentials themselves on the send path, so a `MailBackend` in a team namespace works only if that namespace is listed in `rbac.allowedSecretNamespaces`.

**Credential Secret guard [v0.3.0].** Generated credentials (US-3.7) are available in all namespaces by default, so the controller needs to write Secrets anywhere. RBAC cannot narrow `create` by name or label, so the chart ships a `ValidatingAdmissionPolicy` and binding that apply to requests from the controller's ServiceAccount only:

- The Secret must carry the label `sigillum.dev/credential`, the annotation `sigillum.dev/credential-uid`, and a controller owner reference to the `MailCredential` named in the label with that UID. On update, the existing Secret must already carry the same label and UID annotation. The controller therefore cannot modify or take over any other Secret, such as TLS certificates or database passwords, nor move a credential Secret to another `MailCredential`.
- The Secret must be of type `Opaque` and hold only the keys `username`, `password`, `host` and `port`. Otherwise a Secret of type `kubernetes.io/service-account-token` would make the token controller fill it with a token of any ServiceAccount in the namespace.
- The namespace must not match `credentials.excludeNamespaces`, and must not be the release namespace (which holds the relay credentials).
- `DELETE` is not needed: owned Secrets are garbage-collected with their `MailCredential`.
- **[v0.4.0]** A second allowed shape for the OAuth token Secrets of delegated backends (US-6.3): label `sigillum.dev/oauth-token` with the backend's name, its UID in the annotation `sigillum.dev/oauth-token-uid`, a controller owner reference to that `MailBackend` or `ClusterMailBackend`, type `Opaque`, only the keys `refresh_token`, `access_token` and `expires_at`. It is allowed in the release namespace, where a `ClusterMailBackend`'s credentials usually live, and in every namespace that is not excluded; the excluded namespaces stay closed to both shapes. A Secret has exactly one shape: one carrying both labels is denied, and an update must keep the shape, owner label and UID of the existing Secret, so neither shape can take over a Secret of the other or the relay credentials in the release namespace. The guard is rendered with `credentials.enabled`; delegated backends will need it too.

Without `get`, `list` or `watch`, the controller cannot read any Secret outside the backend-credential namespaces it already had. Worst case, a compromised controller can overwrite or create mail-credential Secrets; it cannot read or change anything else.

The guard is mandatory for generated mode:
- The chart requires Kubernetes 1.32 or later (`kubeVersion`, the oldest version still in LTS support); `admissionregistration.k8s.io/v1` `ValidatingAdmissionPolicy` is GA since 1.30. It renders the controller's Secret-write permission only together with the guard, and neither with `credentials.enabled: false`.
- At startup, before any reconciler runs, and every `--credential-guard-check-interval` (default 5 min; every 30 s while it fails) the controller checks that the guard policy and binding exist and are unchanged: it rebuilds the expected policy from its own flags (`--credential-exclude-namespaces`, its ServiceAccount) and compares failure policy, match constraints, match conditions, variables, validation expressions and the binding's actions. If they differ, it refuses to write Secrets and reports it (`SecretsManaged=False`, reason `GuardMissing`, on every generated `MailCredential`; error log; `sigillum_credential_guard_ok 0`). A lookup that fails for another reason (a timeout, an API server restart) keeps the last verdict, so one failed request does not flip every credential's condition. Bring-your-own-hash mode keeps working. The chart renders the same policy; a CI test renders the chart and runs the controller's check against it. The chart grants the Secret write permission only together with the guard; the role generated from the kubebuilder markers (`config/rbac`) deliberately lacks it.
- Ordering: Helm applies kinds it does not know, such as `ValidatingAdmissionPolicy`, after RBAC objects on install and deletes them after RBAC objects on uninstall (Helm 3 and 4). On uninstall the permission therefore goes first. On install and upgrade the Secret-write binding exists a moment (a few API calls in the same pass) before the guard. On a fresh install no controller runs yet, and a controller from before v0.3.0 has no code that writes Secrets. Helm hooks would reverse the order, but hook resources survive `helm uninstall`, and `before-hook-creation` would delete and recreate the guard on every upgrade while the controller runs. The chart therefore keeps plain resources.

Chart values:

```yaml
credentials:
  enabled: true              # generated mode; false = bring-your-own-hash only
  excludeNamespaces:         # exact names, or prefixes ending in one "*" (other "*" fail the render)
    - "kube-*"               # kube-system, kube-public, kube-node-lease, …
  # The release namespace is always excluded. Add platform namespaces you
  # never want to hold mail credentials, for example cert-manager or
  # istio-system.
  smtpHost: ""               # written into generated Secrets; default: the SMTP proxy Service
  smtpPort: null             # default: smtp.service.port
```

### 4.11 Request flow (REST)

```
App pod → POST /v1/messages, Authorization: Bearer <token>
        │
        ▼
auth middleware ── TokenReview (audience sigillum, LRU cache) ── 401 on failure
        │
        ▼
payload parsing ── JSON / multipart, addresses, headers, size ceiling ── 400 / 413
        │
        ▼
policy.evaluate ── list MailPolicies in caller namespace, match subjects,
        │          pick priority / name winner, check size, recipients count,
        │          senders, recipients, Reply-To ── 403 / 413
        ▼
backend resolve ── backendRef → Ready backend → backend allowedSenders → credentials Secret ── 503 / 403
        │
        ▼
ratelimit.allow ── sliding window per policy (memory or Redis) ── 429 / 503
        │
        ▼
backend.send ── driver.Send via first Ready endpoint ── 502 (refund if transient)
        │
        ▼
202 Accepted  (+ one audit record, log line and metrics for every outcome)
```

The SMTP path is identical from `policy.evaluate` on; authentication happens at `AUTH` (or `MAIL FROM` for pod-IP) and payload parsing at the end of `DATA`.

---

## 5. Non-functional requirements

### 5.1 Performance

| Metric | Target |
|---|---|
| REST latency p50 (excluding upstream send) | < 30 ms |
| REST latency p99 (excluding upstream send) | < 150 ms |
| Throughput per pod (CPU request 500m) | ≥ 200 messages/s |
| TokenReview cache hit rate | ≥ 95 % |

These targets are not yet verified by a benchmark in CI.

### 5.2 Availability

- **SLO:** 99.9 % availability of the REST API.
- **Redundancy:** at least 2 api-server replicas in production (chart default), PDB `minAvailable: 1`, Redis rate-limit store (§4.7).
- **Topology:** `topologySpreadConstraints` across zones for multi-zone clusters (chart value, empty by default).

### 5.3 Security

| Requirement | Implementation |
|---|---|
| TLS | api-server: native TLS optional, otherwise mesh / gateway. SMTP: STARTTLS optional, otherwise mesh. Upstream: STARTTLS by default, certificate verification cannot be disabled. |
| Secret handling | Upstream credentials only in Kubernetes Secrets, never inline in CRs |
| Secret namespace isolation | `MailBackend`: own namespace only. `ClusterMailBackend`: explicit namespace. Readable only in the release namespace and `rbac.allowedSecretNamespaces`. |
| Log hygiene | No tokens, passwords or mail content in logs or audit records |
| Token audience binding | `TokenReview` with `audiences: [sigillum]` and verification of `status.audiences`, for REST, SMTP SASL and (future) IMAP SASL |
| Token cache | Positive and negative results cached for `tokenCacheTTL` (default 5 min), keyed by SHA-256 of the token. A positive entry never outlives the token's own `exp` claim (read without verification, only to shorten the TTL) **[v0.3.0]**. **Revocation latency:** a token that is invalidated before it expires (pod or ServiceAccount deleted) stays accepted until its cache entry expires, up to the TTL. |
| Header spoofing | `@` banned in display names; `Sender` / `Reply-To` checked; `Resent-*` and duplicate headers rejected; managed headers cannot be overridden (§4.4.1, §4.6) |
| Address routing | `%`, `!` and quoted local parts rejected (US-2.4) |
| SMTP credentials | Generated: 256-bit random, only SHA-256 in status; bring your own: argon2id with bounded parameters. TLS required by default, failed logins throttled, revocation immediate (§4.3.4, US-3.7). Controller writes Secrets only through the credential Secret guard (§4.10). |
| Pod Security Standard | Compatible with `restricted` |
| SBOM / signing | Releases after v0.2.1: image and chart signed keyless with cosign, SLSA build provenance via GitHub artifact attestations, SPDX SBOM and BuildKit provenance per platform; base images pinned by digest, Actions by commit SHA (README, "Supply chain") |
| Dependency scanning | CI: `govulncheck` (reachable vulnerabilities), dependency review on PRs (moderate and above), CodeQL for Go and workflows, actionlint and zizmor for workflows and local actions; Dependabot weekly updates with cooldown, security updates immediately |

### 5.4 Scalability

- **Horizontal scaling:** stateless api-server and SMTP proxy scale via HPA (CPU or request rate).
- **Rate-limit store:** Redis Cluster or Sentinel.
- **Cluster size:** design target of 10,000 `MailPolicy` objects and 100 backends (`MailBackend` + `ClusterMailBackend`) per cluster. Policies are listed per request from the informer cache, filtered by namespace.

### 5.5 Observability

- Metrics per US-4.1, logs per US-4.2 and US-4.3, traces per US-4.4.
- Grafana dashboard and alert rules in the Helm chart (US-4.6) **[planned v0.5.0]**.

### 5.6 Compliance

- **Audit retention:** ensured by log aggregation outside Sigillum; the record format is fixed (§4.8).
- **BSI:** usable as evidence component for access control on mail sending (§31 BSIG).
- **GDPR:** no persistence of personal data beyond the transient audit and operational logs, which contain addresses.

### 5.7 Operability

- Installation via Helm in under 5 minutes.
- Configuration fully GitOps-capable.
- Rolling upgrades without mail loss via graceful shutdown with a readiness delay (US-5.3).
- Runbooks for: upstream outage, rate-limit store outage, CRD upgrade / migration **[planned v0.5.0]**.

### 5.8 Maintainability

- Go codebase following Kubernetes code conventions.
- Unit test coverage ≥ 70 %.
- Envtest suite for reconcilers and webhooks; E2E smoke test against kind + Mailpit (`make e2e`).
- Semantic versioning; API group `sigillum.dev` graduates `v1alpha1` → `v1beta1` → `v1`.

### 5.9 Extensibility

- **Driver interface** is an internal, stable Go interface; new backends are additive, without CRD schema breaks.
- **API versioning** allows additive endpoints (for example `/v1/mailboxes`) without breaking `/v1/messages`.
- **No backend type leaks into the REST API:** `POST /v1/messages` is protocol-agnostic. Developers cannot tell whether SMTP, Graph or SendGrid sits behind it, apart from backend-specific error details.
- **Protocol adapters** (SMTP proxy, later IMAP proxy) are separate, optionally enabled deployments on the shared gateway pipeline.
- **Capability advertising** avoids silent loss of function: unsupported operations answer `501` and will be visible up front via `GET /v1/capabilities` [future].

---

## 6. Technology decisions

| Area | Decision | Rationale |
|---|---|---|
| Kubernetes | 1.32 or later (chart `kubeVersion`); envtest and the kind E2E run on a current release (1.36) | Oldest minor still in (LTS) support; `ValidatingAdmissionPolicy` for the credential Secret guard |
| Language | Go (module `go 1.27`, toolchain 1.27) | Ecosystem, kubebuilder, performance |
| Framework | controller-runtime / kubebuilder markers | De-facto standard for operators |
| REST router | chi | Small, low-dependency |
| SMTP | `emersion/go-smtp` + `emersion/go-sasl` | RFC-compliant, including OAUTHBEARER (RFC 7628) |
| Rate limiting | Sliding window: in-process, or Redis sorted set + Lua (`go-redis`) | Horizontal scaling, small footprint |
| Token cache | `hashicorp/golang-lru` | Bounded memory |
| Admission | ValidatingAdmissionWebhook (controller-runtime), cert via cert-manager or existing secret | Consistency at apply time |
| Logging | `log/slog` (stdlib), JSON | Structured, no dependency |
| Metrics | `prometheus/client_golang` | Standard |
| Tracing | OpenTelemetry Go, OTLP/HTTP | Vendor-neutral |
| Container base | `distroless/static:nonroot`, pinned by digest | Minimal, no shell |
| Build / release | Multi-arch `docker buildx` and Helm packaging in GitHub Actions (no third-party actions); cosign (checksum-pinned binary) and `actions/attest` for signing and provenance | Reproducible, verifiable, few supply-chain dependencies |
| Chart distribution | OCI registry | GitOps-compatible |
| Backend drivers | In-process Go interface; gRPC plugins as an option after 1.0 | Simple first; Crossplane-style evolution path |

---

## 7. Boundaries

See also §1.4 (permanent non-goals) and §1.5 (anticipated, not before 1.0). Additionally:

- **No replacement for anti-spam gateways:** Sigillum performs no content filtering or spam checks.
- **No delayed delivery:** messages are handed to the backend synchronously; there is no queue for scheduled sending.

**Left to the upstream mail system.** Sigillum does not replicate what relays and mail providers already do well. Recipes in the docs show where to configure it:

| Concern | Where it belongs |
|---|---|
| Bounces, delivery status, complaint handling | Provider dashboards and webhooks (SES, Postmark, Mailgun, SendGrid), Exchange message trace |
| Suppression lists | Provider suppression lists (SES account-level suppression, Postmark, Mailgun) |
| Journaling / archiving of sent mail | Exchange Online journaling rules, Google Vault, provider archive features |
| DKIM, SPF, DMARC | Provider / relay (§1.4) |
| Attachment and content filtering | Exchange transport rules / Defender, Google Workspace content compliance. A simple attachment-type rule in `MailPolicy` stays in the backlog for providers that lack it (§8.8). |
| Sending reputation, IP warm-up, retries to the recipient MX | Provider / relay |

---

## 8. Roadmap

### 8.0 Versioning and prioritization

**Versioning.** Sigillum stays below 1.0 until it has run in production at independent installations and their feedback is in (exit criteria in §8.7). Minor versions (0.x.0) may still change CRDs in breaking ways, always with a documented migration; patch versions (0.x.y) never do.

**Target users.** Individuals running a home lab or a small cluster, sending through a personal mailbox (Outlook.com, Gmail); they are likely among the first users of a young project maintained by one person. Small and medium organizations: one to a few clusters (typically staging and production), a small platform team or a single operator, a hosted mail provider (Microsoft 365, Google Workspace, Amazon SES, Mailgun, Postmark, …) or a company relay as upstream, and plenty of off-the-shelf software next to in-house services. Large fleets and very large enterprises are welcome, but their needs are not prioritized yet.

**Rules, applied in order:**

1. **Unblock common setups first.** A feature that decides whether typical workloads or providers can use Sigillum at all comes before anything else.
2. **Recipe before feature.** When standard Kubernetes tools already solve it (NetworkPolicy, Kyverno, `ValidatingAdmissionPolicy`, cert-manager, External Secrets, Mailpit), ship a tested recipe instead of code.
3. **Don't replicate the upstream.** Bounces, delivery status, suppression lists, journaling, DKIM and content filtering belong to the mail provider (§7).
4. **Cheap and safe goes early.** Small fixes to known gaps (§9.3) and security hardening ship in the next minor release.
5. **Large-scale features wait for demand.** Multi-cluster gateways, fleet-wide quotas and cloud workload identity move up only when users ask.

**Delivery in small pull requests.** A release is a sequence of pull requests that each do one thing and can be reviewed in one sitting, not one pull request per release (v0.3.0 arrived as one pull request of about 9,400 changed lines in 115 files, followed by a second one for its review findings). Each roadmap section lists its pull requests in order; `CONTRIBUTING.md` has the size rules.

### 8.1 Released

- **v0.1.0 (MVP):** `POST /v1/messages` with attachments (JSON and multipart); ServiceAccount token auth; CRDs `MailBackend`, `ClusterMailBackend`, `MailPolicy` (`type: smtp`); in-memory rate limiting; sender restrictions; Prometheus metrics; structured logs; Helm chart; validating webhook; controller with backend health checks.
- **v0.2.0:** SMTP proxy with OAUTHBEARER and pod-IP fallback; Redis rate-limit store; audit stream and shared gateway pipeline; recipient restrictions; OpenTelemetry tracing.
- **v0.3.0:** see §8.2. `MailCredential` with `AUTH PLAIN` / `LOGIN` on the SMTP proxy, generated passwords behind the credential Secret guard, rotation and bring-your-own argon2id hashes; `allowedRecipients` (exact and glob, #6); `--cluster-name`; `422 upstream-rejected` (G-1); shutdown delay (G-3); token cache bounded by `exp` (G-5); Secret informer restricted to the readable namespaces; recipes in `examples/` (local development, egress, admission, providers, clients, Reloader).
- **v0.2.1 (security patch):** address hardening (`%`, `!`, `@`, quoted local parts; no `@` in display names); `Sender` and `Reply-To` checks; `Resent-*` and duplicate headers rejected; REST size accounting includes subject and custom headers; header values ≤ 998 characters; `smtp.allowInsecureAuth` follows `smtp.tls.secretName`; Helm warnings for plaintext operation and `rateLimit.failOpen`.

### 8.2 v0.3.0 — Works with off-the-shelf apps, cannot be bypassed (released)

Goal: a small team can route *all* cluster mail through Sigillum, including third-party software, and make sure nothing goes around it. All items shipped in v0.3.0.

| Item | Type | Ref |
|---|---|---|
| Sigillum-issued SMTP credentials (`MailCredential`, `AUTH PLAIN` / `LOGIN`), generated in all non-excluded namespaces, with rotation and the credential Secret guard | Feature | US-3.7, §4.3.4, §4.10 |
| Per-address recipient allowlist (`allowedRecipients`) | Feature | US-2.4 |
| Cluster name in audit, logs and metrics | Feature | US-4.5 |
| Token cache bounded by token expiry | Gap fix | G-5 |
| Permanent vs. transient upstream failures distinguishable on REST | Gap fix | G-1 |
| `preStop` delay before draining | Gap fix | G-3 |
| Egress and admission recipes (NetworkPolicy, Cilium, Kyverno, `ValidatingAdmissionPolicy`) | Recipe | US-5.7 |
| Local development recipe with Mailpit | Recipe | US-7.1 |
| Provider recipes: Microsoft 365 (SMTP AUTH, relay connector, High Volume Email), Azure Communication Services, Google Workspace, Amazon SES, Mailgun, Postmark, Brevo via SMTP; Grafana, Alertmanager, Gitea, Nextcloud, Keycloak, Argo CD notifications as clients | Recipe | §8.0 rule 2 |
| Restart apps on credential rotation with Stakater Reloader | Recipe | US-3.7 |

### 8.3 v0.4.0 — Microsoft 365 and Gmail

Goal: keep sending through Microsoft 365 once password logins, app passwords included, are switched off at the end of December 2026; make personal Outlook.com accounts usable at all (they lost password logins already); make personal Gmail accounts and Google Workspace usable without an app password; protect the mailboxes' daily quotas. Target: released before the end of December 2026.

The release is built as a sequence of small pull requests (§8.0, `CONTRIBUTING.md`), each merged to `main` on its own with tests, docs and a changelog entry. Order: Microsoft first (hard deadline), and Outlook.com before Gmail, because personal Gmail accounts still work today with an app password and Outlook.com accounts do not work at all.

| # | Pull request | Depends on | Usable afterwards | Ref |
|---|---|---|---|---|
| 1 | Daily limit `rateLimits.messagesPerDay` (done) | — | Daily cap per policy | US-2.7 |
| 2 | `spec.allowedSenders` on backends, for `smtp` (done) | — | Pin a relay to its domains | US-2.8 |
| 3 | OAuth token sources (`internal/oauth`): client credentials and cache, against a fake token endpoint; no user-visible change (done, §4.5) | — | — | US-6.1 |
| 4a | Graph driver package (`internal/driver/graph`), app-only, messages up to 4 MB, recipients from the envelope; not registered yet (done) | 2, 3 | — | US-6.1 stage 1 |
| 4b | `spec.microsoftGraph` (tenant, client ID, credentials), resolver, driver registration, webhook accepts `microsoftGraph` and requires `allowedSenders`; audit reason `recipient_not_allowed` for the envelope rule; recipe (done) | 4a | Microsoft 365 work accounts | US-6.1 stage 1 |
| 5a | Credential Secret guard admits OAuth token Secrets (label, owner, keys, release namespace) (done) | — | — | US-6.3, §4.10 |
| 5b | Refresh-token source, token Secret and broker in the controller, `sigillum_backend_authorized`; no provider yet (done) | 3, 5a | — | US-6.3 |
| 6 | `authType: XOAUTH2` on the SMTP driver with device code sign-in (`smtp-mail.outlook.com`); recipe `outlook-com.yaml` | 2, 5 | **Outlook.com** | US-6.1 stage 2, US-6.3 |
| 7 | `XOAUTH2` app-only for Microsoft 365 (`SMTP.SendAsApp`) | 3, 6 | Microsoft 365 over SMTP without a password | US-6.1 stage 2 |
| 8 | `sigillum oauth login` (authorization code, PKCE, loopback) | 5 | — | US-6.3 |
| 9a | Envelope rule moved from the Graph driver to `driver.BindToEnvelope`, shared with the Gmail driver; no behaviour change (done) | — | — | US-6.1, US-6.2 |
| 9b | Gmail API driver with a service account (`internal/driver/gmail`, JWT assertion in `internal/oauth`); not registered yet (done) | 2, 3, 9a | — | US-6.2 stage 1 |
| 9c | `spec.gmail`, resolver, registration, webhook accepts `gmail` and requires `allowedSenders`; recipe (done) | 9b | Google Workspace | US-6.2 stage 1 |
| 10 | Gmail delegated; recipe `gmail-oauth.yaml` | 8, 9 | **Personal Gmail** without app password | US-6.2, US-6.3 |
| 11 | `XOAUTH2` Google token sources | 7, 9 | Gmail over SMTP with OAuth | US-6.2 stage 2 |
| 12 | Graph messages above 4 MB via draft and upload sessions (opt-in) | 4 | Large Graph messages | US-6.1 stage 1 |
| 13 | Release: real-account checks (`docs/RELEASE-CHECKS.md`), version bump | all | v0.4.0 | §8.0 |

A backend type, `authType` or field is accepted by the webhook only from the pull request that makes it work, so `main` stays releasable after every merge. If the deadline gets tight, 11 and 12 move to v0.4.1 or v0.5.0; 1 to 6 are the minimum for Microsoft 365 and Outlook.com, and 7 for work accounts that must stay on SMTP. Rows 4 and 6 do not depend on each other and can be reviewed in parallel. Rows 4 and 5 turned out too large for one pull request each: 4 is split into the driver (4a) and its activation (4b), 5 into the guard extension (5a) and the broker (5b), 9 into the shared envelope rule (9a), the driver (9b) and its activation (9c); "4", "5" and "9" in the dependency column mean all parts.

### 8.4 v0.5.0 — Easy to run, easy to debug

Goal: one-command install on a small cluster, and developers can answer "why was my mail rejected?" themselves. Planned as v0.4.0 until the Microsoft 365 deadline moved hosted mailboxes ahead of it.

| Item | Type | Ref |
|---|---|---|
| Webhook certificates without cert-manager | Feature | US-5.6 |
| Preflight endpoint and `kubectl sigillum` plugin (`send`, `whoami`, `explain`, `credential create` / `rotate`) | Feature | US-7.2, §4.4.2 |
| SMTPS (implicit TLS, port 465) on the proxy | Feature | US-1.5 |
| OpenAPI 3.1 description | Feature | US-7.3 |
| Grafana dashboard and `PrometheusRule` alerts | Feature | US-4.6 |
| Runbooks: upstream outage, Redis outage, CRD upgrade | Docs | §5.7 |

### 8.5 v0.6.0 — API stabilization

Goal: freeze the resource shapes so early adopters can rely on them.

| Item | Type | Ref |
|---|---|---|
| Idempotency keys for `POST /v1/messages` | Feature | US-1.6 |
| Decide and implement or remove `matchedSubjects` | Gap fix | G-4, Q-9 |
| Decide subject-type precedence and SMTP rate-limit reply code | Decision | Q-6, Q-7 |
| CRDs to `v1beta1` with a conversion webhook; remove ignored fields (`serviceAccount.namespace`) | API | §5.8 |

### 8.6 v0.7.0 – v0.9.x — Driven by feedback

No fixed scope. Candidates from the backlog (§8.8) move in when users ask for them. The later 0.x releases also carry the 1.0 hardening work: failure-injection tests (relay outage, Redis outage, controller restart), upgrade tests across the last two minor versions, and complete documentation.

### 8.7 v1.0.0 — exit criteria

1.0 is a statement about maturity, not about features. It ships when:

- Sigillum has run in production at **at least three independent organizations for at least three months**, and their feedback has been addressed or explicitly deferred.
- The CRDs have had **no breaking change for two consecutive minor releases**; they are then promoted from `v1beta1` to `v1`.
- There is **no open security gap** in §9.3.
- **Upgrades are tested** from the previous two minor versions, including CRD upgrades.
- Documentation covers installation, every feature, the recipes and the runbooks.

### 8.8 Feature decisions

Every candidate that has been discussed, with its decision and the reason.

| Feature | Decision | Reason |
|---|---|---|
| Sigillum-issued SMTP credentials | Done (v0.3.0) | Most off-the-shelf apps only do `PLAIN` / `LOGIN`; the only alternative is pod-IP trust. No workaround outside Sigillum. Generated by default in all non-excluded namespaces, so small teams have nothing to maintain per namespace. |
| Restarting apps after rotation | Recipe, Done (v0.3.0) | Stakater Reloader already does it. |
| Egress enforcement (block direct access to relays) | Recipe, Done (v0.3.0) | NetworkPolicy / CiliumNetworkPolicy do it; essential, but not Sigillum code. |
| Policy guardrails (sender domains per team, allowed namespaces per `ClusterMailBackend`, no pod-IP in production) | Recipe, Done (v0.3.0) | Kyverno / `ValidatingAdmissionPolicy` do it (§4.9). Resolves Q-8. |
| Per-address recipient allowlist | Done (v0.3.0) | Common staging need ("only the QA inbox"); no workaround with domain lists. |
| Cluster name in telemetry | Done (v0.3.0) | Tiny; staging and production usually share one log backend. |
| Gap fixes G-1, G-3, G-5 | Done (v0.3.0) | Small; G-5 is security-relevant. |
| Local development | Recipe, Done (v0.3.0) | Mailpit as a `MailBackend` works today. A built-in capture driver is not planned. |
| Provider support via SMTP (SES, Mailgun, Postmark, Brevo, Google Workspace relay) | Recipe, Done (v0.3.0) | All providers offer SMTP; the existing driver covers them. |
| Microsoft Graph driver | v0.4.0 | Microsoft 365 is common among small and medium organizations, and password-based SMTP AUTH, app passwords included, is disabled by default from the end of December 2026. Graph needs no SMTP AUTH at all. Workarounds until then: relay connector (static egress IP), Azure Communication Services, High Volume Email (internal only). |
| XOAUTH2 for the SMTP driver | v0.4.0 | Shares the token code with the Graph and Gmail drivers; for setups that must stay on SMTP. |
| Gmail API driver | v0.4.0 | App passwords still work with 2-Step Verification, but they grant full mailbox access, are revoked with a password change and can be disabled by the admin. A service account (Workspace) or a delegated sign-in (personal accounts) needs only `gmail.send`. |
| Personal Outlook.com and Gmail accounts (delegated sign-in) | v0.4.0 | Individuals are likely among the first users. Outlook.com has no password login left at all. |
| Sender allowlist on the backend | v0.4.0 | API backends can send as many mailboxes; the backend must bound them, a company relay may stay open (Q-12). |
| Daily limit per policy | v0.4.0 | Protects the provider's daily quota of a shared sending account. |
| Graph messages above 4 MB | v0.4.0, opt-in | Reports and invoices with attachments exceed 4 MB quickly. Opt-in because drafts need `Mail.ReadWrite`. |
| Webhook certificates without cert-manager | v0.5.0 | Workaround exists (cert-manager or own secret), but it is the biggest install hurdle on small clusters. |
| Preflight and kubectl plugin | v0.5.0 | Main debugging aid for developers and policy authors. |
| SMTPS on port 465 | v0.5.0 | Small; some apps offer nothing else. |
| OpenAPI description | v0.5.0 | Small; enables generated clients. |
| Dashboard and alert rules | v0.5.0 | Small teams rarely write their own. |
| SBOM, signing, dependency scanning | Done (main, first release after v0.2.1) | Cheap in CI; lets security-minded users verify releases. |
| Idempotency keys | v0.6.0 | Duplicate mail on retries is real, but rare enough to follow the basics. |
| `v1beta1` CRDs | v0.6.0 | After the credential and limit fields have settled. |
| API drivers (SES, SendGrid, Mailgun) | Backlog | SMTP endpoints already work; worthwhile mainly with cloud workload identity. |
| Delegated Graph sign-in (`/me/sendMail`) | Backlog | Personal accounts use `XOAUTH2` over SMTP, which keeps the envelope and needs much less code; only needed if Microsoft retires SMTP for Outlook.com. |
| Sigillum-owned public app registration for personal Microsoft accounts | Backlog | Saves Outlook.com users the Entra tenant and app registration; the project would own the registration and its consent screen (Q-13). |
| Cloud workload identity for upstream auth | Backlog | Larger-organization need; External Secrets plus rotation covers small setups. |
| Istio mTLS auth | Backlog | Tokens already work inside meshes. |
| `MailQuota` (namespace-wide) | Backlog | Per-policy daily limit covers most cases. |
| Attachment-type rules in `MailPolicy` | Backlog | Hosted mailboxes already filter; only relevant for plain relays. |
| Opt-in traceability headers (`X-Sigillum-Workload`) | Backlog | Audit log and `Received` header already correlate; headers would expose namespace names to recipients. |
| `GET /v1/capabilities` | Backlog | Only meaningful once a backend offers more than `send`. |
| Central gateway for many clusters (token validation via OIDC / JWKS, issuer → cluster mapping) | Backlog | Large fleets. One install per cluster via GitOps (for example Argo CD ApplicationSets) works today. |
| Fleet-wide quotas, SPIFFE federation | Backlog | Large fleets. |
| Official client SDKs | Not planned | One REST call; clients can be generated from OpenAPI. |
| Native namespace restriction on `ClusterMailBackend` | Not planned | Admission policy recipe (US-5.7). May be revisited if the recipe proves too hard (Q-8). |
| Delivery status, bounces, suppression lists | Not planned | Upstream provider (§7). |
| Mail journaling / archiving | Not planned | Upstream provider (§7). |
| Built-in capture driver | Not planned | Mailpit (US-7.1). |
| Read path, IMAP proxy, webhook receiver | After 1.0 | Unchanged architectural vision (§1.5, Epic 6). |

---

## 9. Risks, open questions, known gaps

### 9.1 Risks

| Risk | Mitigation |
|---|---|
| Workloads bypass Sigillum and talk to the relay directly | Egress recipe (US-5.7); relay credentials exist only in the Sigillum namespace |
| TokenReview load on kube-apiserver | LRU cache with TTL; projected tokens with audience binding |
| Static SMTP credentials (US-3.7) leak | Scoped to one ServiceAccount and its policies; 256-bit random; TLS required; hash only in Sigillum; audited; rotation with grace period; instant revocation by deleting the `MailCredential` |
| Controller write access to Secrets in all namespaces (generated credentials) | No read verbs; mandatory `ValidatingAdmissionPolicy` guard limits writes to labelled Secrets owned by a `MailCredential`; excluded namespaces (default `kube-*` and always the release namespace); controller refuses to write when the guard is missing; bring-your-own-hash mode for teams that want no Secret writes (§4.10) |
| Redis as single point of failure | Sentinel / Cluster; fail closed (`503`) by default, `failOpen` as explicit opt-in |
| Rate limits multiplied by replica count | Documented (§4.7, US-5.2); Redis for multi-replica installs |
| Pod-IP ambiguity for SMTP legacy auth | OAUTHBEARER default, credentials from v0.3.0; pod-IP is a double opt-in; ambiguous IPs rejected; `UsingLegacyAuth` condition |
| Upstream provider disables password SMTP login or app passwords | Graph and Gmail API drivers and XOAUTH2 in v0.4.0, targeted before the Microsoft 365 cut-off at the end of December 2026; relay connector, Azure Communication Services and HVE recipes (`examples/providers/`) until then |
| Refresh token of a delegated backend revoked or expired (password change, revoked consent, Google OAuth client left in testing) | Health check keeps tokens in use; `Ready=False` with `AuthorizationRequired` and `sigillum_backend_authorized` for alerting; Microsoft backends start a new device code automatically (US-6.3) |
| Controller outage stops access token refresh for delegated backends | Tokens are refreshed at half their lifetime, so sending continues for about 30 minutes; the controller is a restarted Deployment with leader election |
| Dependence on upstream availability | Endpoint failover, health checks, clear error semantics (`502` / `451`, rate-limit refund) |
| Overly permissive policies | Governance via RBAC and admission recipes (§4.9, US-5.7); preflight and `explain` (v0.5.0) |
| Unclear precedence between overlapping policies | Explicit `priority`, deterministic name tie-break (US-2.6) |
| No mail queue → loss risk during upstream outage | Caller responsibility; idempotency keys (v0.6.0) make retries safe |
| CRDs not upgraded by Helm | Documented upgrade procedure (US-5.1); components refuse to start on outdated CRDs (v0.3.0); runbook in v0.5.0 |
| Too few users to validate the design | Stay below 1.0 until the exit criteria (§8.7) are met |

### 9.2 Open questions

| # | Question | Notes |
|---|---|---|
| Q-1 | Is "Sigillum" the final name, or is an internal name wanted? | |
| Q-2 | API group `sigillum.dev` or an internal company suffix? | Must be settled before `v1beta1` (v0.6.0). |
| Q-3 | Is a persistent retry queue ever needed? | Today the caller retries (§4.7); idempotency keys (US-1.6) reduce the need. |
| Q-4 | Are backend events (bounces, delivery status) needed inside the cluster? | Default answer: no, the provider handles them (§7). |
| Q-5 | Is multi-cluster federation a goal? | Backlog; decided by demand (§8.8). |
| Q-6 | Should subject type (explicit SA > SA selector > pod selector) become a secondary precedence key after `priority`? | Decide by v0.6.0. |
| Q-7 | Keep `421` for SMTP rate limiting? | `421` conventionally means the server is closing the connection; `451 4.7.x` is the common per-message temporary failure. Decide by v0.6.0. |
| Q-8 | Should `ClusterMailBackend` restrict which namespaces may reference it natively? | Decided for now: no, use the admission recipe (US-5.7). Revisit if users find the recipe too hard. |
| Q-9 | What should `MailPolicy.status.matchedSubjects` count, or should it be removed? | See G-4; decide by v0.6.0. |
| Q-10 | Should the webhook warn when `senderRestrictions` is present with an empty `allowedSenders` list? | That configuration denies every sender and is almost always a mistake (US-2.3). A warning does not change behavior. |
| Q-11 | `MailCredential` design | **Decided:** controller-generated Secrets by default in all namespaces except `credentials.excludeNamespaces` (default `kube-*`, release namespace always), guarded as in §4.10; bring-your-own argon2id hash as alternative; SHA-256 for generated passwords; no per-policy opt-in; TLS required by default (US-3.7, §4.3.4). |
| Q-12 | Should a Graph or Gmail backend send as whichever mailbox `From` names, or be pinned to one mailbox in its spec? | **Decided:** it depends on the upstream, so the backend states it. API backends send as `From`, bounded by the backend's own `allowedSenders` globs (US-2.8): a company relay can forward any address of its domains, a personal account only its own. |
| Q-13 | Should Sigillum ship a shared OAuth client ID for personal accounts, so users need no app registration of their own? | **Decided for v0.4.0:** every user brings their own client (US-6.3). A Sigillum-owned public registration for personal Microsoft accounts (device code, no secret) may follow later (§8.8); it would remove the Entra tenant an Outlook.com user must otherwise get through an Azure sign-up, but the project would own the registration and the consent screen users see. Google is less affected: any Google account can create the project and client for free. The client ID stays a spec field, so a later default does not change existing backends. |

Settled: a backend can define several endpoints as a failover group (`spec.smtp.endpoints`).

### 9.3 Known gaps

Specified behavior the current release (v0.3.0) does not meet yet:

| ID | Gap | Where specified | Planned |
|---|---|---|---|
| G-2 | The gateway checks backend `Ready` but not `status.capabilities`. | US-2.5, §4.5 | With the first non-SMTP driver |
| G-4 | `MailPolicy.status.matchedSubjects` is never populated. | §4.3.2 | v0.6.0 |

Closed in v0.3.0:

| ID | Gap | Resolution |
|---|---|---|
| G-1 | REST returned `502` for both transient and permanent upstream failures. | Permanent rejections answer `422 upstream-rejected` (audit / metric `upstream_rejected`); `502 upstream-error` is transient only (§4.4.3). |
| G-3 | No `preStop` delay: late clients could hit a closed listener. | `--shutdown-delay` (default 5 s) fails readiness while still serving, before draining (US-5.3). |
| G-5 | TokenReview cache entries were not bounded by the token's `exp` (security). | Positive cache entries expire at the token's `exp` at the latest (§5.3). |

---

## 10. Glossary

| Term | Meaning |
|---|---|
| **CRD** | Custom Resource Definition, the Kubernetes API extension mechanism |
| **TokenReview** | Kubernetes API that validates bearer tokens |
| **Projected ServiceAccount token** | Short-lived, audience-bound token mounted into a pod |
| **SPIFFE** | Secure Production Identity Framework for Everyone, a standard for workload identity |
| **XFCC** | `X-Forwarded-Client-Cert`, the header Envoy / Istio use to pass the client certificate identity |
| **Backend** | Mail system behind Sigillum that messages are forwarded to (and, in future, read from): SMTP, Graph, Gmail or SendGrid |
| **Driver** | Internal Go implementation that encapsulates one backend protocol and implements the `Driver` interface |
| **Capability** | Declared feature of a backend / driver (`send`, `read`, `subscribeEvents`, `folders`) |
| **Gateway pipeline** | Transport-agnostic send path shared by REST and SMTP: policy, backend, rate limit, send, audit |
| **Policy subject** | Caller identity (ServiceAccount, pod) a policy matches |
| **Preflight** | Dry-run validation of a message without delivery |
| **MailCredential** | Sigillum-issued username / password bound to one ServiceAccount, for SMTP clients without token support; generated into a Secret by the controller or backed by a user-supplied hash (US-3.7) |
| **Recipe** | Tested configuration of a standard tool (NetworkPolicy, Kyverno, Mailpit, …) shipped instead of a Sigillum feature (§8.0) |

---

## 11. References

- [kube-mail (reference project, abandoned)](https://github.com/martin-helmich/kube-mail)
- [Kubernetes bound ServiceAccount tokens](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens)
- [Kubernetes TokenReview API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)
- [RFC 5322 — Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322)
- [RFC 6409 — Message Submission for Mail](https://datatracker.ietf.org/doc/html/rfc6409)
- [RFC 7628 — SASL Mechanisms for OAuth (OAUTHBEARER)](https://datatracker.ietf.org/doc/html/rfc7628)
- [RFC 7807 — Problem Details for HTTP APIs](https://datatracker.ietf.org/doc/html/rfc7807)
- [SPIFFE specification](https://github.com/spiffe/spiffe)
- [Istio: forwardClientCertDetails](https://istio.io/latest/docs/reference/config/istio.mesh.v1alpha1/)
- [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/)

# Field trial on a local kind cluster: feedback and bugs

**Date:** 2026-10-05 · **Commit under test:** `0d34ede` (`main`, CHANGELOG at
`0.4.0 - unreleased`, chart `0.3.0`) · **Cluster:** kind v0.33.0,
Kubernetes v1.36.4 (the node image CI pins), single node · **Extras:**
cert-manager v1.15.1 (as in the README), Mailpit v1.31.2

I installed Sigillum the way a new user would: first the README's *Install*
section verbatim, then the `examples/local-dev` profile. After that I tried
the README *Quickstart* manifests, the REST API, the SMTP proxy,
MailCredentials, admission validation, upgrade and uninstall. Every finding
below was reproduced on the running cluster; the commands are inline.

Severity: **High** means a user ends up with a broken or less secure setup
without noticing. **Medium** means wrong behaviour or a misleading doc that
costs debugging time. **Low** covers polish.

## Summary

| # | Severity | Area | Finding |
|---|---|---|---|
| 1 | High | Chart | `helm install` with default values leaves the controller in CrashLoopBackOff, and its `failurePolicy: Fail` webhook then blocks every Sigillum resource in the cluster |
| 2 | High | Validation | All semantic validation lives only in the webhook. Without it (the local-dev profile) `allowedRecipients: ["*"]` is admitted, reported `Ready=True` and lets the workload mail anyone |
| 3 | High | REST API | Unknown JSON fields are silently ignored and an empty body is accepted, so `{"text": "..."}` at the top level delivers an **empty** mail with `202` |
| 4 | Medium | Backend / security | Upstream `authType: LOGIN` with `tls: none` sends the relay password in cleartext. `PLAIN` with `tls: none` shows the backend Ready but fails every send with a "transient" 502. Admission accepts both without a warning |
| 5 | Medium | Validation | Policy `senderRestrictions.allowedSenders` accepts `"*"` and unanchored `*example.com` (which matches `x@evilexample.com`), although the same patterns are rejected for backend `allowedSenders` and `allowedRecipients` |
| 6 | Medium | Docs | The README Quickstart uses unreleased 0.4.0 fields, while "Not yet implemented" lists them as upcoming. The local-dev recipe installs the published OCI chart (0.3.0), which drops those fields |
| 7 | Medium | Docs | Nothing shows how to mount the projected token `/var/run/secrets/tokens/sigillum` that the README and NOTES rely on |
| 8 | Medium | SMTP proxy | Messages without `Date:` / `Message-ID:` are relayed without them (an MSA should add both, RFC 6409 §8) |
| 9 | Low | Controller | The leader lease is not released on shutdown, so every rollout has a ~30 s window with no reconciliation |
| 10 | Low | Status | A policy whose `allowedSenders` exceed the backend's `allowedSenders` is `Ready=True` with no hint |
| 11 | Low | REST API | Not all errors are RFC 7807, some `detail` texts expose Go internals, and `Content-Type` is not checked |
| 12 | Low | Observability | Two log schemas (controller: zap `ts`/`level:"info"`; api/smtp: slog `time`/`level:"INFO"`) and mixed key casing (`authMethod` next to `service_account`) |
| 13 | Low | Chart | cert-manager warns "Certificate will be issued with an empty Issuer DN" for the webhook certificate |
| 14 | Low | CLI | `sigillum --help` prints only `must pass --mode=…` and exits 2 |
| 15 | Low | Chart | NOTES Quickstart step 1 references `corporate-smtp-credentials` without saying to create it |

## What worked well

- The README install (cert-manager plus `helm install`) came up healthy on
  the first try. Pods run non-root with a read-only root filesystem, and
  the NOTES warn clearly about plaintext HTTP and in-memory rate limits.
- The REST happy path works end to end: `202` with `messageId` and
  `policyMatched`, delivered to Mailpit with a correct MIME structure. UTF-8
  subjects and filenames are encoded, and text+HTML+attachment produce a
  proper `multipart/mixed`.
- Policy enforcement was correct in every case I tried: sender globs, case
  folding, recipient domains (no implicit subdomains), `allowedRecipients`
  exact and glob, a mixed allowed/denied recipient list (denied as a
  whole), `Reply-To` and `Sender` checks, `@` in display names, `%`
  routing in local parts, `maxRecipients`, and the backend `allowedSenders`
  intersection.
- Header injection is handled: CRLF in the subject is Q-encoded, CRLF in a
  custom header value gives `400`, and a managed header such as `From` in
  `headers` is dropped.
- Rate limiting is exact: 60/min admitted exactly 60 (denied requests do
  not count), then `429` with a sensible `Retry-After`.
- The SMTP proxy handles OAUTHBEARER and MailCredential PLAIN/LOGIN logins,
  refuses `<>`, refuses duplicate `From`, strips `Bcc:`, and requires
  AUTH. Its replies use proper enhanced status codes.
- MailCredential works well: the generated Secret carries
  host/port/username/password, rotation via annotation keeps the old
  password valid through the grace period, deleting the credential revokes
  it immediately and removes the Secret, a pre-existing foreign Secret is
  never overwritten (`SecretConflict`), and `kube-*` is refused at
  admission.
- Admission messages are precise, and the warning on an empty
  `allowedSenders` is a nice touch.
- The audit stream has one record per request, accepted or rejected, with
  a reason.

---

## Findings in detail

### 1. Default `helm install` breaks Sigillum resource admission cluster-wide (High)

`webhook.enabled` defaults to `true` and `webhook.certificate.useCertManager`
defaults to `false`. Without the `--set` flag from the README, nothing
creates `sigillum-webhook-tls`. The volume is `optional: true`, so the pod
starts, then exits:

```text
$ helm install sigillum ./charts/sigillum -n sigillum-system      # "STATUS: deployed"
$ kubectl -n sigillum-system get pods
sigillum-controller-…   0/1   CrashLoopBackOff   3
$ kubectl -n sigillum-system logs deploy/sigillum-controller --previous | tail -1
{"level":"ERROR","msg":"controller exited with error","err":"open /etc/sigillum/webhook-tls/tls.crt: no such file or directory"}
$ kubectl apply -f clustermailbackend.yaml
Error from server (InternalError): … failed calling webhook "vclustermailbackend.sigillum.dev": … connect: connection refused
```

Because of `failurePolicy: Fail`, every create or update of any Sigillum
resource fails until the release is fixed. The NOTES do not mention it,
and Helm reports success.

**Suggestions**, any one of these would help:

- In the chart, `fail` at render time when `webhook.enabled` is set,
  `useCertManager` is false, and `lookup` finds no Secret named
  `webhook.certificate.secretName`. The message should name both ways out:
  `--set webhook.certificate.useCertManager=true` or
  `--set webhook.enabled=false`.
- Or default `useCertManager` to `true` and fail at render time when the
  `cert-manager.io/v1` API is missing (`.Capabilities.APIVersions.Has`).
- Drop `optional: true` from the volume, so the pod stays
  `ContainerCreating` with a clear `FailedMount` event instead of
  crash-looping.

### 2. Validation exists only in the webhook (High)

The local-dev profile runs with `webhook.enabled: false`. Its comment says
"the controller still reports invalid resources in status", but the
controller only checks references (`mailpolicy_controller.go:19`), and the
CRDs have no `x-kubernetes-validations`. A policy that the webhook
rejects (verified with the webhook on) is admitted, goes Ready, and is
enforced with the permissive meaning:

```yaml
recipientRestrictions:
  allowedDomains: ["*.example.com"]   # webhook: "must be a bare domain"
  allowedRecipients: ["*"]            # webhook: wildcard rejected
```

```text
$ kubectl -n nowebhook get mailpolicy invalid-but-admitted -o jsonpath='{.status.conditions[0]}'
Ready=True Ready: policy is ready and backend is reachable
$ curl … -d '{"from":"app@example.com","to":["anyone@evil.test"],…}'
{"messageId":"584c9f65-…","policyMatched":"invalid-but-admitted",…}   # 202
```

Running without the webhook is also what users will do to avoid
cert-manager (see #1, and the roadmap item "install without
cert-manager"). The policy then silently loses its recipient restriction.

**Suggestions:** run the webhook's `Validate*` functions in the controller
as well, and set `Ready=False, reason InvalidConfiguration` on failure.
Then have the gateway skip, or deny on, policies that are not Ready, which
it already does for backends. Where the rules fit, also express them as
CEL rules in the CRDs so the API server enforces them without a webhook.
Until then, correct the comment in `values-local.yaml`.

### 3. REST: silently ignored fields and empty bodies (High)

`requestBody` has an `Extra map[string]interface{} json:"-"` field that is
never filled, and `json.Unmarshal` ignores unknown keys. Combined with an
empty body being valid, a typo delivers an empty mail and reports success:

```text
$ curl … -d '{"from":"dev@example.com","to":["a@example.com"],"subject":"typo top-level text","text":"Your password reset link: …"}'
{"messageId":"48838edd-…","policyMatched":"dev-permissive",…}    # 202, body delivered empty
$ curl … -d '{…,"replyTo":"r@example.com"}'                       # 202, no Reply-To header
```

**Suggestions:** use `json.Decoder.DisallowUnknownFields()` and return a
`400` that names the field (for example "unknown field \"text\"; did you
mean body.text?"). Reject a message with no `body.text`, no `body.html`
and no attachment, or at least document that it is allowed. Remove the
unused `Extra` field.

### 4. Upstream credentials over `tls: none` (Medium)

Both cases were reproduced against Mailpit started with
`--smtp-auth-accept-any --smtp-auth-allow-insecure`:

| Backend | Status | Send result |
|---|---|---|
| `authType: PLAIN`, `tls: none` | `Ready=True` | `502 upstream-error: upstream transient error: unencrypted connection`, on every message, and classified transient so clients retry forever |
| `authType: LOGIN`, `tls: none` | `Ready=True` | `202`; the relay password went over the wire base64-encoded, i.e. in cleartext |

The cause is that `PLAIN` uses `net/smtp.PlainAuth`, which refuses
unencrypted non-localhost connections, while the custom `loginAuth`
(`internal/driver/smtp/smtp.go`) has no such check. The webhook accepted
both backends without a warning.

**Suggestions:** reject `authType != NONE` with `tls: none` at admission
(or require an explicit opt-in such as `allowPlaintextAuth: true` for mesh
setups). Give `loginAuth.Start` the same TLS check as `PlainAuth`. Have
the health probe authenticate, so a backend that cannot log in is not
`Ready`. Classify "unencrypted connection" as a configuration error, not a
transient one.

### 5. Policy `allowedSenders` patterns are not validated (Medium)

`addressEntryError` already guards backend `allowedSenders` and
`allowedRecipients`, but policy `senderRestrictions.allowedSenders` does
not use it:

```text
policy  allowedSenders: ["*"]            -> created
policy  allowedSenders: ["*example.com"] -> created          (matches x@evilexample.com, per SPEC US-2.3)
backend allowedSenders: ["*example.com"] -> "a pattern must have the form <local-part pattern>@<domain>"
```

SPEC US-2.3 documents the `*example.com` pitfall instead of preventing it.
**Suggestion:** validate policy senders with `addressEntryError`. To stay
compatible in the 0.x series, start with an admission warning and turn it
into an error one minor release later.

### 6. README documents unreleased features (Medium)

- The README Quickstart uses `ClusterMailBackend.spec.allowedSenders` and
  `rateLimits.messagesPerDay`. Both are in CHANGELOG `0.4.0 - unreleased`,
  while the README's "Not yet implemented" still lists "a sender allowlist
  per backend and a daily limit" as next up. Chart and Makefile still say
  `0.3.0`.
- `examples/local-dev/README.md` installs
  `oci://ghcr.io/se-wo/charts/sigillum`, the latest published chart
  (0.3.0). If someone pairs it with the README Quickstart, the 0.3 CRDs
  prune both fields: client-side `kubectl apply` gives no warning, and the
  backend ends up with no sender bound.

**Suggestions:** mark unreleased fields in the README (as SPEC does with
**[v0.4.0]**), or keep the README of `main` at the released state. Update
"Not yet implemented". Have the local-dev recipe say which chart version
matches the examples, or install from `./charts/sigillum`.

### 7. No example for the projected ServiceAccount token (Medium)

The README says "Mount a projected token with audience `sigillum`", and
the NOTES use `$(cat /var/run/secrets/tokens/sigillum)`, but no file in
the repo contains a `serviceAccountToken` projected volume. That snippet
is the first thing a user needs:

```yaml
volumes:
  - name: sigillum-token
    projected:
      sources:
        - serviceAccountToken: { audience: sigillum, expirationSeconds: 3600, path: sigillum }
containers:
  - volumeMounts: [{ name: sigillum-token, mountPath: /var/run/secrets/tokens, readOnly: true }]
```

Also worth one sentence: the token is rotated, so read the file on every
request and do not cache it at startup.

### 8. SMTP proxy relays messages without `Date` / `Message-ID` (Medium)

A minimal DATA (`From`, `To`, `Subject` only) was relayed byte for byte
with neither `Date:` nor `Message-ID:`. Mailpit filled in a
`Message-ID`; a real relay may not, and a missing `Date` violates RFC 5322
§3.6. Several large receivers score such mail as spam. The REST path sets
both. **Suggestion:** as a submission agent (RFC 6409 §8.2/§8.3), add
`Date` and `Message-ID` when they are absent. This keeps the "byte for
byte" promise for everything the client sent.

### 9. Leader lease is held until expiry on rollout (Low)

After `helm upgrade`, the new controller logged
`Attempting to acquire leader lease` at 05:43:34 and acquired it at
05:44:03. For those ~30 s, resources created during the rollout showed an
empty `READY`. `ctrl.Options` in `internal/controller/controller.go`
does not set `LeaderElectionReleaseOnCancel: true`. That is safe here,
because the manager exits right after it stops, and it removes the gap.

### 10. A policy that the backend narrows still shows Ready (Low)

A policy with `allowedSenders: ["app@other.test", "app@example.com"]` on a
backend limited to `*@example.com` is `Ready=True`, and only sends fail
(`403 sender-not-allowed`, "not allowed by backend"). An admission
warning, or a condition such as `SendersNarrowedByBackend`, naming the
entries the backend will never allow would save a debugging round.

### 11. REST error-response polish (Low)

- The README says "All errors use RFC 7807", but an unknown path returns
  `404 page not found` (text/plain) and `GET /v1/messages` returns an
  empty `405`.
- Some `detail` texts expose Go internals, for example
  `json: cannot unmarshal string into Go struct field requestBody.to of type []string`
  (better: "`to` must be an array of addresses"), or
  `[invalid bearer token, token audiences ["https://kubernetes.default.svc.cluster.local"] is invalid for the target audiences ["sigillum"]]`
  (useful content, but the raw slice formatting could become
  "token audience is … , expected sigillum (create the token with --audience sigillum)").
- A request with `Content-Type: text/plain` and a JSON body is accepted.
  Answering `415` for anything other than `application/json` or
  `multipart/form-data` would catch broken clients early.
- The `SecretConflict` condition message ends with the guard's generic
  "the server rejected our request due to an error in our request".

### 12. Two log schemas (Low)

The README promises "structured slog (JSON)". The api-server and SMTP
proxy emit `{"time":…,"level":"INFO","msg":…}`, while the controller
emits zap's `{"level":"info","ts":…,"msg":…}`. Keys also mix camelCase
and snake_case in one line (`"authMethod"` next to `"service_account"`
and `"message_id"`). Routing controller-runtime through a `logr` → `slog`
bridge (`logr.FromSlogHandler`) would give one schema.

### 13. Webhook certificate without a subject (Low)

cert-manager emits `Warning BadConfig: Certificate will be issued with an
empty Issuer DN, which contravenes RFC 5280` for `sigillum-webhook-1`.
Adding `commonName` (or `subject.organizations: [sigillum]`) to the
self-signed `Certificate` in `cert-manager.yaml` silences it.

### 14. `sigillum --help` (Low)

It prints `must pass --mode=api, --mode=controller or --mode=smtp` and
exits 2. Printing the usage and flags of each mode, with exit 0 for
`--help`, would help anyone who runs the image directly.

### 15. NOTES Quickstart step 1 needs a Secret it never mentions (Low)

The `ClusterMailBackend` in the NOTES references
`credentialsRef: corporate-smtp-credentials`, but unlike the README, the
NOTES never create that Secret. Copied as is, the backend stays
`Ready=False` with "credentials secret … not found". Either add the
`kubectl create secret generic …` line or use `authType: NONE` in the
NOTES example.

Minor observation: `helm uninstall` leaves `sigillum-webhook-tls` behind.
That is cert-manager's default (`--enable-certificate-owner-ref` is off).
A note in the uninstall docs would do.

---

## Reproducing the cluster

The sandbox host for this trial was unusual (cgroup v1, `oom_score_adj`
not lowerable, no egress to quay.io, ghcr.io blobs or get.helm.sh). None
of that affects the findings, but it needed these workarounds:

```yaml
# kind.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri"]
    restrict_oom_score_adj = true
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: KubeletConfiguration
    failCgroupV1: false
```

```sh
kind create cluster --name sigillum --config kind.yaml \
  --image kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed
# Images that could not be pulled were built locally and loaded with
# `kind load docker-image`: Sigillum from this commit (host `go build` +
# distroless/static:nonroot) and cert-manager v1.15.1 from source.
```

On a normal workstation, `kind create cluster` followed by the README
steps is enough.

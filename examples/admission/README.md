# Admission guardrails for policy authors (US-5.7, SPEC §4.9)

Sigillum enforces `MailPolicy` objects; it does not judge them. Whoever may
write a `MailPolicy` in a namespace decides what that namespace may send.
These policies let the platform team put limits on that, with the admission
tools you already run. Each guardrail comes as a Kubernetes
`ValidatingAdmissionPolicy` (built in since 1.30, no extra software) and,
where Kyverno is used, as a Kyverno `ClusterPolicy`.

| Guardrail | ValidatingAdmissionPolicy | Kyverno |
|---|---|---|
| `senderRestrictions` is required | [`vap-require-sender-restrictions.yaml`](vap-require-sender-restrictions.yaml) | [`kyverno-mailpolicy-guardrails.yaml`](kyverno-mailpolicy-guardrails.yaml) |
| Senders stay within the namespace's domain (label `sigillum.dev/sender-domain`) | [`vap-sender-domain.yaml`](vap-sender-domain.yaml) | ″ |
| A `ClusterMailBackend` may only be used by namespaces labelled `backends.sigillum.dev/<name>: "true"` | [`vap-restrict-cluster-backends.yaml`](vap-restrict-cluster-backends.yaml) | ″ |
| No `legacyAuth.podIPFallback` in namespaces labelled `environment: production` | [`vap-forbid-podip-fallback.yaml`](vap-forbid-podip-fallback.yaml) | ″ |
| No workload Secrets that look like SMTP credentials | — | [`kyverno-no-smtp-secrets.yaml`](kyverno-no-smtp-secrets.yaml) |

Namespace labels are the policy's input, so only the platform team may set
them: restrict `namespaces` `patch`/`update` to cluster admins (the default
`admin` and `edit` roles cannot change namespaces).

Example namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: billing
  labels:
    environment: production
    sigillum.dev/sender-domain: billing.example.com
    backends.sigillum.dev/corporate-smtp: "true"
```

Check a policy without applying it: `kubectl apply --dry-run=server -f
my-mailpolicy.yaml` runs admission and reports denials.

Sigillum itself also validates every `MailPolicy` (structure, selectors,
domains) with its own webhook; these recipes add organisation-specific rules
on top.

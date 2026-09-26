# Egress enforcement: Sigillum as the only way out (US-5.7)

Sigillum enforces nothing if a workload can talk to the relay directly.
Block outbound SMTP (TCP 25, 465, 587) for every pod except Sigillum's.
Also keep the relay credentials in the Sigillum namespace only, so a
workload has nothing to log in with.

Pick one:

| File | CNI | Scope |
|---|---|---|
| [`networkpolicy-deny-smtp.yaml`](networkpolicy-deny-smtp.yaml) | Any CNI that supports `endPort` (Calico, Cilium, Antrea, OVN-Kubernetes, most cloud CNIs) | One namespace. Apply it to every workload namespace, or let Kyverno do it: |
| [`kyverno-generate-deny-smtp.yaml`](kyverno-generate-deny-smtp.yaml) | as above, plus Kyverno | Generates the NetworkPolicy into every namespace except Sigillum's and `kube-*`, including new ones |
| [`cilium-deny-smtp.yaml`](cilium-deny-smtp.yaml) | Cilium ≥ 1.15 | Cluster-wide deny rule, plus an FQDN allowlist for Sigillum itself |

Standard NetworkPolicy has no deny rules, so the vanilla recipe *allows*
all egress except the three SMTP ports. NetworkPolicies are additive: another
policy in the same namespace that allows port 587 re-opens it for the pods it
selects. The Cilium variant uses a real deny rule, which no allow rule can
override.

Test it from a workload pod (should time out or be refused):

```sh
kubectl run smtp-test --rm -it --restart=Never --image=busybox:1.36 -- \
  nc -vz -w 3 smtp.office365.com 587
```

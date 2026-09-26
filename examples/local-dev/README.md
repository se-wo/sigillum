# Local development with Mailpit (US-7.1)

A single-replica Sigillum that delivers everything into
[Mailpit](https://mailpit.axllent.org/) instead of real mailboxes. Works on
kind, k3d, minikube and Docker Desktop. No cert-manager, no Redis.

```sh
# 1. Mailpit, the capture backend.
kubectl create namespace mailpit
kubectl -n mailpit apply -f examples/local-dev/mailpit.yaml

# 2. Sigillum with the local profile (one replica, in-memory rate limits,
#    no admission webhook, SMTP proxy with credential logins over plaintext).
helm upgrade --install sigillum oci://ghcr.io/se-wo/charts/sigillum \
  --namespace sigillum-system --create-namespace \
  -f examples/local-dev/values-local.yaml

# 3. The Mailpit backend and a permissive policy for namespace "dev".
kubectl create namespace dev
kubectl -n dev create serviceaccount my-app
kubectl apply -f examples/local-dev/backend-and-policy.yaml
kubectl get clustermailbackend mailpit     # wait for READY=True
```

Send from the laptop as the `my-app` ServiceAccount:

```sh
kubectl -n sigillum-system port-forward svc/sigillum-api 8443:8443 &
TOKEN=$(kubectl -n dev create token my-app --audience sigillum)
curl -sS http://127.0.0.1:8443/v1/messages \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"from":"dev@example.com","to":["someone@example.com"],"subject":"hello","body":{"text":"it works"}}'

kubectl -n mailpit port-forward svc/mailpit 8025:8025   # then open http://127.0.0.1:8025
```

To try SMTP with a username and password, apply the credential in
`backend-and-policy.yaml` (already included) and read the generated Secret:

```sh
kubectl -n dev get secret my-app-smtp -o jsonpath='{.data.password}' | base64 -d
kubectl -n sigillum-system port-forward svc/sigillum-smtp 1587:587 &
# e.g. swaks --server 127.0.0.1:1587 --auth PLAIN --auth-user my-app.dev \
#   --auth-password "$PASSWORD" --from dev@example.com --to someone@example.com
```

The profile turns off everything a local cluster does not need. Do not use
it in production: plaintext AUTH, no webhook validation, per-replica rate
limits. A built-in capture driver is not planned: Mailpit does this well.

# Recipes

Tested configurations of standard tools, shipped instead of Sigillum
features where those tools already do the job (SPEC §8.0, rule 2). CI parses
every YAML file here and runs Sigillum's own validation on the Sigillum
resources (`test/examples`), renders the chart with the local-development
values, applies the ValidatingAdmissionPolicy recipes to a real API server,
and the kind e2e suite enforces `require-sender-restrictions`.

| Directory | What it gives you | Spec |
|---|---|---|
| [`local-dev/`](local-dev/) | Sigillum + Mailpit on kind, k3d, minikube or Docker Desktop in a few minutes | US-7.1 |
| [`egress/`](egress/) | Block direct SMTP egress so Sigillum cannot be bypassed | US-5.7 |
| [`admission/`](admission/) | Guardrails for policy authors (ValidatingAdmissionPolicy and Kyverno) | US-5.7, §4.9 |
| [`providers/`](providers/) | Backends for Microsoft 365, Google Workspace, Amazon SES, Mailgun, Postmark, Brevo | §8.2 |
| [`clients/`](clients/) | MailCredentials for Grafana, Alertmanager, Gitea, Nextcloud, Keycloak, Argo CD notifications | US-3.7 |
| [`reloader/`](reloader/) | Restart apps after a credential rotation with Stakater Reloader | US-3.7 |

Replace `sigillum-system` with your release namespace and `example.com`
with your domains throughout.

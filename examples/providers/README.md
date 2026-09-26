# Upstream providers via SMTP (SPEC §8.2)

Every common mail provider offers SMTP submission, which the built-in SMTP
driver covers. Each file holds a `ClusterMailBackend` and the credentials
Secret it reads (keys `username` and `password`, in the Sigillum release
namespace or one listed in `rbac.allowedSecretNamespaces`). Fill in the
Secret out of band (External Secrets, Sealed Secrets, `kubectl create
secret`), never in Git.

| Provider | Endpoint | Auth | Notes |
|---|---|---|---|
| [Microsoft 365](microsoft-365.yaml) | `smtp.office365.com:587` STARTTLS | `LOGIN` with a licensed mailbox | SMTP AUTH must be enabled for that mailbox. Microsoft is retiring Basic auth for SMTP AUTH; OAuth (`XOAUTH2`) is planned for v0.5.0. Alternative today: a connector for SMTP relay (`<tenant>.mail.protection.outlook.com:25`, `authType: NONE`), which needs a static egress IP. Sending limits: 10,000 recipients per day and mailbox. |
| [Google Workspace](google-workspace.yaml) | `smtp-relay.gmail.com:587` STARTTLS | `PLAIN` with an app password (2-Step Verification on the account), or `NONE` with the relay's IP allowlist | Configure the SMTP relay service in the Admin console ("Require SMTP authentication"). Daily limits per user apply. |
| [Amazon SES](amazon-ses.yaml) | `email-smtp.<region>.amazonaws.com:587` STARTTLS | `PLAIN` with SES SMTP credentials | SMTP credentials are derived from an IAM user; they are not the IAM access key. Verify the sender domain; leave the sandbox for production. |
| [Mailgun](mailgun.yaml) | `smtp.mailgun.org:587` (EU: `smtp.eu.mailgun.org`) STARTTLS | `PLAIN` with a domain SMTP user | |
| [Postmark](postmark.yaml) | `smtp.postmarkapp.com:587` STARTTLS | `PLAIN`; username and password are both the Server API token | Add header `X-PM-Message-Stream` for broadcast streams. |
| [Brevo](brevo.yaml) | `smtp-relay.brevo.com:587` STARTTLS | `LOGIN` with the SMTP key | |

Bounces, suppression lists, delivery status and DKIM stay with the provider
(SPEC §7); configure them there.

Check the backend after applying: `kubectl get cmb` shows `READY`, and
`kubectl describe cmb <name>` shows the per-endpoint probe result. The probe
only checks that the endpoint answers SMTP (and TLS); a wrong password shows
up as `502`/`451` on the first send, with the relay's reply in the log.

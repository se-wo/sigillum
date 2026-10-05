# Upstream providers via SMTP (SPEC §8.2)

Every common mail provider offers SMTP submission, which the built-in SMTP
driver covers. Each file holds a `ClusterMailBackend` and, where needed, the
credentials Secret it reads (keys `username` and `password`, in the Sigillum
release namespace or one listed in `rbac.allowedSecretNamespaces`). Fill in
the Secret out of band (External Secrets, Sealed Secrets, `kubectl create
secret`), never in Git.

The SMTP driver authenticates with `PLAIN`, `LOGIN` or `CRAM-MD5`, i.e. with
a static secret, or with `XOAUTH2` and a person's one-time sign-in (v0.4.0,
personal Outlook.com accounts, [`outlook-com.yaml`](outlook-com.yaml)).
Microsoft 365 work accounts can use the Microsoft Graph driver instead
(v0.4.0, [`microsoft-365-graph.yaml`](microsoft-365-graph.yaml)). A Gmail
API driver is planned for v0.4.0 (SPEC US-6.1, US-6.2). The table shows what still works with a static secret, as of
September 2026.

| Provider | File | Endpoint | Auth | Password login still possible? |
|---|---|---|---|---|
| Microsoft 365, SMTP AUTH | [`microsoft-365.yaml`](microsoft-365.yaml) | `smtp.office365.com:587` | `LOGIN`, mailbox password | **Being retired.** Works while SMTP AUTH is enabled for tenant and mailbox. Disabled by default for existing tenants at the end of December 2026 (admins can re-enable), not available to new tenants, final removal date announced in H2 2027. App passwords are no way out: they are Basic auth too and stop with it (personal Microsoft accounts no longer have them). Stopgap only. |
| Microsoft 365, Microsoft Graph (v0.4.0) | [`microsoft-365-graph.yaml`](microsoft-365-graph.yaml) | `graph.microsoft.com` (`sendMail`) | Entra app, client secret, `Mail.Send` scoped with RBAC for Applications | Not needed: no SMTP AUTH, no mailbox password. **Recommended for work accounts.** Up to 4 MB per message. Rotate the client secret before it expires (≤ 24 months). |
| Microsoft 365, relay connector | [`microsoft-365-connector.yaml`](microsoft-365-connector.yaml) | `<tenant>.mail.protection.outlook.com:25` | `NONE`, inbound connector by static egress IP | Not needed. Requires a static egress IP and outbound port 25. |
| Azure Communication Services | [`azure-communication-services.yaml`](azure-communication-services.yaml) | `smtp.azurecomm.net:587` | `LOGIN`, Entra app + client secret | Yes: a client secret, not a mailbox password. Rotate before it expires (≤ 24 months). |
| Microsoft 365 High Volume Email | [`microsoft-365-hve.yaml`](microsoft-365-hve.yaml) | `smtp-hve.office365.com:587` | `LOGIN`, HVE account | Yes, until September 2028, for **internal recipients only**. |
| Outlook.com (personal Microsoft account, v0.4.0) | [`outlook-com.yaml`](outlook-com.yaml) | `smtp-mail.outlook.com:587` | `XOAUTH2`, your own app registration and a one-time sign-in | **No.** Basic auth and app passwords are already gone for personal accounts. Sign in once with the code the controller shows; it keeps the token fresh. |
| Gmail (personal account) | [`gmail.yaml`](gmail.yaml) | `smtp.gmail.com:587` | `PLAIN` with an app password | Only app passwords (2-Step Verification on); no cut-off announced. Gmail API driver with a one-time sign-in planned for v0.4.0. |
| Google Workspace | [`google-workspace.yaml`](google-workspace.yaml) | `smtp-relay.gmail.com:587` | `PLAIN` with an app password, or `NONE` by static egress IP | Only app passwords (2-Step Verification, not disabled by the admin); no cut-off announced. "Less secure apps" are gone; plain account passwords are rejected. A Gmail API driver with a service account is planned for v0.4.0. |
| Amazon SES | [`amazon-ses.yaml`](amazon-ses.yaml) | `email-smtp.<region>.amazonaws.com:587` | `PLAIN`, SES SMTP credentials | Yes. Derived from an IAM user (not the IAM access key). Verify the sender domain; leave the sandbox for production. |
| Mailgun | [`mailgun.yaml`](mailgun.yaml) | `smtp.mailgun.org:587` (EU: `smtp.eu.mailgun.org`) | `PLAIN`, domain SMTP credential | Yes. |
| Postmark | [`postmark.yaml`](postmark.yaml) | `smtp.postmarkapp.com:587` | `PLAIN`, Server API token or SMTP token | Yes. Add header `X-PM-Message-Stream` for broadcast streams. |
| Brevo | [`brevo.yaml`](brevo.yaml) | `smtp-relay.brevo.com:587` | `LOGIN`, SMTP key | Yes: an SMTP key, not the account password. |

A personal Outlook.com account needs v0.4.0 (`XOAUTH2`); a personal Gmail
account works with an app password.

For Microsoft 365: use the Graph driver (v0.4.0). Without it, use the relay
connector if you have a static egress IP, Azure Communication Services if
you do not, and HVE for purely internal mail. Keep SMTP AUTH with a mailbox
password or app password only as a bridge, and no later than the end of
December 2026.

Provider rules change; check the provider's current documentation before
relying on a date above.

Bounces, suppression lists, delivery status and DKIM stay with the provider
(SPEC §7); configure them there.

Check the backend after applying: `kubectl get cmb` shows `READY`, and
`kubectl describe cmb <name>` shows the per-endpoint probe result. The probe
only checks that the endpoint answers SMTP (and TLS); a wrong password shows
up as `502`/`451` on the first send, with the relay's reply in the log.

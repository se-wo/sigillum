# Off-the-shelf apps with MailCredentials (US-3.7)

Most third-party software only speaks SMTP with a username and password.
A `MailCredential` gives such an app its own Sigillum login, bound to its
ServiceAccount: the same policy matching, rate limits and audit trail as a
token caller, without handing out the relay password.

Prerequisites (platform team, once):

```yaml
# Helm values
smtp:
  enabled: true
  authModes: [oauthbearer, credential]
  tls:
    secretName: sigillum-smtp-tls   # STARTTLS; see "TLS" below
credentials:
  enabled: true                      # generated passwords
```

Per app (the team, in Git): the `MailCredential` and a `MailPolicy` from the
file for that app. The controller creates the Secret (`username`,
`password`, `host`, `port`) in the app's namespace; nothing secret is
committed. Point the app at it:

| App | File | Where the app reads the Secret |
|---|---|---|
| Grafana | [`grafana.yaml`](grafana.yaml) | Helm values `smtp.existingSecret` |
| Alertmanager | [`alertmanager.yaml`](alertmanager.yaml) | `smtp_auth_password_file` from a mounted Secret |
| Gitea | [`gitea.yaml`](gitea.yaml) | `GITEA__MAILER__USER` / `GITEA__MAILER__PASSWD` env |
| Nextcloud | [`nextcloud.yaml`](nextcloud.yaml) | `SMTP_NAME` / `SMTP_PASSWORD` env |
| Keycloak | [`keycloak.yaml`](keycloak.yaml) | realm email settings, password from the Keycloak vault |
| Argo CD notifications | [`argocd-notifications.yaml`](argocd-notifications.yaml) | `argocd-notifications-secret` (bring-your-own-hash mode) |

App settings, all with host `sigillum-smtp.sigillum-system.svc`, port
`587`, STARTTLS required, and the username `<credential>.<namespace>` from
the Secret's `username` key:

**Grafana** (grafana/grafana chart):

```yaml
smtp:
  existingSecret: grafana-smtp
  userKey: username
  passwordKey: password
grafana.ini:
  smtp:
    enabled: true
    host: sigillum-smtp.sigillum-system.svc:587
    from_address: grafana@monitoring.example.com
    startTLS_policy: MandatoryStartTLS
```

**Alertmanager** (kube-prometheus-stack; the Secret is mounted under
`/etc/alertmanager/secrets/<name>/`):

```yaml
alertmanager:
  alertmanagerSpec:
    secrets: [alertmanager-smtp]
  config:
    global:
      smtp_smarthost: sigillum-smtp.sigillum-system.svc:587
      smtp_from: alertmanager@monitoring.example.com
      smtp_auth_username: alertmanager.monitoring
      smtp_auth_password_file: /etc/alertmanager/secrets/alertmanager-smtp/password
      smtp_require_tls: true
```

**Gitea** (gitea-charts/gitea):

```yaml
gitea:
  config:
    mailer:
      ENABLED: true
      PROTOCOL: smtp+starttls
      SMTP_ADDR: sigillum-smtp.sigillum-system.svc
      SMTP_PORT: 587
      FROM: gitea@example.com
  additionalConfigFromEnvs:
    - name: GITEA__MAILER__USER
      valueFrom: { secretKeyRef: { name: gitea-smtp, key: username } }
    - name: GITEA__MAILER__PASSWD
      valueFrom: { secretKeyRef: { name: gitea-smtp, key: password } }
```

**Nextcloud** (nextcloud/nextcloud chart; the image reads `SMTP_*` env):

```yaml
nextcloud:
  mail:
    enabled: true
    fromAddress: nextcloud
    domain: example.com
    smtp:
      host: sigillum-smtp.sigillum-system.svc
      port: 587
      secure: ""        # STARTTLS is negotiated on 587
      authtype: LOGIN
  extraEnv:
    - name: SMTP_NAME
      valueFrom: { secretKeyRef: { name: nextcloud-smtp, key: username } }
    - name: SMTP_PASSWORD
      valueFrom: { secretKeyRef: { name: nextcloud-smtp, key: password } }
```

**Keycloak**: in *Realm settings → Email* set host, port 587, *Enable
StartTLS*, *Enable Authentication*, username `keycloak.keycloak`, and
password `${vault.smtp-password}`. Start Keycloak with the file vault
(`--vault=file --vault-dir=/opt/keycloak/vault`) and mount the generated
Secret there with `items: [{key: password, path: <realm>_smtp-password}]`.
Realm imports (`KeycloakRealmImport`) take the same `smtpServer` block.

**Argo CD notifications** reads SMTP credentials only from
`argocd-notifications-secret`, which Argo CD's own manifests create. Use
bring-your-own-hash mode instead of a generated Secret:

```sh
PASSWORD=$(openssl rand -base64 32)
# argon2id, 19 MiB, 2 passes (argon2 CLI; or python argon2-cffi PasswordHasher)
HASH=$(printf %s "$PASSWORD" | argon2 "$(openssl rand -hex 16)" -id -t 2 -k 19456 -p 1 -e)
kubectl -n argocd patch secret argocd-notifications-secret --type merge \
  -p "{\"stringData\":{\"email-username\":\"argocd-notifications.argocd\",\"email-password\":\"$PASSWORD\"}}"
# put $HASH into spec.passwordHash of argocd-notifications.yaml, then apply it
```

```yaml
# argocd-notifications-cm
data:
  service.email.sigillum: |
    host: sigillum-smtp.sigillum-system.svc
    port: 587
    from: argocd@example.com
    username: $email-username
    password: $email-password
```

## TLS

Credential logins require STARTTLS (`smtp.tls.secretName`): a password,
unlike a token, stays valid for months if it leaks. The certificate must be
valid for `sigillum-smtp.sigillum-system.svc` and trusted by the apps, for
example issued by cert-manager from an internal CA whose certificate you
distribute with trust-manager. Inside a service mesh that encrypts
pod-to-pod traffic with mTLS you may instead set `smtp.allowInsecureAuth:
true`.

## Rotation and revocation

- Rotate now: `kubectl -n monitoring annotate mailcredential grafana
  sigillum.dev/rotate="$(date +%s)" --overwrite`. The previous password
  keeps working for `spec.rotation.gracePeriod` (default 24h); audit records
  of logins that still use it carry `"credential_previous": true`.
- Rotate periodically: `spec.rotation.interval: 90d`.
- Apps that read the password only at startup need a restart; see
  [`../reloader/`](../reloader/).
- Revoke: delete the `MailCredential`. Its Secret is garbage-collected, and
  the proxy refuses the credential, including on open connections, as soon
  as it sees the deletion.

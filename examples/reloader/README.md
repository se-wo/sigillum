# Restart apps after a credential rotation (US-3.7)

Most apps read their SMTP password once, at startup. After a rotation of a
generated `MailCredential` the new password is in the Secret, and the old
one keeps working for `spec.rotation.gracePeriod` (default 24h). Restart the
app within that window, automatically with
[Stakater Reloader](https://github.com/stakater/Reloader):

```sh
helm repo add stakater https://stakater.github.io/stakater-charts
helm install reloader stakater/reloader -n reloader --create-namespace
```

Annotate the app's workload with the generated Secret's name
([`grafana-deployment-patch.yaml`](grafana-deployment-patch.yaml)); Reloader
performs a rolling restart whenever that Secret changes. With the Grafana
chart this is `annotations` in its values:

```yaml
annotations:
  secret.reloader.stakater.com/reload: grafana-smtp
```

Apps that mount the Secret as a file and re-read it per message (for example
Alertmanager with `smtp_auth_password_file`) need no restart; the kubelet
updates the file within about a minute.

Find stragglers before the grace period ends: audit records of logins with
the previous password carry `"credential_previous": true` and the
credential's username, and the SMTP proxy logs a warning for each.

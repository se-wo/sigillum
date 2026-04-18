# Sigillum — High-Level Spezifikation

*Policy-enforced mail gateway for Kubernetes*

| Feld | Wert |
|---|---|
| **Name** | Sigillum |
| **Version** | 0.1 — Draft for Engineering Review |
| **Status** | Zur Implementierungsplanung freigegeben |
| **Autor** | Sebastian (privates OSS-Projekt) |
| **Zielgruppe** | Platform Engineering (fiktiv) — privates OSS-Projekt, inspiriert von realen Anforderungen |
| **Zweck** | Fachliche und technische Grundlage für den Implementierungsplan (Ultraplan) |

---

## 1. Produktvision

### 1.1 Problemstellung

In unserem Kubernetes-Ökosystem versenden zahlreiche Workloads (Applikationen, CronJobs, Operators, Monitoring-Stack) E-Mails — typischerweise Transaktionsmails, Notifications, Reports. Der heutige Zustand hat drei strukturelle Schwächen:

1. **Credential-Sprawl:** Jeder Workload führt eigene SMTP-Credentials als Secret. Rotation, Audit und Revokation sind operativ teuer und fehleranfällig.
2. **Fehlende Policy-Durchsetzung:** Der zentrale Mailserver akzeptiert jede Absenderadresse innerhalb unserer Domain. Ein kompromittierter Workload kann Phishing-Mails unter beliebigen internen Identitäten versenden.
3. **Keine Observability / Rate-Control:** Es existiert keine zentrale Sicht auf E-Mail-Volumina pro Workload und keine Schutzschicht gegen Runaway-Loops (z. B. fehlerhafte Retry-Logik, die Tausende Mails erzeugt).

### 1.2 Produktvision

> **Sigillum ist ein Kubernetes-natives Mail-Gateway, das sichere, policy-kontrollierte E-Mail-Zustellung für Cluster-Workloads bereitstellt — ohne dass Entwickler SMTP-Credentials verwalten müssen.**

Das Gateway bietet eine REST-API als primäres Interface sowie einen SMTP-Proxy für Legacy-Integration. Policies werden deklarativ als Custom Resources verwaltet und folgen den etablierten Kubernetes-Konventionen (GitOps, RBAC, Namespaces). Authentifizierung erfolgt K8s-nativ über ServiceAccount-Tokens oder Istio-mTLS — nicht über separate API-Keys.

### 1.3 Geschäftsziele

| Ziel | Messbar als |
|---|---|
| Reduktion verwalteter Mail-Credentials | 1 zentrale Credential-Konfiguration statt N pro Workload |
| Compliance-Konformität (BSI/NIS2) | Auditierbarer Absender-Nachweis pro Mail, vollständiges Audit-Log |
| Betriebssicherheit | Rate-Limit-Durchsetzung verhindert Runaway-Versand |
| Entwicklerfreundlichkeit | Kein Credential-Management im Workload-Code |

### 1.4 Nicht-Ziele

Folgende Funktionen sind explizit **kein** Bestandteil dieses Produkts — weder jetzt noch in späteren Versionen:

- **Mail-Speicherung / Postfächer auf Sigillum-Seite:** Sigillum hostet selbst keine Mailboxen. Read-Funktionalität (siehe 1.5) erfolgt immer via Backend, nicht via lokaler Storage.
- **Template-Engine:** Rendering bleibt Aufgabe des Workloads.
- **Address-Resolution / Distribution Lists:** Empfängerlisten verantwortet der Aufrufer.
- **DKIM/DMARC-Signierung:** Wird durch das Backend erledigt, nicht durch Sigillum.
- **Mailrelay-Funktionalität für externe Sender:** Nur Cluster-interne Workloads sind Nutzer.
- **Anti-Spam / Content-Filtering:** Nicht im Scope.

### 1.5 Nicht im MVP, aber architektonisch vorgesehen

Diese Fähigkeiten sind nicht Teil von v1.0, aber die Architektur muss sie ermöglichen, ohne dass Breaking Changes an CRDs oder API entstehen:

- **Mail-Empfang (Read-Path):** Zugriff auf ein Postfach via Backend-nativer API (IMAP, Microsoft Graph Mail.Read, Gmail API). Read-Funktionalität bleibt pro Backend optional.
- **Backend-Diversität:** Neben klassischem SMTP sollen API-basierte Backends anbindbar sein — konkret im Blick: Microsoft Graph (Mail.Send / Mail.Read), SendGrid, Gmail API. Jedes Backend deklariert seine Capabilities; Policies und API-Oberfläche respektieren diese.
- **IMAP-Proxy für Legacy-Reader:** Analog zum SMTP-Proxy auf dem Send-Pfad könnte ein IMAP-Proxy Legacy-Workloads erlauben, Postfächer zu lesen, deren Backend eigentlich Graph oder Gmail ist.

Konsequenz für die v1-Architektur: Die CRDs, das Driver-Interface und das Capability-Modell sind so geschnitten, dass diese Erweiterungen *additiv* sind — kein Migration-Pfad, keine neuen API-Gruppen nötig.

---

## 2. Personas

| Persona | Verantwortlichkeit | Primäre Interaktion |
|---|---|---|
| **Application Developer (Dev)** | Entwickelt Workloads, die E-Mails senden | REST-API / SMTP-Clientbibliothek |
| **Platform Engineer (PE)** | Betreibt Sigillum, pflegt Upstream-Konfiguration | CRDs, Helm-Chart, Metriken |
| **Security / Compliance Officer (SCO)** | Definiert Policies, auditiert Nutzung | CRDs (MailPolicy), Audit-Logs |
| **Namespace-Owner / Tenant-Admin** | Verantwortlich für eigene Team-Namespaces | MailPolicy-CRs im eigenen Namespace |

---

## 3. User Stories

User Stories sind nach Epics gruppiert. Jede Story folgt dem Schema **Als \<Rolle\> möchte ich \<Fähigkeit\>, damit \<Nutzen\>** und enthält Akzeptanzkriterien.

### Epic 1 — E-Mail-Versand aus Workloads

#### US-1.1 — REST-API-Versand
**Als** Developer **möchte ich** E-Mails per HTTP-POST an Sigillum senden, **damit** ich ohne SMTP-Library und ohne Credential-Handling Mails verschicken kann.

*Akzeptanzkriterien:*
- Endpoint `POST /v1/messages` akzeptiert JSON-Payload mit `from`, `to`, `cc`, `bcc`, `subject`, `body` (text/html), `attachments`, `headers`.
- Response enthält `message_id` für nachgelagerte Korrelation.
- Synchrone Annahme der Mail (Upstream-Delivery kann asynchron erfolgen).
- HTTP-Statuscodes folgen Semantik: `202 Accepted`, `400` (Payload-Fehler), `401` (Auth), `403` (Policy-Verletzung), `429` (Rate-Limit), `502` (Upstream-Fehler).

#### US-1.2 — SMTP-Proxy für Legacy-Workloads
**Als** Developer **möchte ich** den bestehenden SMTP-Client meiner Legacy-Anwendung nutzen können, **damit** ich keinen Code refactoren muss — aber mit moderner, K8s-nativer Authentifizierung statt Pod-IP-Vertrauen.

*Akzeptanzkriterien:*
- SMTP-Server akzeptiert Verbindungen auf Port 587 cluster-intern.
- Unterstützt SMTP-Submission-Flow (MAIL FROM, RCPT TO, DATA).
- Authentifizierung über drei Modi (per Deployment konfigurierbar, Präzedenz in angegebener Reihenfolge):
  1. **Istio-mTLS** — Ableitung der Identität aus SPIFFE-ID (siehe US-3.3).
  2. **SASL OAUTHBEARER** (RFC 7628) — ServiceAccount-Token via SASL (siehe US-3.4).
  3. **Pod-IP-Lookup** — Fallback, nur aktiv wenn per Policy explizit erlaubt (siehe US-3.5).
- STARTTLS optional, intern via Service-Mesh bevorzugt.
- Ist als eigenständige Komponente deaktivierbar für Deployments, die rein auf REST setzen.

#### US-1.3 — Anhänge
**Als** Developer **möchte ich** Dateianhänge verschicken können, **damit** ich Reports als PDF versenden kann.

*Akzeptanzkriterien:*
- REST: Anhänge als Base64 im JSON oder als `multipart/form-data`.
- Größenlimit konfigurierbar pro Policy (Default: 10 MiB pro Mail).
- Content-Type und Dateiname werden übernommen.

#### US-1.4 — Fehlertransparenz
**Als** Developer **möchte ich** verständliche Fehlermeldungen erhalten, **damit** ich weiß, ob ich retryen soll oder ob mein Payload fehlerhaft ist.

*Akzeptanzkriterien:*
- RFC-7807 Problem-Details-Format für Fehler.
- Unterscheidung zwischen retry-fähig (`5xx`) und nicht-retry-fähig (`4xx`).
- Policy-Verletzungen enthalten Verweis auf den verletzten Regel-Namen.

---

### Epic 2 — Policy-Management via CRDs

#### US-2.1 — Mail-Backend als CRD
**Als** Platform Engineer **möchte ich** Mail-Backends als CRD definieren (`MailBackend` / `ClusterMailBackend`), **damit** ich sie per GitOps verwalten und verschiedene Backend-Typen ohne API-Migration einbinden kann.

*Akzeptanzkriterien:*
- Namespace-scoped CRD `MailBackend` und cluster-scoped CRD `ClusterMailBackend`.
- Spec enthält einen `type`-Diskriminator (`smtp` in v1; `microsoftGraph`, `sendgrid`, `gmail` als future, nicht implementiert).
- Bei `type: smtp`: `endpoints`-Liste (mindestens ein Eintrag), `authType`, `credentialsRef`.
- `endpoints` ist eine geordnete Failover-Liste; der erste Ready-Endpoint wird für Sends verwendet.
- Validation-Webhook prüft Erreichbarkeit beim Create/Update für jeden Endpoint (nur für implementierte Typen).
- Status-Subresource reflektiert: `Ready`-Condition (True, wenn mind. 1 Endpoint Ready), `capabilities` (vom Driver deklariert), `endpointStatus` pro Endpoint, `lastProbeTime`.
- Unbekannte/nicht-implementierte `type`-Werte werden abgelehnt mit klarer Fehlermeldung.

#### US-2.2 — Mail-Policies mit Rate-Limiting
**Als** Platform Engineer **möchte ich** pro Namespace Rate-Limits definieren können, **damit** ein fehlerhafter Workload nicht den gesamten Mailversand stört.

*Akzeptanzkriterien:*
- Namespace-scoped CRD `MailPolicy`.
- Rate-Limits konfigurierbar als `messagesPerMinute` und `messagesPerHour`.
- Sliding-Window-Zählung.
- Bei Überschreitung: HTTP 429 mit `Retry-After`-Header; SMTP: `421` Response.

#### US-2.3 — Absender-Adressvalidierung
**Als** Security Officer **möchte ich** erlaubte Absenderadressen pro Policy whitelisten können, **damit** Workloads nur unter autorisierten Identitäten senden.

*Akzeptanzkriterien:*
- `allowedSenders` als Liste von Exact-Match und Glob-Patterns (z. B. `*@noreply.example.com`).
- Bei Verletzung: HTTP 403 mit eindeutigem Error-Code `sender_not_allowed`.
- Policy-Match per `subjectSelector` (siehe US-3.x).

#### US-2.4 — Empfänger-Allow/Denylist
**Als** Security Officer **möchte ich** Empfänger-Domains einschränken können, **damit** Entwicklungs-Workloads keine Mails an externe Adressen senden.

*Akzeptanzkriterien:*
- `allowedRecipientDomains` (Allowlist) und `blockedRecipientDomains` (Denylist) optional konfigurierbar.
- Denylist hat Vorrang vor Allowlist.

#### US-2.5 — Multi-Backend-Routing
**Als** Platform Engineer **möchte ich** pro Policy ein anderes Backend wählen können, **damit** z. B. Test-Workloads in einen MailHog senden und Prod-Workloads in den echten Corporate-SMTP oder (künftig) in Microsoft Graph.

*Akzeptanzkriterien:*
- `backendRef` in `MailPolicy` zeigt auf eine `MailBackend` oder `ClusterMailBackend` (`kind`-Feld unterscheidet).
- Referenziertes Backend muss `status.capabilities` enthalten, die die Operation abdecken (z. B. `send` für POST /v1/messages).
- Fehlt die Policy oder existiert der Backend nicht / ist nicht Ready, wird die Mail abgelehnt (kein Default-Backend).

#### US-2.6 — Policy-Priorität bei mehrfachem Match
**Als** Platform Engineer **möchte ich** deterministisches Verhalten bei überlappenden Policies, **damit** Konfigurationen vorhersagbar sind.

*Akzeptanzkriterien:*
- Bei mehreren Matches: spezifischster Match gewinnt (nach definierten Regeln, dokumentiert in CRD-Schema).
- Tie-Break: alphabetisch nach Policy-Name.
- Nicht-gematchte Requests werden mit `403 no_policy_matched` abgelehnt (Default-Deny).

---

### Epic 3 — Kubernetes-native AuthN/AuthZ

#### US-3.1 — ServiceAccount-Token-Authentifizierung
**Als** Developer **möchte ich** mich mit meinem Pod-ServiceAccount-Token authentifizieren, **damit** ich keine separaten Credentials verwalten muss.

*Akzeptanzkriterien:*
- REST-API akzeptiert `Authorization: Bearer <token>`.
- Token wird via Kubernetes `TokenReview` API validiert (projected ServiceAccount-Token mit Audience `sigillum`).
- `TokenReview`-Response liefert Namespace und SA-Name; diese werden für Policy-Matching verwendet.
- Ungültige/abgelaufene Tokens werden mit `401 invalid_token` abgelehnt.

#### US-3.2 — Policy-Subject-Matching
**Als** Security Officer **möchte ich** Policies an konkrete ServiceAccounts oder Labels binden können, **damit** Policies feingranular greifen.

*Akzeptanzkriterien:*
- `MailPolicy.spec.subjects` kann drei Matcher-Typen enthalten:
  - `serviceAccount: {name, namespace}` — exakter SA-Match
  - `serviceAccountSelector: {matchLabels}` — Label-Selector auf SA
  - `podSelector: {matchLabels}` — für SMTP-Pfad via Pod-IP-Lookup
- Match-Auswertung erfolgt in Reihenfolge: explicit SA > SA-Selector > Pod-Selector.

#### US-3.3 — Istio-mTLS-Authentifizierung (optional, stärkster Modus)
**Als** Platform Engineer **möchte ich** bei aktivem Istio-Service-Mesh die SPIFFE-Identität für Auth nutzen können, **damit** Token-Handling entfällt und Auth kryptographisch an die Workload-Identität gebunden ist.

*Akzeptanzkriterien:*
- Optional aktivierbarer Auth-Modus `istio`.
- Auswertung des `X-Forwarded-Client-Cert`-Headers (Istio-sidecar-injiziert).
- SPIFFE-ID wird geparst und auf SA/Namespace gemappt.
- Gilt für REST-Pfad; für SMTP-Pfad analog über Peer-Identität der mTLS-Verbindung.

#### US-3.4 — SASL OAUTHBEARER für SMTP (und future IMAP)
**Als** Developer **möchte ich** mein SMTP-Client-Programm mit meinem ServiceAccount-Token authentifizieren, **damit** die SMTP-Auth dieselbe Vertrauensbasis hat wie REST — statt schwacher Pod-IP-Vertrauensannahme.

*Akzeptanzkriterien:*
- SMTP-Server kann `AUTH OAUTHBEARER` (RFC 7628) aushandeln.
- Token-Extraktion aus dem SASL-Payload (Format: `n,a=<user>,^Aauth=Bearer <token>^A^A`).
- Token-Validierung erfolgt wie im REST-Pfad via Kubernetes `TokenReview` API mit Audience `sigillum`.
- SA-Name und Namespace aus `TokenReview`-Response werden für Policy-Matching verwendet — identisch zum REST-Pfad.
- Ungültige oder abgelaufene Tokens werden mit SMTP-Response `535 5.7.8 Authentication credentials invalid` abgelehnt.
- Projected ServiceAccount-Token (typischerweise unter `/var/run/secrets/tokens/sigillum`) ist der Standard-Lieferweg; Beispiel-Pod-Spec in der Dokumentation.
- Modus ist pro SMTP-Proxy-Deployment aktivierbar; kann parallel zu `istio` konfiguriert sein.

#### US-3.5 — Pod-IP-Auth als expliziter Legacy-Fallback
**Als** Platform Engineer **möchte ich** Pod-IP-basierte Identifikation nur für Workloads erlauben, die SASL-Auth nicht können, **damit** der schwache Auth-Modus nicht implizit für alle Workloads gilt.

*Akzeptanzkriterien:*
- Pod-IP-Auth ist nicht Default, sondern muss pro `MailPolicy` aktiviert werden (`spec.legacyAuth.podIPFallback: true`).
- Ist SASL-Auth am SMTP-Handshake erfolgt, wird Pod-IP-Auth ignoriert (stärkerer Modus gewinnt).
- Policies mit Pod-IP-Fallback werden im Status sichtbar als `UsingLegacyAuth` Condition markiert, damit Security-Scans sie finden.
- Grund: Pod-IPs sind in NAT-/Mesh-/CNI-Szenarien unzuverlässig und nicht kryptographisch an Identitäten gebunden.

#### US-3.6 — API-Server-RBAC für CRDs
**Als** Platform Engineer **möchte ich** dass CRD-Zugriff über Standard-K8s-RBAC gesteuert wird, **damit** keine separaten Berechtigungsmodelle entstehen.

*Akzeptanzkriterien:*
- CRDs sind reguläre K8s-Resources und respektieren RBAC.
- Controller verwendet minimalen RBAC-Scope (least privilege).
- Dokumentierte `ClusterRole`-Templates für `view`, `edit`, `admin`.

---

### Epic 4 — Operations & Observability

#### US-4.1 — Prometheus-Metriken
**Als** Platform Engineer **möchte ich** Metriken über Mail-Durchsatz, Latenz und Fehler, **damit** ich SLOs definieren kann.

*Akzeptanzkriterien:*
- `/metrics`-Endpoint im Prometheus-Format.
- Mindestens folgende Metriken (Label: `namespace`, `policy`, `backend`, `result`):
  - `sigillum_messages_total` (Counter)
  - `sigillum_message_size_bytes` (Histogram)
  - `sigillum_backend_duration_seconds` (Histogram)
  - `sigillum_ratelimit_rejected_total` (Counter)
  - `sigillum_policy_denied_total` (Counter, Label: `reason`)
- ServiceMonitor-Manifest als Teil des Helm-Charts.

#### US-4.2 — Strukturierte Logs
**Als** Platform Engineer **möchte ich** strukturierte JSON-Logs, **damit** ich Mails durchsuchen und korrelieren kann.

*Akzeptanzkriterien:*
- JSON-Logformat (`slog` oder `zap`).
- Log-Level via ENV steuerbar.
- Pflichtfelder pro Log-Eintrag: `timestamp`, `level`, `message_id`, `namespace`, `service_account`, `authMethod` (`istio` | `oauth_bearer` | `pod_ip_legacy`), `policy`, `backend`, `result`.
- Keine Mail-Inhalte in Logs (nur Metadaten).

#### US-4.3 — Audit-Log-Stream
**Als** Security Officer **möchte ich** einen separaten Audit-Log-Stream, **damit** Compliance-Anforderungen (BSI, NIS2) erfüllt werden.

*Akzeptanzkriterien:*
- Separater Logger mit fixer Struktur, auf stdout (Sidecar-Aggregation möglich).
- Log-Eintrag pro Mail-Request, auch bei Ablehnung.
- Enthält: Zeitstempel, Caller-Identity (SA/Namespace), `from`, `to[]`, Policy-Name, Decision (`accept`/`reject`), Reason, `message_id`.
- Keine Mail-Body-Inhalte im Audit-Log.

#### US-4.4 — OpenTelemetry-Tracing
**Als** Platform Engineer **möchte ich** Traces vom REST-Aufruf bis zum Upstream-SMTP-Send, **damit** ich Latenzprobleme debuggen kann.

*Akzeptanzkriterien:*
- OTLP-Export konfigurierbar via Standard-ENV-Vars.
- Span-Hierarchie: `http.request` → `auth.tokenreview` → `policy.evaluate` → `backend.send`.
- W3C Trace-Context-Propagation (eingehender `traceparent`-Header wird übernommen).

---

### Epic 5 — Platform Operations

#### US-5.1 — GitOps-kompatibles Deployment
**Als** Platform Engineer **möchte ich** Sigillum via Helm-Chart oder Kustomize deployen, **damit** es in unseren ArgoCD-Flow passt.

*Akzeptanzkriterien:*
- Offizielles Helm-Chart mit sinnvollen Defaults.
- Alle Konfigurationsparameter via `values.yaml`.
- CRDs separat installierbar (Helm-Hook oder eigenes Chart).
- Keine Runtime-Konfiguration außerhalb von K8s-Resources (kein init-Script).

#### US-5.2 — Hochverfügbarkeit
**Als** Platform Engineer **möchte ich** Sigillum HA betreiben, **damit** ein Pod-Ausfall keinen Mail-Versand unterbricht.

*Akzeptanzkriterien:*
- Stateless-Design (Rate-Limit-State extern).
- Horizontale Skalierung via Replicas möglich.
- PodDisruptionBudget im Chart.
- Leader-Election für Controller (nicht für API-Server).

#### US-5.3 — Graceful Shutdown
**Als** Platform Engineer **möchte ich** dass laufende Mail-Requests bei Pod-Termination abgeschlossen werden, **damit** keine Mails verloren gehen.

*Akzeptanzkriterien:*
- SIGTERM löst Draining aus; Readiness-Probe wird `false`.
- Laufende Requests dürfen `terminationGracePeriodSeconds` (Default: 30 s) nutzen.
- Neue Requests werden in Draining-Phase abgelehnt (`503`).

#### US-5.4 — Health- und Readiness-Probes
**Als** Platform Engineer **möchte ich** K8s-Standard-Probes, **damit** Self-Healing funktioniert.

*Akzeptanzkriterien:*
- `/healthz`: Liveness — prüft Prozess.
- `/readyz`: Readiness — prüft Upstream-Erreichbarkeit und Controller-Sync.

#### US-5.5 — Resource-Limits und Security-Context
**Als** Platform Engineer **möchte ich** definierte Resource-Requests/Limits und gehärteten SecurityContext, **damit** das Deployment unseren Baseline-Policies entspricht.

*Akzeptanzkriterien:*
- Non-root, read-only-Rootfs, dropped Capabilities.
- Default-Resources im Chart, überschreibbar.
- Kompatibel mit Pod Security Standards `restricted`.

---

### Epic 6 — Erweiterbarkeit (Future, nicht v1-Scope)

Dieser Epic beschreibt *architektonische Vorgaben*, nicht zu bauende Features. Die v1-Architektur muss diese Erweiterungen ohne Breaking Changes ermöglichen.

#### US-6.1 — Microsoft Graph als Send-Backend (future)
**Als** Platform Engineer **möchte ich** künftig Microsoft Graph (`Mail.Send`) als Backend-Typ konfigurieren können, **damit** Workloads über Microsoft 365 senden können ohne separaten SMTP-Server.

*Architektonische Vorgabe für v1:*
- `MailBackend.spec.type` akzeptiert den Wert `microsoftGraph` semantisch (Schema-Platzhalter vorhanden, Validation lehnt ihn in v1 ab).
- Kein Redesign der CRDs nötig, wenn `microsoftGraph`-Driver hinzukommt.

#### US-6.2 — SendGrid / Gmail als Send-Backend (future)
**Als** Platform Engineer **möchte ich** SendGrid (API-Key) und Gmail API (Service-Account) als Backends einbinden können.

*Architektonische Vorgabe für v1:*
- Verschiedene Auth-Mechanismen pro Backend-Typ (API-Key, Service-Account-JSON, OAuth2-Client-Credentials) müssen über typ-spezifische Secret-Strukturen abbildbar sein, ohne die zentrale Secret-Handling-Logik zu ändern.

#### US-6.3 — Mail-Lesen via REST (future)
**Als** Developer **möchte ich** künftig Postfächer per REST-API lesen können (List, Fetch, Search), **damit** Workloads eingehende Mails verarbeiten können ohne IMAP-Library.

*Architektonische Vorgabe für v1:*
- Driver-Interface enthält vorreservierte Methoden `Read()` und `Subscribe()`.
- API-Oberfläche ist versionierbar; `/v1/messages` bleibt für Send, Read-Endpoints können additiv unter `/v1/mailboxes/...` eingeführt werden.

#### US-6.4 — IMAP-Proxy für Legacy-Reader (future)
**Als** Developer einer Legacy-Anwendung **möchte ich** künftig Postfächer per IMAP lesen können, auch wenn das Backend Microsoft Graph ist.

*Architektonische Vorgabe für v1:*
- Der api-server ist so modularisiert, dass zusätzliche Protokoll-Adapter (SMTP-Proxy, IMAP-Proxy) additiv aktivierbar sind.

#### US-6.5 — Webhook-Push für Backend-Events (future)
**Als** Developer **möchte ich** Events wie Bounces, Delivery-Bestätigungen oder eingehende Mails per Webhook an meinen Workload geliefert bekommen.

*Architektonische Vorgabe für v1:*
- Der Controller ist so ausgelegt, dass er später eine Webhook-Receiver-Komponente betreiben kann; keine Architekturänderung nötig.

---

## 4. Architektur

### 4.1 Komponentenübersicht

```
┌─────────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                       │
│                                                              │
│  Caller Workload                  Sigillum System        │
│  ┌──────────────┐                 ┌────────────────────────┐ │
│  │  App-Pod     │  HTTPS + Bearer │  api-server (N Repl.)  │ │
│  │              │ ───────────────▶│  ┌──────────────────┐  │ │
│  │              │  SMTP (587)     │  │ REST Handler     │  │ │
│  │              │ ───────────────▶│  │ SMTP Handler     │  │ │
│  └──────────────┘                 │  │ Auth (TokenRev.) │  │ │
│                                   │  │ Policy Engine    │  │ │
│                                   │  │ Upstream Client  │  │ │
│                                   │  └──────────────────┘  │ │
│                                   └────────┬───────────────┘ │
│                                            │                 │
│  ┌─────────────────────┐                   │                 │
│  │  controller         │                   │                 │
│  │  (Leader-elected)   │                   │                 │
│  │  ┌────────────────┐ │                   │                 │
│  │  │ CRD Reconciler │ │                   │                 │
│  │  │ Validation WH  │ │                   │                 │
│  │  │ Upstream Probe │ │                   │                 │
│  │  └────────────────┘ │                   │                 │
│  └─────────────────────┘                   │                 │
│             │                              │                 │
│             ▼                              ▼                 │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                K8s API (CRDs, Secrets, TokenReview)    │  │
│  └────────────────────────────────────────────────────────┘  │
│                                            │                 │
│  ┌────────────────────────────┐            │                 │
│  │ Rate-Limit Backend         │◀───────────┘                 │
│  │ (Redis oder In-Memory)     │                              │
│  └────────────────────────────┘                              │
└──────────────────────────────────────────┼───────────────────┘
                                           ▼
                                  Backend (SMTP / Graph / SendGrid / Gmail)
```

### 4.2 Logische Komponenten

| Komponente | Verantwortung | Deployment |
|---|---|---|
| **api-server** | REST- und SMTP-Endpoints, Auth, Policy-Evaluation, Upstream-Send | Deployment, horizontal skalierbar |
| **controller** | Reconciliation von `MailBackend`/`ClusterMailBackend` und `MailPolicy`, Status-Updates, ValidatingWebhook, periodische Backend-Probes | Deployment mit Leader-Election, 1–3 Replicas |
| **rate-limit-backend** | State für Sliding-Window-Counter | Deployment (Redis) **oder** In-Memory (Single-Replica-Modus) |

**Hinweis:** `api-server` und `controller` können als ein Binary ausgeliefert werden mit unterschiedlichen Startmodi (`--mode=api`, `--mode=controller`). Reduziert Artifact-Management.

### 4.3 Custom Resource Definitionen

#### 4.3.1 MailBackend / ClusterMailBackend

`MailBackend` (namespace-scoped) und `ClusterMailBackend` (cluster-scoped) repräsentieren ein konkretes Mail-System, an das Sigillum Nachrichten weiterleitet (Send) und aus dem es perspektivisch Nachrichten liest (Read, future). Das Pattern folgt cert-manager mit `Issuer`/`ClusterIssuer`.

Die Trennung:
- **`ClusterMailBackend`:** Zentraler, von der Plattform bereitgestellter Backend (z. B. Corporate-SMTP). Referenzierbar aus allen Namespaces.
- **`MailBackend`:** Team-eigener Backend im Namespace des Teams (z. B. eigener SendGrid-Account). Referenziert Secrets im gleichen Namespace.

Die Spec ist eine **diskriminierte Union**: `spec.type` bestimmt, welches Backend-spezifische Feld ausgewertet wird. In v1 wird nur `type: smtp` implementiert; die restlichen Typen sind architektonisch vorgesehen, werden aber in späteren Phasen geliefert.

```yaml
apiVersion: sigillum.dev/v1alpha1
kind: ClusterMailBackend
metadata:
  name: corporate-smtp
spec:
  type: smtp                     # enum: smtp | microsoftGraph | sendgrid | gmail
  smtp:
    endpoints:                   # geordnete Failover-Liste; erste Ready wird verwendet
      - host: smtp-primary.internal.example.com
        port: 587
        tls: starttls
      - host: smtp-fallback.internal.example.com
        port: 587
        tls: starttls
    authType: PLAIN              # gilt für alle endpoints
    credentialsRef:              # gilt für alle endpoints
      name: corporate-smtp-credentials
      namespace: sigillum-system
    connectionTimeoutSeconds: 10
  healthCheck:
    enabled: true
    intervalSeconds: 60
status:
  capabilities:                  # vom Driver zur Laufzeit deklariert
    - send
  endpointStatus:                # pro Endpoint Ready/NotReady
    - host: smtp-primary.internal.example.com
      ready: true
    - host: smtp-fallback.internal.example.com
      ready: true
  conditions:
    - type: Ready                # True wenn mind. 1 Endpoint Ready
      status: "True"
      reason: AtLeastOneEndpointReady
  lastProbeTime: "2026-04-18T09:05:00Z"
```

Auch wenn v1 zunächst nur einen Endpoint pro Backend praktisch nutzen muss, ist die Listen-Struktur von Anfang an vorgesehen, damit Failover-Szenarien (z. B. Corporate-SMTP + externes Relay als Fallback) und gemischte Read/Write-Endpoints (IMAP auf einem Host, SMTP auf einem anderen) später ohne Schema-Bruch unterstützt werden können.

Secret-Struktur pro Backend-Typ wird in der Implementierungs-Dokumentation standardisiert (z. B. SMTP: Keys `username` / `password`; Graph: Key `client_secret`; SendGrid: Key `api_key`; Gmail: Key `service_account.json`).

#### 4.3.2 MailPolicy (namespace-scoped)

```yaml
apiVersion: sigillum.dev/v1alpha1
kind: MailPolicy
metadata:
  name: billing-service-policy
  namespace: billing
spec:
  priority: 100              # höher = spezifischer; Tie-Break: Name alphabetisch
  subjects:
    - serviceAccount:
        name: billing-mailer
    - serviceAccountSelector:
        matchLabels:
          app.kubernetes.io/component: notifier
  backendRef:
    name: corporate-smtp
    kind: ClusterMailBackend   # oder MailBackend (namespace-scoped)
  senderRestrictions:
    allowedSenders:
      - billing@example.com
      - "*@billing.noreply.example.com"
  recipientRestrictions:
    allowedDomains:
      - example.com
      - customer.example.com
    blockedDomains: []
  rateLimits:
    messagesPerMinute: 60
    messagesPerHour: 1000
  messageLimits:
    maxSizeBytes: 10485760   # 10 MiB
    maxRecipients: 50
  legacyAuth:
    podIPFallback: false     # optional; wenn true, ist Pod-IP-Auth als Fallback zulässig
status:
  conditions:
    - type: Ready
      status: "True"
  matchedSubjects: 2
```

#### 4.3.3 (Optional, v1) MailQuota (namespace-scoped)

Namespace-weites Kontingent, unabhängig von einzelnen Policies:

```yaml
apiVersion: sigillum.dev/v1alpha1
kind: MailQuota
metadata:
  name: default
  namespace: billing
spec:
  messagesPerDay: 10000
```

### 4.4 REST-API-Spezifikation (v1)

**Base-Path:** `/v1`
**Content-Type:** `application/json`
**Auth:** `Authorization: Bearer <ServiceAccount-Token>` mit Audience `sigillum`

#### 4.4.1 POST /v1/messages

Request:
```json
{
  "from": "billing@example.com",
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
      "contentBase64": "JVBERi0xLjQK..."
    }
  ],
  "headers": {
    "X-Correlation-ID": "abc-123"
  }
}
```

Response `202 Accepted`:
```json
{
  "messageId": "8f2e...",
  "policyMatched": "billing-service-policy",
  "acceptedAt": "2026-04-18T09:10:00Z"
}
```

Error-Responses folgen RFC 7807:
```json
{
  "type": "https://sigillum.dev/errors/sender-not-allowed",
  "title": "Sender address not allowed by policy",
  "status": 403,
  "detail": "Sender 'evil@example.com' not in allowedSenders of policy 'billing-service-policy'",
  "policy": "billing-service-policy",
  "messageId": "8f2e..."
}
```

#### 4.4.2 GET /v1/policies/preflight

Ermöglicht Dry-Run-Validierung, bevor eine Mail tatsächlich gesendet wird:
- Request: identisch zu `/v1/messages`
- Response: würde-akzeptiert/würde-abgelehnt mit Begründung, ohne Upstream-Aufruf
- Nutzen: Debug-Tool für Entwickler

### 4.5 Backend-Driver und Capability-Modell

**Driver-Interface.** Intern implementiert Sigillum jedes Backend als Driver, der ein gemeinsames Go-Interface erfüllt. Das Interface ist von Anfang an für Send *und* Read ausgelegt, auch wenn v1 nur Send nutzt:

```go
type Driver interface {
    // Metadaten
    Type() BackendType               // smtp | microsoftGraph | ...
    Capabilities() []Capability      // send, read, subscribeEvents, folders, ...
    HealthCheck(ctx context.Context) error

    // Send-Pfad (v1)
    Send(ctx context.Context, msg *Message) (*SendResult, error)

    // Read-Pfad (future, optional je nach Capability)
    // Read(ctx context.Context, req *ReadRequest) (*ReadResult, error)
    // Subscribe(ctx context.Context, req *SubscribeRequest) (<-chan *Event, error)
}
```

Neue Backend-Typen werden durch neue Driver-Implementierungen hinzugefügt. v1 liefert ausschließlich einen SMTP-Driver, aber das Interface und die Registry sind so geschnitten, dass Graph-/SendGrid-/Gmail-Driver ohne API-Group-Migration eingehängt werden können.

**Capability-Matrix** (Zielbild, v1 nur erste Zeile umgesetzt):

| Backend-Typ       | send | read | subscribeEvents  | folders |
|-------------------|------|------|------------------|---------|
| `smtp`            |  ✓   |  ✗   |  ✗               |  ✗      |
| `microsoftGraph`  |  ✓   |  ✓   |  ✓               |  ✓      |
| `gmail`           |  ✓   |  ✓   |  ✓ (via Pub/Sub) |  ✓      |
| `sendgrid`        |  ✓   |  ✗   |  ✓ (Bounce-Webhook) |  ✗   |
| `imap` (future)   |  ✗   |  ✓   |  ✓ (IDLE)        |  ✓      |

**Capability-Propagation:**
- Der Driver meldet seine Capabilities an den Controller, der sie in `Backend.status.capabilities` schreibt.
- Die REST-API exponiert unter `GET /v1/capabilities` die für den authentifizierten Caller verfügbaren Capabilities (berechnet aus den matchenden Policies und deren referenzierten Backends).
- Requests gegen nicht-unterstützte Capabilities werden mit `501 Not Implemented` und klarer Fehlerreferenz abgelehnt.

### 4.6 SMTP-Proxy-Verhalten

- Listener auf TCP 587 (Submission).
- Keine SMTP-AUTH-Mechanismen ausgehandelt (analog kube-mail); Identifikation per Pod-IP → Pod → ServiceAccount.
- Pod-Lookup via Kubernetes API (mit Cache).
- Sonst identische Policy-Logik wie REST-Pfad.
- STARTTLS optional; empfohlener Modus bei Mesh-Nutzung: ohne TLS (Mesh übernimmt).

### 4.7 State-Management

- **Stateless Core:** api-server hält keinen persistenten Zustand.
- **Rate-Limit-State:** Pluggable Backend — Redis für HA, In-Memory nur für Single-Replica-Dev.
- **Cache:** K8s-Informer-Caches (controller-runtime Standard) für CRDs, Secrets, Pods.
- **Kein Mail-Queue:** Bei Upstream-Fehler wird `502` zurückgegeben; Retry-Verantwortung liegt beim Caller. (Retry-Queue ist optional für v2.)

### 4.8 Auth-Flow (REST)

```
App-Pod → HTTPS POST /v1/messages, Bearer <token>
         │
         ▼
api-server extrahiert Token
         │
         ▼
TokenReview-Call an kube-apiserver (audience: Sigillum)
         │
         ▼
Response: authenticated=true, username=system:serviceaccount:billing:billing-mailer
         │
         ▼
Policy-Engine sucht MailPolicy im Namespace 'billing', die SA 'billing-mailer' matcht
         │
         ▼
Rate-Limit-Check (Redis INCR + EXPIRE)
         │
         ▼
Sender-/Recipient-/Size-Check
         │
         ▼
Backend-Send (MailBackend/ClusterMailBackend + credentialsRef-Secret)
         │
         ▼
202 Accepted
```

---

## 5. Nicht-funktionale Anforderungen

### 5.1 Performance

| Metrik | Zielwert |
|---|---|
| REST-Latenz p50 (ohne Upstream-Send) | < 30 ms |
| REST-Latenz p99 (ohne Upstream-Send) | < 150 ms |
| Durchsatz pro Pod (CPU-Request 500m) | ≥ 200 Mails/s |
| TokenReview-Cache-Hit-Rate | ≥ 95 % (TTL: 5 min) |

### 5.2 Verfügbarkeit

- **SLO:** 99.9 % Verfügbarkeit der REST-API.
- **Redundanz:** Mindestens 2 api-server-Replicas in Produktion; PDB `minAvailable: 1`.
- **Topologie:** TopologySpreadConstraints über Zonen, falls Cluster multi-zone.

### 5.3 Sicherheit

| Anforderung | Umsetzung |
|---|---|
| TLS-Terminierung | Via Istio-mTLS oder Gateway-TLS vorgelagert; interne Kommunikation mTLS |
| Secret-Handling | Upstream-Credentials ausschließlich als K8s-Secrets; niemals in CRs inline |
| Secret-Namespace-Isolation | `credentialsRef` referenziert Secrets im Sigillum-System-Namespace |
| Log-Hygiene | Keine Tokens, keine Passwörter, keine Mail-Bodies in Logs |
| Token-Audience-Binding | `TokenReview` mit `audiences: [sigillum]` für REST, SMTP-SASL und (future) IMAP-SASL — einheitlich, um Token-Missbrauch zu verhindern |
| Pod Security Standard | Kompatibel mit `restricted` |
| SBOM / Signierung | SBOM (SPDX) im Release; Cosign-Signatur für Container-Images |
| Dependency Scanning | Trivy/Grype in CI |

### 5.4 Skalierbarkeit

- **Horizontal Scaling:** Stateless api-server skaliert via HPA (CPU- oder Request-Rate-basiert).
- **Rate-Limit-Backend:** Redis-Cluster-Support oder einzelner Redis-Sentinel-Modus.
- **Cluster-Größe:** Designziel bis 10.000 MailPolicies und 100 Backends (MailBackend + ClusterMailBackend) pro Cluster.

### 5.5 Observability

- Metriken gemäß US-4.1.
- Logs gemäß US-4.2 und US-4.3.
- Traces gemäß US-4.4.
- Dashboard-Templates (Grafana-JSON) im Helm-Chart beigelegt.

### 5.6 Compliance

- **Audit-Log-Retention:** Sicherzustellen durch Log-Aggregation außerhalb Sigillum; eigenes Format ist fix dokumentiert.
- **BSI-Relevanz:** Einsatz als Wirksamkeitsnachweis-Komponente für Zugriffssteuerung auf Mailversand (§31 BSIG) möglich.
- **DSGVO:** Keine Persistierung personenbezogener Daten außerhalb transienter Audit-Logs.

### 5.7 Betreibbarkeit

- Installation per Helm unter 5 Minuten.
- Konfiguration vollständig GitOps-fähig.
- Rolling-Upgrade ohne Mail-Verlust durch Graceful Shutdown (US-5.3).
- Dokumentierte Runbooks für: Upstream-Ausfall, Rate-Limit-Backend-Ausfall, CRD-Migration.

### 5.8 Wartbarkeit

- Go-Codebase gemäß Kubernetes Code Conventions.
- Unit-Test-Coverage ≥ 70 %.
- E2E-Tests gegen Kind-Cluster (GitHub Actions).
- Semver-Versionierung; API-Gruppe `sigillum.dev/v1alpha1` → `v1beta1` → `v1`.

### 5.9 Erweiterbarkeit

- **Backend-Driver-Interface** ist öffentliches, stabiles Go-Interface; neue Backends sind additiv ohne CRD-Schema-Bruch.
- **API-Versionierung** erlaubt additive Endpoints (z. B. `/v1/mailboxes`) ohne Breaking Changes an bestehenden `/v1/messages`.
- **Kein leakender Backend-Typ in der REST-API:** Das REST-Interface (`POST /v1/messages`) ist protokoll-agnostisch — Entwickler merken nicht, ob SMTP, Graph oder SendGrid hinten dran hängt, abgesehen von Backend-spezifischen Fehlersituationen.
- **Protokoll-Adapter** (SMTP-Proxy, später IMAP-Proxy) sind separate, optional aktivierbare Komponenten.
- **Capability-Advertising** vermeidet schweigende Funktionsverluste: Nicht unterstützte Operationen werden mit `501 Not Implemented` beantwortet und in `GET /v1/capabilities` vorab sichtbar gemacht.

---

## 6. Technologie-Entscheidungen

| Bereich | Entscheidung | Begründung |
|---|---|---|
| Sprache | Go 1.22+ | Ökosystem, kubebuilder, Performance |
| Framework | controller-runtime / kubebuilder | De-facto-Standard für Operators |
| REST-Framework | chi oder net/http mit Std-Lib | Schlank, low-dependency |
| SMTP-Library | emersion/go-smtp + emersion/go-sasl | RFC-konform inkl. OAUTHBEARER (RFC 7628) |
| Rate-Limit-Backend | Redis mit Sliding-Window-Algorithmus | Horizontale Skalierung, geringer Footprint |
| Secret-Validation | Kubernetes ValidatingAdmissionWebhook | CRD-Konsistenz bereits bei Apply |
| Logging | log/slog (Go-Stdlib) | Strukturiert, Stdlib |
| Metriken | prometheus/client_golang | Standard |
| Tracing | OpenTelemetry-Go | Vendor-neutral |
| Container-Base | distroless/static | Minimal, keine Shell |
| Build | ko oder buildah | Reproduzierbar |
| Release | GoReleaser | Multi-Arch, SBOM, Signierung |
| Chart-Repository | OCI-Registry (intern) | GitOps-kompatibel |
| Backend-Driver | In-Process Go-Interface (v1); gRPC-Plugin als Option (v2+) | Einfach in v1, Crossplane-Pattern als Evolutionspfad |

---

## 7. Abgrenzungen

Siehe auch 1.4 (dauerhafte Nicht-Ziele) und 1.5 (future-vorgesehen, aber nicht v1). Zusätzlich zu den dort genannten Punkten:

- **Kein Replacement für Anti-Spam-Gateways:** Sigillum führt keine Content-Filter oder Spam-Checks durch.
- **Keine Bounce-Verarbeitung in v1:** Rückläufer werden vom Backend verarbeitet. API-basierte Backends (SendGrid, Graph) können Bounces per Webhook liefern — die Verarbeitung ist für v1.2+ vorgesehen.
- **Kein Delayed-Delivery:** Mails werden synchron an das Backend gegeben; keine Queue für zeitversetzten Versand.

---

## 8. Roadmap und MVP-Scope

### 8.1 MVP (v0.1.0)

Liefert den Kern-Use-Case „Developer sendet per REST, Policy wird durchgesetzt":

- REST-API `/v1/messages` inklusive Attachments
- ServiceAccount-Token-Auth (TokenReview)
- CRDs `MailBackend`, `ClusterMailBackend` und `MailPolicy` (nur `type: smtp` implementiert)
- Rate-Limiting (In-Memory, Single-Replica-fähig)
- Sender-Restriktionen
- Prometheus-Metriken (Basis-Set)
- Strukturierte Logs
- Helm-Chart
- ValidatingWebhook für CRDs
- Controller mit Backend-HealthCheck

### 8.2 v0.2.0

- SMTP-Proxy
- Redis-basiertes Rate-Limit-Backend für HA
- Audit-Log-Stream
- Empfänger-Restriktionen
- OpenTelemetry-Tracing

### 8.3 v0.3.0

- Istio-mTLS-Auth (SPIFFE)
- `MailQuota` (Namespace-weit)
- Preflight-Endpoint
- Grafana-Dashboards
- Dokumentierte Runbooks

### 8.4 v1.0.0 (Produktionsreife)

- API-Promotion `v1alpha1` → `v1beta1` → `v1`
- Dokumentation vollständig
- E2E-Testsuite vollständig
- Chaos-Tests
- SBOM + Image-Signierung in Release-Pipeline

### 8.5 v1.1+ (Backend-Expansion, future)

- **v1.1:** Microsoft Graph als Send-Backend (`type: microsoftGraph`)
- **v1.2:** SendGrid als Send-Backend + Webhook-Receiver für Bounces
- **v1.3:** Gmail API als Send-Backend

### 8.6 v2.0 (Read-Path, future)

- `MailboxBinding`-CRD für Read-Zugriff auf Backends
- `GET /v1/mailboxes/{name}/messages` REST-Endpoints
- Webhook-Push für Events (eingehende Mails, Bounces)
- IMAP-Proxy für Legacy-Reader (optional aktivierbar)
- Driver-Implementierungen von `Read()` und `Subscribe()` für Graph, Gmail, IMAP

---

## 9. Risiken und offene Fragen

### 9.1 Risiken

| Risiko | Mitigation |
|---|---|
| TokenReview-Last auf kube-apiserver | Caching mit TTL; projected Tokens mit Audience-Binding |
| Redis-Single-Point-of-Failure | Redis-Sentinel/Cluster; Fallback auf strict-Mode (deny on Redis-down) |
| Pod-IP-Ambiguität bei SMTP-Legacy-Auth | SASL OAUTHBEARER ist Default; Pod-IP-Auth nur opt-in pro Policy; `UsingLegacyAuth` Status macht Restbestände sichtbar |
| Abhängigkeit von Upstream-SMTP-Verfügbarkeit | HealthCheck + klare Fehler-Semantik (502 retry-fähig) |
| Policy-Komplexität (unklare Matches) | Preflight-Endpoint, dry-run-Flag, Priority-Feld für Deterministik |
| Fehlende Mail-Queue → Verlustrisiko bei Upstream-Ausfall | Dokumentiert als Caller-Verantwortung; Retry-Queue optional v2 |

### 9.2 Offene Fragen

1. **Name:** Ist „Sigillum" final oder ist ein interner Name gewünscht?
1. **API-Group-Prefix:** `sigillum.dev` vs. internes Firmen-Suffix?
2. **Multi-Cluster-Support:** Ist Federation mehrerer Cluster ein Zielbild?
3. **Retry-Queue:** Braucht v1 bereits einen persistenten Retry-Mechanismus?
4. **Bounce-Handling:** Soll v2 einen eingehenden Bounce-Endpoint haben?
5. **Backend-Pool:** Soll ein `MailBackend` mehrere Server/Endpoints als Failover-Gruppe definieren können (z. B. primärer SMTP + Fallback-SMTP)?

---

## 10. Glossar

| Begriff | Bedeutung |
|---|---|
| **CRD** | Custom Resource Definition — Kubernetes-eigene Erweiterung der API |
| **TokenReview** | Kubernetes-API, die Bearer-Tokens validiert |
| **SPIFFE** | Secure Production Identity Framework for Everyone — Standard für Workload-Identität |
| **Backend** | Mail-System hinter Sigillum, an das Mails weitergeleitet werden und aus dem (future) gelesen wird. Kann SMTP, Graph, Gmail oder SendGrid sein. |
| **Driver** | Interne Go-Implementierung, die ein konkretes Backend-Protokoll kapselt und das `Driver`-Interface erfüllt. |
| **Capability** | Deklarierte Fähigkeit eines Backends/Drivers (z. B. `send`, `read`, `subscribeEvents`, `folders`). |
| **Policy Subject** | Aufrufer-Identität (SA, Pod), auf die eine Policy matcht |
| **Preflight** | Dry-Run-Validierung einer Mail ohne tatsächliche Zustellung |

---

## 11. Referenzen

- [kube-mail (Referenz-Projekt, abandoned)](https://github.com/martin-helmich/kube-mail)
- [Kubernetes TokenRequest API](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens)
- [RFC 7807 — Problem Details for HTTP APIs](https://datatracker.ietf.org/doc/html/rfc7807)
- [SPIFFE Specification](https://github.com/spiffe/spiffe)
- [OpenTelemetry Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/)

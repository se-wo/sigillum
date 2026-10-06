// Package gateway is the transport-agnostic send pipeline shared by the REST
// api-server and the SMTP proxy:
//
//	policy match -> policy evaluate -> rate limit -> backend resolve -> send
//
// Every call to Send produces exactly one audit record, one operational log
// line and the matching Prometheus metrics. Transports only parse their wire
// format and map Result onto their own status codes.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/audit"
	"github.com/se-wo/sigillum/internal/controller"
	"github.com/se-wo/sigillum/internal/driver"
	// The gateway builds drivers through the registry, and the backend
	// validity check accepts only registered types; register them here
	// rather than rely on a transport importing them.
	_ "github.com/se-wo/sigillum/internal/driver/graph"
	_ "github.com/se-wo/sigillum/internal/driver/smtp"
	"github.com/se-wo/sigillum/internal/policy"
	"github.com/se-wo/sigillum/internal/policy/ratelimit"
	"github.com/se-wo/sigillum/internal/telemetry"
	"github.com/se-wo/sigillum/internal/webhook"
)

// Auth methods, as logged in the authMethod field (US-4.2).
const (
	AuthOAuthBearer    = "oauth_bearer"
	AuthPodIPLegacy    = "pod_ip_legacy"
	AuthSMTPCredential = "smtp_credential"
)

// Transports, as recorded in the audit stream.
const (
	TransportREST = "rest"
	TransportSMTP = "smtp"
)

// PolicyStore is the read-side abstraction used to fetch policies on the hot
// path. Backed by a controller-runtime informer cache in production.
type PolicyStore interface {
	ListInNamespace(namespace string) []sigv1.MailPolicy
}

// CachedPolicyStore lists policies through a controller-runtime reader.
type CachedPolicyStore struct {
	C client.Reader
}

// ListInNamespace implements PolicyStore.
func (s CachedPolicyStore) ListInNamespace(namespace string) []sigv1.MailPolicy {
	var list sigv1.MailPolicyList
	if err := s.C.List(context.Background(), &list, client.InNamespace(namespace)); err != nil {
		return nil
	}
	return list.Items
}

// Identity is the authenticated caller.
type Identity struct {
	Namespace      string
	ServiceAccount string
	AuthMethod     string
	// PodLabels is set only for pod-IP legacy auth, where the pod is known.
	PodLabels map[string]string
	// Credential is the MailCredential username (smtp_credential only), and
	// CredentialPrevious marks a login with the previous password during a
	// rotation's grace period.
	Credential         string
	CredentialPrevious bool
}

// Request is one message to push through the pipeline.
type Request struct {
	Identity  Identity
	Transport string
	// MessageID is the Sigillum-assigned ID (also used as the RFC 5322
	// Message-ID local part).
	MessageID string
	// Message drives policy evaluation. On the REST path it is also what the
	// driver assembles and sends.
	Message *driver.Message
	// Raw, when set, is relayed verbatim instead of assembling Message
	// (SMTP path). Message.To then holds the envelope recipients.
	Raw []byte
	// EnvelopeFrom is the SMTP MAIL FROM address (Raw only).
	EnvelopeFrom string
	// Sender and ReplyTo are the addresses of the Sender and Reply-To
	// headers, checked against the policy like From and the recipients.
	Sender    string
	ReplyTo   []string
	SizeBytes int64
}

// Status classifies a Result so transports can pick a status code.
type Status int

const (
	StatusAccepted Status = iota
	StatusDenied
	StatusRateLimited
	StatusBackendNotReady
	StatusUpstreamError
	// StatusUnavailable: a Sigillum dependency (e.g. the Redis rate-limit
	// store) is down. Retryable; not the caller's fault.
	StatusUnavailable
	// StatusPolicyInvalid: the matching policy breaks the admission rules
	// (admitted without the webhook, or by an older version). Not the
	// caller's fault; retryable once the policy is fixed.
	StatusPolicyInvalid
)

// Result is the outcome of Send.
type Result struct {
	Status     Status
	Policy     string
	Backend    string
	DenyReason policy.DenyReason // StatusDenied only
	Detail     string
	RetryAfter time.Duration // StatusRateLimited only
	// Permanent marks an upstream rejection that will not succeed on retry
	// (StatusUpstreamError only). SMTP maps it to 5xx instead of 4xx, REST
	// to 422 upstream-rejected instead of 502 upstream-error.
	Permanent  bool
	UpstreamID string
	AcceptedAt time.Time
}

// Gateway holds the dependencies of the send pipeline.
type Gateway struct {
	Logger   *slog.Logger
	Audit    audit.Logger
	Policies PolicyStore
	// Reader resolves ServiceAccounts, backends and credential Secrets.
	Reader  client.Reader
	Limiter ratelimit.Limiter
	// NewDriver builds a driver from a resolved backend config; defaults to
	// driver.New. Overridable in tests.
	NewDriver func(driver.Config) (driver.Driver, error)

	validity validityCache
}

// Send runs one message through the pipeline.
func (g *Gateway) Send(ctx context.Context, req Request) Result {
	id := req.Identity
	logger := g.Logger.With(
		"message_id", req.MessageID,
		"namespace", id.Namespace,
		"service_account", id.ServiceAccount,
		"authMethod", id.AuthMethod,
		"transport", req.Transport,
	)
	if id.Credential != "" {
		logger = logger.With("credential", id.Credential)
		if id.CredentialPrevious {
			logger = logger.With("credential_previous", true)
		}
	}
	if tid := telemetry.TraceID(ctx); tid != "" {
		logger = logger.With("trace_id", tid)
	}
	view := policy.MessageView{
		From:         req.Message.From.Address,
		EnvelopeFrom: req.EnvelopeFrom,
		Sender:       req.Sender,
		Recipients:   Recipients(req.Message),
		ReplyTo:      req.ReplyTo,
		SizeBytes:    req.SizeBytes,
	}
	ev := audit.Event{
		MessageID:          req.MessageID,
		Namespace:          id.Namespace,
		ServiceAccount:     id.ServiceAccount,
		AuthMethod:         id.AuthMethod,
		Credential:         id.Credential,
		CredentialPrevious: id.CredentialPrevious,
		Transport:          req.Transport,
		From:               view.From,
		To:                 view.Recipients,
	}

	evalCtx, evalSpan := telemetry.Tracer().Start(ctx, "policy.evaluate", trace.WithAttributes(
		attribute.String("sigillum.namespace", id.Namespace),
		attribute.String("sigillum.service_account", id.ServiceAccount),
		attribute.String("sigillum.auth_method", id.AuthMethod),
		attribute.Int("sigillum.recipients", len(view.Recipients)),
	))
	policies := g.Policies.ListInNamespace(id.Namespace)
	caller := policy.Caller{
		Namespace:      id.Namespace,
		ServiceAccount: id.ServiceAccount,
		PodLabels:      id.PodLabels,
		LegacyPodIP:    id.AuthMethod == AuthPodIPLegacy,
	}
	if policy.NeedsSALabels(policies) {
		caller.SALabels, caller.SALabelsKnown = g.serviceAccountLabels(evalCtx, id.Namespace, id.ServiceAccount)
	}
	matched := policy.Match(policies, caller)
	// A policy the webhook would reject is refused, not enforced with
	// whatever its malformed entries happen to match ("*" in
	// allowedRecipients would allow everyone). The controller reports the
	// reason in its Ready condition.
	if matched != nil {
		if verr := g.validity.check(matched, func() error { return webhook.ValidateMailPolicy(matched) }); verr != nil {
			evalSpan.SetAttributes(attribute.String("sigillum.policy", matched.Name),
				attribute.Bool("sigillum.allowed", false), attribute.String("sigillum.deny_reason", "policy_invalid"))
			evalSpan.End()
			telemetry.PolicyDeniedTotal.WithLabelValues(id.Namespace, matched.Name, "policy_invalid").Inc()
			logger.Warn("policy invalid", "policy", matched.Name, "err", verr)
			ev.Policy, ev.Decision, ev.Reason = matched.Name, audit.DecisionReject, "policy_invalid"
			g.Audit.Record(ev)
			return Result{Status: StatusPolicyInvalid, Policy: matched.Name,
				Detail: fmt.Sprintf("MailPolicy %q is invalid; its Ready condition names the problem", matched.Name)}
		}
	}
	decision := policy.Evaluate(matched, view)
	evalSpan.SetAttributes(attribute.String("sigillum.policy", nameOf(decision.Policy)),
		attribute.Bool("sigillum.allowed", decision.Allowed))
	if !decision.Allowed {
		evalSpan.SetAttributes(attribute.String("sigillum.deny_reason", string(decision.DenyReason)))
	}
	evalSpan.End()
	// deny records a refusal by the policy or, with a backend, by the
	// backend's allowedSenders. Result.Backend stays empty for a policy's
	// refusal; the REST reply tells the two apart by it.
	deny := func(policyName string, reason policy.DenyReason, detail, backend string, logAttrs ...any) Result {
		telemetry.PolicyDeniedTotal.WithLabelValues(id.Namespace, policyName, string(reason)).Inc()
		logger.Info("request denied", append([]any{"result", "denied", "reason", string(reason), "policy", policyName}, logAttrs...)...)
		ev.Policy, ev.Backend, ev.Decision, ev.Reason = policyName, backend, audit.DecisionReject, string(reason)
		g.Audit.Record(ev)
		return Result{Status: StatusDenied, Policy: policyName, Backend: backend, DenyReason: reason, Detail: detail}
	}
	if !decision.Allowed {
		return deny(nameOf(decision.Policy), decision.DenyReason, decision.DenyDetail, "")
	}
	p := decision.Policy
	ev.Policy = p.Name

	// Resolve the backend before charging the rate limit, so an unavailable
	// backend does not use up the budget of messages that were never sent.
	notReady := func(err error) Result {
		telemetry.PolicyDeniedTotal.WithLabelValues(p.Namespace, p.Name, "backend_not_ready").Inc()
		logger.Warn("backend not ready", "policy", p.Name, "err", err)
		ev.Decision, ev.Reason = audit.DecisionReject, "backend_not_ready"
		g.Audit.Record(ev)
		return Result{Status: StatusBackendNotReady, Policy: p.Name, Detail: err.Error()}
	}
	backendKey, spec, status, secretNs, err := g.backendForPolicy(ctx, p)
	if err != nil {
		return notReady(err)
	}
	ev.Backend = backendKey

	// The backend bounds the senders of every policy that uses it (US-2.8);
	// a policy can narrow that list but never widen it. nil: no bound.
	// Checked before the credentials are resolved, so a refused sender gets
	// a permanent 403 even while the credentials Secret is broken.
	if spec.AllowedSenders != nil {
		if from, ok := policy.SendersAllowed(view, spec.AllowedSenders); !ok {
			return deny(p.Name, policy.DenySenderNotAllowed,
				"sender '"+from+"' not in the backend's allowedSenders", backendKey,
				"backend", backendKey, "restriction", "backend")
		}
	}

	d, err := g.openDriver(ctx, backendKey, spec, status, secretNs)
	if err != nil {
		return notReady(err)
	}
	defer d.Close()

	rlKey := p.Namespace + "/" + p.Name
	charged := false
	var limits ratelimit.Limits
	if rl := p.Spec.RateLimits; rl != nil {
		limits = ratelimit.Limits{PerMinute: rl.MessagesPerMinute, PerHour: rl.MessagesPerHour, PerDay: rl.MessagesPerDay}
	}
	if !limits.None() {
		rlCtx, rlSpan := telemetry.Tracer().Start(ctx, "ratelimit.allow")
		ok, retry, err := g.Limiter.Allow(rlCtx, rlKey, limits)
		rlSpan.SetAttributes(attribute.Bool("sigillum.allowed", ok))
		if err != nil {
			rlSpan.SetStatus(codes.Error, err.Error())
		}
		rlSpan.End()
		if err != nil {
			logger.Error("rate limiter unavailable", "policy", p.Name, "err", err)
			ev.Decision, ev.Reason = audit.DecisionReject, "ratelimit_unavailable"
			g.Audit.Record(ev)
			return Result{Status: StatusUnavailable, Policy: p.Name, Detail: "rate limiter unavailable; retry later"}
		}
		if !ok {
			telemetry.RatelimitRejectedTotal.WithLabelValues(p.Namespace, p.Name).Inc()
			logger.Info("request rejected", "result", "ratelimited", "policy", p.Name)
			ev.Decision, ev.Reason = audit.DecisionReject, "rate_limited"
			g.Audit.Record(ev)
			return Result{Status: StatusRateLimited, Policy: p.Name, RetryAfter: retry,
				Detail: "policy '" + p.Name + "' rate limit exceeded"}
		}
		charged = true
	}

	sendCtx, sendSpan := telemetry.Tracer().Start(ctx, "backend.send", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("sigillum.backend", backendKey), attribute.String("sigillum.policy", p.Name)))
	start := time.Now()
	var res *driver.SendResult
	if req.Raw != nil {
		rs, ok := d.(driver.RawSender)
		if !ok {
			err = fmt.Errorf("%w: backend %s cannot relay raw messages", driver.ErrUpstreamPermanent, backendKey)
		} else {
			res, err = rs.SendRaw(sendCtx, req.EnvelopeFrom, view.Recipients, req.Raw)
		}
	} else {
		res, err = d.Send(sendCtx, req.Message)
	}
	dur := time.Since(start).Seconds()
	if err != nil {
		sendSpan.SetStatus(codes.Error, err.Error())
	}
	sendSpan.End()

	if err != nil && errors.Is(err, driver.ErrRecipientNotInEnvelope) {
		// An API backend delivers to the header recipients; one the policy
		// never checked as an envelope recipient is a policy refusal
		// (SPEC US-6.1), not an upstream failure. Nothing was sent.
		if charged {
			if rerr := g.Limiter.Refund(ctx, rlKey); rerr != nil {
				logger.Warn("rate limit refund failed", "policy", p.Name, "err", rerr)
			}
		}
		detail := strings.TrimPrefix(err.Error(), driver.ErrUpstreamPermanent.Error()+": ")
		return deny(p.Name, policy.DenyRecipientBlocked, detail, backendKey,
			"backend", backendKey, "restriction", "headers")
	}
	if err != nil {
		// A permanent rejection (5xx to MAIL, RCPT or DATA) and a transient
		// failure get different reasons, so SIEM rules and dashboards can
		// tell "fix the message" from "the relay is down" (G-1).
		permanent := errors.Is(err, driver.ErrUpstreamPermanent)
		resultLabel := "upstream_error"
		if permanent {
			resultLabel = "upstream_rejected"
		}
		telemetry.BackendDurationSeconds.WithLabelValues(p.Namespace, p.Name, backendKey, resultLabel).Observe(dur)
		telemetry.MessagesTotal.WithLabelValues(p.Namespace, p.Name, backendKey, resultLabel).Inc()
		logger.Error("upstream send failed", "policy", p.Name, "backend", backendKey, "err", err, "result", resultLabel)
		ev.Decision, ev.Reason = audit.DecisionReject, resultLabel
		g.Audit.Record(ev)
		// A transient failure will be retried by the caller (SMTP clients do
		// so automatically on 4xx); give the hit back so retries through an
		// outage do not exhaust the budget. A permanent rejection was a real
		// attempt and stays charged.
		if charged && !permanent {
			if rerr := g.Limiter.Refund(ctx, rlKey); rerr != nil {
				logger.Warn("rate limit refund failed", "policy", p.Name, "err", rerr)
			}
		}
		return Result{Status: StatusUpstreamError, Policy: p.Name, Backend: backendKey, Detail: err.Error(),
			Permanent: permanent}
	}
	const resultLabel = "ok"
	telemetry.BackendDurationSeconds.WithLabelValues(p.Namespace, p.Name, backendKey, resultLabel).Observe(dur)
	telemetry.MessagesTotal.WithLabelValues(p.Namespace, p.Name, backendKey, resultLabel).Inc()
	telemetry.MessageSizeBytes.WithLabelValues(p.Namespace, p.Name, backendKey).Observe(float64(view.SizeBytes))
	logger.Info("message accepted", "policy", p.Name, "backend", backendKey,
		"upstream_id", res.UpstreamID, "result", resultLabel)
	ev.Decision = audit.DecisionAccept
	g.Audit.Record(ev)
	return Result{Status: StatusAccepted, Policy: p.Name, Backend: backendKey,
		UpstreamID: res.UpstreamID, AcceptedAt: res.AcceptedAt}
}

// Reject records a request that was refused before it reached the pipeline
// (authentication failure, malformed payload). Identity and addresses are
// whatever the transport managed to establish; empty fields are omitted.
func (g *Gateway) Reject(ev audit.Event, reason string) {
	ev.Decision, ev.Reason = audit.DecisionReject, reason
	g.Audit.Record(ev)
}

// Recipients flattens To, Cc and Bcc into bare addresses.
func Recipients(m *driver.Message) []string {
	out := make([]string, 0, len(m.To)+len(m.Cc)+len(m.Bcc))
	for _, set := range [][]driver.Address{m.To, m.Cc, m.Bcc} {
		for _, a := range set {
			out = append(out, a.Address)
		}
	}
	return out
}

// serviceAccountLabels returns the labels of the caller's ServiceAccount and
// whether the lookup succeeded. On failure selector subjects are skipped
// (fail closed) instead of failing the request.
func (g *Gateway) serviceAccountLabels(ctx context.Context, namespace, name string) (map[string]string, bool) {
	var sa corev1.ServiceAccount
	if err := g.Reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &sa); err != nil {
		g.Logger.Warn("service account lookup failed; selector subjects will not match",
			"namespace", namespace, "service_account", name, "err", err)
		return nil, false
	}
	return sa.Labels, true
}

// backendForPolicy resolves the policy's BackendRef to a Ready backend and
// returns its key, its spec and status and the namespace its credentials
// Secret defaults to. Refuses to send if the referenced backend has
// Ready=False.
func (g *Gateway) backendForPolicy(ctx context.Context, p *sigv1.MailPolicy) (string, *sigv1.BackendSpec, *sigv1.BackendStatus, string, error) {
	switch p.Spec.BackendRef.Kind {
	case sigv1.KindMailBackend:
		var mb sigv1.MailBackend
		if err := g.Reader.Get(ctx, types.NamespacedName{Namespace: p.Namespace, Name: p.Spec.BackendRef.Name}, &mb); err != nil {
			return "", nil, nil, "", fmt.Errorf("MailBackend %s/%s: %w", p.Namespace, p.Spec.BackendRef.Name, err)
		}
		// The status may predate an update that made the spec invalid.
		if verr := g.validity.check(&mb, func() error { return webhook.ValidateBackend(&mb) }); verr != nil {
			return "", nil, nil, "", fmt.Errorf("MailBackend %s/%s is invalid: %w", p.Namespace, p.Spec.BackendRef.Name, verr)
		}
		if !backendIsReady(&mb.Status) {
			return "", nil, nil, "", fmt.Errorf("MailBackend %s/%s is not Ready", p.Namespace, p.Spec.BackendRef.Name)
		}
		return p.Namespace + "/" + mb.Name, &mb.Spec, &mb.Status, mb.Namespace, nil
	case sigv1.KindClusterMailBackend, "":
		var cmb sigv1.ClusterMailBackend
		if err := g.Reader.Get(ctx, types.NamespacedName{Name: p.Spec.BackendRef.Name}, &cmb); err != nil {
			return "", nil, nil, "", fmt.Errorf("ClusterMailBackend %s: %w", p.Spec.BackendRef.Name, err)
		}
		if verr := g.validity.check(&cmb, func() error { return webhook.ValidateBackend(&cmb) }); verr != nil {
			return "", nil, nil, "", fmt.Errorf("ClusterMailBackend %s is invalid: %w", p.Spec.BackendRef.Name, verr)
		}
		if !backendIsReady(&cmb.Status) {
			return "", nil, nil, "", fmt.Errorf("ClusterMailBackend %s is not Ready", p.Spec.BackendRef.Name)
		}
		return "/" + cmb.Name, &cmb.Spec, &cmb.Status, "", nil
	default:
		return "", nil, nil, "", fmt.Errorf("unsupported backendRef.kind %q", p.Spec.BackendRef.Kind)
	}
}

// openDriver resolves a backend's credentials and builds its driver.
func (g *Gateway) openDriver(ctx context.Context, backendKey string, spec *sigv1.BackendSpec, status *sigv1.BackendStatus, secretNs string) (driver.Driver, error) {
	cfg, err := controller.ResolveBackendConfig(ctx, g.Reader, backendKey, spec, secretNs)
	if err != nil {
		return nil, err
	}
	if cfg.SMTP != nil {
		cfg.SMTP.Endpoints = preferReadyEndpoints(cfg.SMTP.Endpoints, status.EndpointStatus)
	}
	newDriver := g.NewDriver
	if newDriver == nil {
		newDriver = driver.New
	}
	return newDriver(cfg)
}

// preferReadyEndpoints moves the endpoints the last probe found unready to
// the end, keeping the declared order otherwise. The driver tries endpoints
// in order, so a stalled first endpoint would otherwise cost every message
// a connection timeout before failover. Endpoints the probe has not seen
// keep their place.
func preferReadyEndpoints(eps []driver.SMTPEndpoint, probed []sigv1.EndpointStatus) []driver.SMTPEndpoint {
	unready := map[string]bool{}
	for _, st := range probed {
		if !st.Ready {
			unready[net.JoinHostPort(st.Host, strconv.Itoa(int(st.Port)))] = true
		}
	}
	if len(unready) == 0 {
		return eps
	}
	out := make([]driver.SMTPEndpoint, 0, len(eps))
	var last []driver.SMTPEndpoint
	for _, ep := range eps {
		if unready[net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port)))] {
			last = append(last, ep)
		} else {
			out = append(out, ep)
		}
	}
	return append(out, last...)
}

func backendIsReady(s *sigv1.BackendStatus) bool {
	for _, c := range s.Conditions {
		if c.Type == sigv1.ConditionReady {
			return string(c.Status) == "True"
		}
	}
	return false
}

func nameOf(p *sigv1.MailPolicy) string {
	if p == nil {
		return ""
	}
	return p.Name
}

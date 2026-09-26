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
	"github.com/se-wo/sigillum/internal/policy"
	"github.com/se-wo/sigillum/internal/policy/ratelimit"
	"github.com/se-wo/sigillum/internal/telemetry"
)

// Auth methods, as logged in the authMethod field (US-4.2).
const (
	AuthOAuthBearer = "oauth_bearer"
	AuthPodIPLegacy = "pod_ip_legacy"
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
	SizeBytes    int64
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
	// (StatusUpstreamError only). SMTP maps it to 5xx instead of 4xx.
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
	if tid := telemetry.TraceID(ctx); tid != "" {
		logger = logger.With("trace_id", tid)
	}
	view := policy.MessageView{
		From:         req.Message.From.Address,
		EnvelopeFrom: req.EnvelopeFrom,
		Recipients:   Recipients(req.Message),
		SizeBytes:    req.SizeBytes,
	}
	ev := audit.Event{
		MessageID:      req.MessageID,
		Namespace:      id.Namespace,
		ServiceAccount: id.ServiceAccount,
		AuthMethod:     id.AuthMethod,
		Transport:      req.Transport,
		From:           view.From,
		To:             view.Recipients,
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
	decision := policy.Evaluate(policy.Match(policies, caller), view)
	evalSpan.SetAttributes(attribute.String("sigillum.policy", nameOf(decision.Policy)),
		attribute.Bool("sigillum.allowed", decision.Allowed))
	if !decision.Allowed {
		evalSpan.SetAttributes(attribute.String("sigillum.deny_reason", string(decision.DenyReason)))
	}
	evalSpan.End()
	if !decision.Allowed {
		ns, name := id.Namespace, nameOf(decision.Policy)
		telemetry.PolicyDeniedTotal.WithLabelValues(ns, name, string(decision.DenyReason)).Inc()
		logger.Info("request denied", "result", "denied", "reason", string(decision.DenyReason), "policy", name)
		ev.Policy, ev.Decision, ev.Reason = name, audit.DecisionReject, string(decision.DenyReason)
		g.Audit.Record(ev)
		return Result{Status: StatusDenied, Policy: name, DenyReason: decision.DenyReason, Detail: decision.DenyDetail}
	}
	p := decision.Policy
	ev.Policy = p.Name

	// Resolve the backend before charging the rate limit, so an unavailable
	// backend does not use up the budget of messages that were never sent.
	d, backendKey, err := g.backendForPolicy(ctx, p)
	if err != nil {
		telemetry.PolicyDeniedTotal.WithLabelValues(p.Namespace, p.Name, "backend_not_ready").Inc()
		logger.Warn("backend not ready", "policy", p.Name, "err", err)
		ev.Decision, ev.Reason = audit.DecisionReject, "backend_not_ready"
		g.Audit.Record(ev)
		return Result{Status: StatusBackendNotReady, Policy: p.Name, Detail: err.Error()}
	}
	defer d.Close()
	ev.Backend = backendKey

	rlKey := p.Namespace + "/" + p.Name
	charged := false
	if rl := p.Spec.RateLimits; rl != nil && (rl.MessagesPerMinute > 0 || rl.MessagesPerHour > 0) {
		rlCtx, rlSpan := telemetry.Tracer().Start(ctx, "ratelimit.allow")
		ok, retry, err := g.Limiter.Allow(rlCtx, rlKey, rl.MessagesPerMinute, rl.MessagesPerHour)
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

	if err != nil {
		const resultLabel = "upstream_error"
		telemetry.BackendDurationSeconds.WithLabelValues(p.Namespace, p.Name, backendKey, resultLabel).Observe(dur)
		telemetry.MessagesTotal.WithLabelValues(p.Namespace, p.Name, backendKey, resultLabel).Inc()
		logger.Error("upstream send failed", "policy", p.Name, "backend", backendKey, "err", err, "result", resultLabel)
		ev.Decision, ev.Reason = audit.DecisionReject, "upstream_error"
		g.Audit.Record(ev)
		permanent := errors.Is(err, driver.ErrUpstreamPermanent)
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

// backendForPolicy resolves the policy's BackendRef into a live driver.
// Refuses to send if the referenced backend has Ready=False.
func (g *Gateway) backendForPolicy(ctx context.Context, p *sigv1.MailPolicy) (driver.Driver, string, error) {
	newDriver := g.NewDriver
	if newDriver == nil {
		newDriver = driver.New
	}
	switch p.Spec.BackendRef.Kind {
	case sigv1.KindMailBackend:
		var mb sigv1.MailBackend
		if err := g.Reader.Get(ctx, types.NamespacedName{Namespace: p.Namespace, Name: p.Spec.BackendRef.Name}, &mb); err != nil {
			return nil, "", fmt.Errorf("MailBackend %s/%s: %w", p.Namespace, p.Spec.BackendRef.Name, err)
		}
		if !backendIsReady(&mb.Status) {
			return nil, "", fmt.Errorf("MailBackend %s/%s is not Ready", p.Namespace, p.Spec.BackendRef.Name)
		}
		cfg, err := controller.ResolveBackendConfig(ctx, g.Reader, p.Namespace+"/"+mb.Name, &mb.Spec, mb.Namespace)
		if err != nil {
			return nil, "", err
		}
		d, err := newDriver(cfg)
		return d, p.Namespace + "/" + mb.Name, err
	case sigv1.KindClusterMailBackend, "":
		var cmb sigv1.ClusterMailBackend
		if err := g.Reader.Get(ctx, types.NamespacedName{Name: p.Spec.BackendRef.Name}, &cmb); err != nil {
			return nil, "", fmt.Errorf("ClusterMailBackend %s: %w", p.Spec.BackendRef.Name, err)
		}
		if !backendIsReady(&cmb.Status) {
			return nil, "", fmt.Errorf("ClusterMailBackend %s is not Ready", p.Spec.BackendRef.Name)
		}
		cfg, err := controller.ResolveBackendConfig(ctx, g.Reader, "/"+cmb.Name, &cmb.Spec, "")
		if err != nil {
			return nil, "", err
		}
		d, err := newDriver(cfg)
		return d, "/" + cmb.Name, err
	default:
		return nil, "", fmt.Errorf("unsupported backendRef.kind %q", p.Spec.BackendRef.Kind)
	}
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

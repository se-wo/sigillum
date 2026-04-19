package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/apiserver/problem"
	"github.com/se-wo/sigillum/internal/driver"
	"github.com/se-wo/sigillum/internal/policy"
	"github.com/se-wo/sigillum/internal/telemetry"
)

// requestBody is the JSON payload accepted by POST /v1/messages.
type requestBody struct {
	From        string                 `json:"from"`
	To          []string               `json:"to,omitempty"`
	Cc          []string               `json:"cc,omitempty"`
	Bcc         []string               `json:"bcc,omitempty"`
	Subject     string                 `json:"subject,omitempty"`
	Body        requestBodyContent     `json:"body,omitempty"`
	Attachments []requestAttachment    `json:"attachments,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Extra       map[string]interface{} `json:"-"`
}

type requestBodyContent struct {
	Text string `json:"text,omitempty"`
	HTML string `json:"html,omitempty"`
}

type requestAttachment struct {
	Filename      string `json:"filename"`
	ContentType   string `json:"contentType,omitempty"`
	Disposition   string `json:"disposition,omitempty"`
	ContentBase64 string `json:"contentBase64"`
}

// responseBody is the success envelope for POST /v1/messages.
type responseBody struct {
	MessageID     string    `json:"messageId"`
	PolicyMatched string    `json:"policyMatched"`
	AcceptedAt    time.Time `json:"acceptedAt"`
}

// handleSendMessage is the hot path. It performs:
//
//	body decode -> address parse -> policy match -> rate limit ->
//	policy evaluate (sender/recipient/size) -> driver.Send -> 202.
func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	if s.shutting.Load() {
		problem.Write(w, problem.New(problem.TypeShuttingDown, http.StatusServiceUnavailable,
			"Service draining", "the api-server is terminating; retry on a different replica"))
		return
	}

	ctx := r.Context()
	subject, ok := SubjectFrom(ctx)
	if !ok {
		problem.Write(w, problem.New(problem.TypeInvalidToken, http.StatusUnauthorized,
			"Authentication required", "missing or invalid Bearer token"))
		return
	}

	maxBody := int64(32 * 1024 * 1024) // 32 MiB hard ceiling — policy enforces lower limits
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Failed to read request body", err.Error()))
		return
	}
	if int64(len(body)) > maxBody {
		problem.Write(w, problem.New(problem.TypeMessageTooLarge, http.StatusRequestEntityTooLarge,
			"Request body exceeds 32MiB ceiling", "use a smaller message or split attachments"))
		return
	}

	var req requestBody
	if err := json.Unmarshal(body, &req); err != nil {
		problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Malformed JSON payload", err.Error()))
		return
	}

	msgID := uuid.NewString()
	logger := s.logger.With(
		"message_id", msgID,
		"namespace", subject.Namespace,
		"service_account", subject.ServiceAccount,
		"authMethod", "oauth_bearer",
	)

	from, err := parseAddress(req.From)
	if err != nil {
		problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Invalid 'from' address", err.Error()))
		return
	}
	to, err := parseAddressList(req.To)
	if err != nil {
		problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Invalid 'to' address", err.Error()))
		return
	}
	cc, err := parseAddressList(req.Cc)
	if err != nil {
		problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Invalid 'cc' address", err.Error()))
		return
	}
	bcc, err := parseAddressList(req.Bcc)
	if err != nil {
		problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Invalid 'bcc' address", err.Error()))
		return
	}
	if len(to)+len(cc)+len(bcc) == 0 {
		problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"At least one recipient required", "provide one of to, cc or bcc"))
		return
	}

	atts, err := decodeAttachments(req.Attachments)
	if err != nil {
		problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Invalid attachment", err.Error()))
		return
	}

	allRecipientStrs := append(append([]string{}, addressesToStrings(to)...), addressesToStrings(cc)...)
	allRecipientStrs = append(allRecipientStrs, addressesToStrings(bcc)...)
	view := policy.MessageView{
		From:       from.Address,
		Recipients: allRecipientStrs,
		SizeBytes:  estimateSize(req, atts),
	}

	// Subject matching needs the live policy list. The store guarantees a
	// snapshot scoped to the caller's namespace so the engine sees nothing
	// outside it.
	policies := s.policyStore.ListInNamespace(subject.Namespace)
	matched := policy.Match(policies, policy.Caller{
		Namespace:      subject.Namespace,
		ServiceAccount: subject.ServiceAccount,
	})
	decision := policy.Evaluate(matched, view)
	if !decision.Allowed {
		emitDeny(logger, subject, view, decision)
		writePolicyDeny(w, msgID, decision)
		return
	}

	policyKey := decision.Policy.Namespace + "/" + decision.Policy.Name
	if rl := decision.Policy.Spec.RateLimits; rl != nil && (rl.MessagesPerMinute > 0 || rl.MessagesPerHour > 0) {
		ok, retry := s.limiter.Allow(ctx, policyKey, rl.MessagesPerMinute, rl.MessagesPerHour)
		if !ok {
			telemetry.RatelimitRejectedTotal.WithLabelValues(decision.Policy.Namespace, decision.Policy.Name).Inc()
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
			problem.Write(w, problem.Problem{
				Type:      problem.TypeBase + problem.TypeRateLimited,
				Title:     "Rate limit exceeded",
				Status:    http.StatusTooManyRequests,
				Detail:    "policy '" + decision.Policy.Name + "' rate limit exceeded",
				Policy:    decision.Policy.Name,
				MessageID: msgID,
			})
			logger.Info("request rejected", "result", "ratelimited", "policy", decision.Policy.Name)
			return
		}
	}

	d, backendKey, err := s.backendForPolicy(ctx, decision.Policy)
	if err != nil {
		telemetry.PolicyDeniedTotal.WithLabelValues(decision.Policy.Namespace, decision.Policy.Name, "backend_not_ready").Inc()
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypeBackendNotReady,
			Title:     "Backend not ready",
			Status:    http.StatusServiceUnavailable,
			Detail:    err.Error(),
			Policy:    decision.Policy.Name,
			MessageID: msgID,
		})
		logger.Warn("backend not ready", "policy", decision.Policy.Name, "err", err)
		return
	}
	defer d.Close()

	driverMsg := &driver.Message{
		MessageID:   "<" + msgID + "@sigillum.local>",
		From:        toDriverAddress(from),
		To:          toDriverAddresses(to),
		Cc:          toDriverAddresses(cc),
		Bcc:         toDriverAddresses(bcc),
		Subject:     req.Subject,
		Body:        driver.Body{Text: req.Body.Text, HTML: req.Body.HTML},
		Attachments: atts,
		Headers:     req.Headers,
	}

	start := time.Now()
	res, err := d.Send(ctx, driverMsg)
	dur := time.Since(start).Seconds()

	resultLabel := "ok"
	if err != nil {
		resultLabel = "upstream_error"
		telemetry.BackendDurationSeconds.WithLabelValues(decision.Policy.Namespace, decision.Policy.Name, backendKey, resultLabel).Observe(dur)
		telemetry.MessagesTotal.WithLabelValues(decision.Policy.Namespace, decision.Policy.Name, backendKey, resultLabel).Inc()
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypeUpstreamError,
			Title:     "Upstream backend error",
			Status:    http.StatusBadGateway,
			Detail:    err.Error(),
			Policy:    decision.Policy.Name,
			MessageID: msgID,
		})
		logger.Error("upstream send failed", "backend", backendKey, "err", err, "result", resultLabel)
		return
	}
	telemetry.BackendDurationSeconds.WithLabelValues(decision.Policy.Namespace, decision.Policy.Name, backendKey, resultLabel).Observe(dur)
	telemetry.MessagesTotal.WithLabelValues(decision.Policy.Namespace, decision.Policy.Name, backendKey, resultLabel).Inc()
	telemetry.MessageSizeBytes.WithLabelValues(decision.Policy.Namespace, decision.Policy.Name, backendKey).Observe(float64(view.SizeBytes))

	logger.Info("message accepted",
		"policy", decision.Policy.Name,
		"backend", backendKey,
		"upstream_id", res.UpstreamID,
		"result", resultLabel,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(responseBody{
		MessageID:     msgID,
		PolicyMatched: decision.Policy.Name,
		AcceptedAt:    res.AcceptedAt,
	})
}

func writePolicyDeny(w http.ResponseWriter, msgID string, d policy.Decision) {
	switch d.DenyReason {
	case policy.DenyNoPolicy:
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypeNoPolicyMatched,
			Title:     "No matching policy",
			Status:    http.StatusForbidden,
			Detail:    d.DenyDetail,
			MessageID: msgID,
		})
	case policy.DenySenderNotAllowed:
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypeSenderNotAllowed,
			Title:     "Sender address not allowed by policy",
			Status:    http.StatusForbidden,
			Detail:    d.DenyDetail,
			Policy:    nameOf(d.Policy),
			MessageID: msgID,
		})
	case policy.DenyRecipientBlocked:
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypeRecipientBlocked,
			Title:     "Recipient address not allowed by policy",
			Status:    http.StatusForbidden,
			Detail:    d.DenyDetail,
			Policy:    nameOf(d.Policy),
			MessageID: msgID,
		})
	case policy.DenyMessageTooLarge:
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypeMessageTooLarge,
			Title:     "Message exceeds policy size limit",
			Status:    http.StatusRequestEntityTooLarge,
			Detail:    d.DenyDetail,
			Policy:    nameOf(d.Policy),
			MessageID: msgID,
		})
	case policy.DenyTooManyRecipient:
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypeTooManyRecipients,
			Title:     "Too many recipients for policy",
			Status:    http.StatusForbidden,
			Detail:    d.DenyDetail,
			Policy:    nameOf(d.Policy),
			MessageID: msgID,
		})
	default:
		problem.Write(w, problem.New(problem.TypeNoPolicyMatched, http.StatusForbidden,
			"Request denied", d.DenyDetail))
	}
}

func emitDeny(logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}, subject any, view policy.MessageView, d policy.Decision) {
	policyName := nameOf(d.Policy)
	ns := ""
	if d.Policy != nil {
		ns = d.Policy.Namespace
	}
	telemetry.PolicyDeniedTotal.WithLabelValues(ns, policyName, string(d.DenyReason)).Inc()
	logger.Info("request denied", "result", "denied", "reason", string(d.DenyReason),
		"policy", policyName, "from", view.From, "recipients", strings.Join(view.Recipients, ","))
}

func nameOf(p *sigv1.MailPolicy) string {
	if p == nil {
		return ""
	}
	return p.Name
}

func parseAddress(s string) (mail.Address, error) {
	a, err := mail.ParseAddress(strings.TrimSpace(s))
	if err != nil {
		return mail.Address{}, fmt.Errorf("%q: %w", s, err)
	}
	return *a, nil
}

func parseAddressList(in []string) ([]mail.Address, error) {
	out := make([]mail.Address, 0, len(in))
	for _, s := range in {
		a, err := parseAddress(s)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func addressesToStrings(in []mail.Address) []string {
	out := make([]string, len(in))
	for i, a := range in {
		out[i] = a.Address
	}
	return out
}

func toDriverAddress(a mail.Address) driver.Address {
	return driver.Address{Name: a.Name, Address: a.Address}
}

func toDriverAddresses(in []mail.Address) []driver.Address {
	out := make([]driver.Address, len(in))
	for i, a := range in {
		out[i] = toDriverAddress(a)
	}
	return out
}

func decodeAttachments(in []requestAttachment) ([]driver.Attachment, error) {
	out := make([]driver.Attachment, 0, len(in))
	for i, a := range in {
		raw, err := base64.StdEncoding.DecodeString(a.ContentBase64)
		if err != nil {
			return nil, fmt.Errorf("attachment[%d] %q: %w", i, a.Filename, err)
		}
		out = append(out, driver.Attachment{
			Filename:    a.Filename,
			ContentType: a.ContentType,
			Disposition: a.Disposition,
			Content:     raw,
		})
	}
	return out, nil
}

// estimateSize returns the post-decode payload weight used for size policy
// checks — body text/html bytes plus decoded attachment bytes.
func estimateSize(req requestBody, atts []driver.Attachment) int64 {
	var n int64
	n += int64(len(req.Body.Text))
	n += int64(len(req.Body.HTML))
	for _, a := range atts {
		n += int64(len(a.Content))
	}
	return n
}

// requestContextKey is the context key for the authenticated subject.
type requestContextKey struct{}

// SubjectFrom retrieves the authenticated subject from the request context.
func SubjectFrom(ctx context.Context) (subject, bool) {
	v, ok := ctx.Value(requestContextKey{}).(subject)
	return v, ok
}

// withSubject returns a child context carrying the authenticated subject.
func withSubject(ctx context.Context, s subject) context.Context {
	return context.WithValue(ctx, requestContextKey{}, s)
}

type subject struct {
	Namespace      string
	ServiceAccount string
}

var _ = errors.New // keep import in case future error wrapping is needed

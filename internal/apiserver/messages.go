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

	const maxBody = 32 * 1024 * 1024 // 32 MiB hard ceiling — policy enforces lower limits

	var req requestBody
	var atts []driver.Attachment
	if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "multipart/form-data") {
		var merr error
		req, atts, merr = parseMultipartMessage(r, maxBody)
		if merr != nil {
			if errors.Is(merr, errBodyTooLarge) {
				problem.Write(w, problem.New(problem.TypeMessageTooLarge, http.StatusRequestEntityTooLarge,
					"Request body exceeds 32MiB ceiling", "use a smaller message or split attachments"))
			} else {
				problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
					"Failed to parse multipart body", merr.Error()))
			}
			return
		}
	} else {
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
		if err := json.Unmarshal(body, &req); err != nil {
			problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
				"Malformed JSON payload", err.Error()))
			return
		}
		for i, att := range req.Attachments {
			if err := validateAttachmentMeta(att); err != nil {
				problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
					fmt.Sprintf("Invalid attachment[%d]", i), err.Error()))
				return
			}
		}
		var decErr error
		atts, decErr = decodeAttachments(req.Attachments)
		if decErr != nil {
			problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
				"Invalid attachment", decErr.Error()))
			return
		}
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

	if err := validateRequestHeaders(req.Headers); err != nil {
		problem.Write(w, problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Invalid header", err.Error()))
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

// validateRequestHeaders rejects header keys or values containing CR, LF, or
// NUL, which would allow SMTP header injection through the driver.
func validateRequestHeaders(h map[string]string) error {
	for k, v := range h {
		if strings.ContainsAny(k, "\r\n\x00") {
			return fmt.Errorf("header key contains CR, LF, or NUL")
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("header %q value contains CR, LF, or NUL", k)
		}
	}
	return nil
}

// validateAttachmentMeta rejects attachment metadata fields (filename,
// contentType, disposition) containing CR, LF, or NUL.
func validateAttachmentMeta(a requestAttachment) error {
	if strings.ContainsAny(a.Filename, "\r\n\x00") {
		return fmt.Errorf("filename %q contains CR, LF, or NUL", a.Filename)
	}
	if strings.ContainsAny(a.ContentType, "\r\n\x00") {
		return fmt.Errorf("contentType %q contains CR, LF, or NUL", a.ContentType)
	}
	if strings.ContainsAny(a.Disposition, "\r\n\x00") {
		return fmt.Errorf("disposition %q contains CR, LF, or NUL", a.Disposition)
	}
	return nil
}

var errBodyTooLarge = errors.New("aggregate request body exceeds 32 MiB ceiling")

// parseMultipartMessage parses a multipart/form-data request body.
// The part named "data" must contain a JSON object with message metadata
// (from, to, cc, bcc, subject, body, headers). The attachments field in that
// JSON is ignored — file parts are collected from all other named parts.
func parseMultipartMessage(r *http.Request, maxBytes int64) (requestBody, []driver.Attachment, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return requestBody{}, nil, fmt.Errorf("multipart: %w", err)
	}

	var req requestBody
	var atts []driver.Attachment
	var total int64

	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return requestBody{}, nil, fmt.Errorf("multipart part: %w", err)
		}

		name := part.FormName()
		filename := part.FileName()
		ct := part.Header.Get("Content-Type")

		content, readErr := io.ReadAll(io.LimitReader(part, maxBytes-total+1))
		if readErr != nil {
			return requestBody{}, nil, fmt.Errorf("reading part %q: %w", name, readErr)
		}
		total += int64(len(content))
		if total > maxBytes {
			return requestBody{}, nil, errBodyTooLarge
		}

		if name == "data" {
			if jsonErr := json.Unmarshal(content, &req); jsonErr != nil {
				return requestBody{}, nil, fmt.Errorf("data part: %w", jsonErr)
			}
			continue
		}

		// Treat every other named part as a binary file attachment.
		if filename == "" {
			filename = name
		}
		if ct == "" {
			ct = "application/octet-stream"
		}
		if metaErr := validateAttachmentMeta(requestAttachment{Filename: filename, ContentType: ct}); metaErr != nil {
			return requestBody{}, nil, metaErr
		}
		atts = append(atts, driver.Attachment{
			Filename:    filename,
			ContentType: ct,
			Content:     content,
		})
	}

	return req, atts, nil
}

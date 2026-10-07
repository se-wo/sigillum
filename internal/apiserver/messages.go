package apiserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"net/textproto"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/se-wo/sigillum/internal/apiserver/problem"
	"github.com/se-wo/sigillum/internal/audit"
	"github.com/se-wo/sigillum/internal/driver"
	"github.com/se-wo/sigillum/internal/gateway"
	"github.com/se-wo/sigillum/internal/policy"
)

// requestBody is the JSON payload accepted by POST /v1/messages.
type requestBody struct {
	From        string              `json:"from"`
	To          []string            `json:"to,omitempty"`
	Cc          []string            `json:"cc,omitempty"`
	Bcc         []string            `json:"bcc,omitempty"`
	Subject     string              `json:"subject,omitempty"`
	Body        requestBodyContent  `json:"body,omitempty"`
	Attachments []requestAttachment `json:"attachments,omitempty"`
	Headers     map[string]string   `json:"headers,omitempty"`
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

// handleSendMessage parses the REST payload and hands the message to the
// shared gateway pipeline:
//
//	body decode -> address parse -> gateway.Send (policy, rate limit,
//	backend, audit) -> map Result to 202 / RFC-7807 problem.
func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), requestBudget)
	defer cancel()
	msgID := uuid.NewString()
	subject, authenticated := SubjectFrom(ctx)
	// ev accumulates what is known about the request so that every early
	// exit still leaves a complete audit record (US-4.3). from/to are filled
	// in as soon as they are parsed: a payload rejected after that point
	// (e.g. a header-injection attempt) is exactly what a SIEM wants to see.
	ev := audit.Event{MessageID: msgID, Transport: gateway.TransportREST}
	if authenticated {
		ev.Namespace = subject.Namespace
		ev.ServiceAccount = subject.ServiceAccount
		ev.AuthMethod = gateway.AuthOAuthBearer
	}

	if s.shutting.Load() {
		s.gw.Reject(ev, "shutting_down")
		problem.Write(w, problem.New(problem.TypeShuttingDown, http.StatusServiceUnavailable,
			"Service draining", "the api-server is terminating; retry on a different replica"))
		return
	}
	if !authenticated { // the auth middleware normally answers first
		s.gw.Reject(ev, "missing_token")
		problem.Write(w, problem.New(problem.TypeInvalidToken, http.StatusUnauthorized,
			"Authentication required", "missing or invalid Bearer token"))
		return
	}

	// Bound the bodies held at once before reading this one (see
	// bodyBudget). Callers are authenticated by now, so anonymous clients
	// cannot take up the budget.
	release, ok := s.bodies.reserve(ctx, r)
	if !ok {
		s.gw.Reject(ev, "busy")
		w.Header().Set("Retry-After", "5")
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypeUnavailable,
			Title:     "Too many large requests in progress",
			Status:    http.StatusServiceUnavailable,
			Detail:    "the api-server is already holding its limit of request bodies; retry later",
			MessageID: msgID,
		})
		return
	}
	defer release()

	// rejectPayload answers 4xx for a request that never reached the
	// pipeline and still leaves an audit record.
	rejectPayload := func(p problem.Problem) {
		p.MessageID = msgID
		// Same audit reasons as the SMTP proxy: SIEM rules key on them.
		reason := "invalid_payload"
		if p.Type == problem.TypeBase+problem.TypeMessageTooLarge {
			reason = "message_too_large"
		}
		s.gw.Reject(ev, reason)
		problem.Write(w, p)
	}

	const maxBody = 32 * 1024 * 1024 // 32 MiB hard ceiling — policy enforces lower limits

	var req requestBody
	var atts []driver.Attachment
	if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "multipart/form-data") {
		var merr error
		req, atts, merr = parseMultipartMessage(r, maxBody)
		if merr != nil {
			if errors.Is(merr, errBodyTooLarge) {
				rejectPayload(problem.New(problem.TypeMessageTooLarge, http.StatusRequestEntityTooLarge,
					"Request body exceeds 32MiB ceiling", "use a smaller message or split attachments"))
			} else {
				rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
					"Failed to parse multipart body", merr.Error()))
			}
			return
		}
	} else {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
				"Failed to read request body", err.Error()))
			return
		}
		if int64(len(body)) > maxBody {
			rejectPayload(problem.New(problem.TypeMessageTooLarge, http.StatusRequestEntityTooLarge,
				"Request body exceeds 32MiB ceiling", "use a smaller message or split attachments"))
			return
		}
		if err := decodeRequestJSON(body, &req); err != nil {
			rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
				"Malformed JSON payload", err.Error()))
			return
		}
		for i, att := range req.Attachments {
			if err := validateAttachmentMeta(att); err != nil {
				rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
					fmt.Sprintf("Invalid attachment[%d]", i), err.Error()))
				return
			}
		}
		var decErr error
		atts, decErr = decodeAttachments(req.Attachments)
		if decErr != nil {
			rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
				"Invalid attachment", decErr.Error()))
			return
		}
	}

	ev.From = req.From // raw until parsed, so a malformed sender is still recorded
	from, err := parseAddress(req.From)
	if err == nil {
		err = policy.ValidateAddressHeader(req.From, 1)
	}
	if err != nil {
		rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Invalid 'from' address", err.Error()))
		return
	}
	to, err := parseAddressList(req.To)
	if err != nil {
		rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Invalid 'to' address", err.Error()))
		return
	}
	cc, err := parseAddressList(req.Cc)
	if err != nil {
		rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Invalid 'cc' address", err.Error()))
		return
	}
	bcc, err := parseAddressList(req.Bcc)
	if err != nil {
		rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Invalid 'bcc' address", err.Error()))
		return
	}
	msg := &driver.Message{
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
	ev.From = from.Address
	ev.To = gateway.Recipients(msg)
	if len(ev.To) == 0 {
		rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"At least one recipient required", "provide one of to, cc or bcc"))
		return
	}

	if err := validateRequestHeaders(req.Headers); err != nil {
		rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Invalid header", err.Error()))
		return
	}
	sender, replyTo, err := addressHeaders(req.Headers)
	if err != nil {
		rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Invalid header", err.Error()))
		return
	}
	if !hasContent(req.Body, atts) {
		rejectPayload(problem.New(problem.TypeInvalidPayload, http.StatusBadRequest,
			"Message has no content", "set body.text or body.html, or add a non-empty attachment"))
		return
	}

	res := s.gw.Send(ctx, gateway.Request{
		Identity: gateway.Identity{
			Namespace:      subject.Namespace,
			ServiceAccount: subject.ServiceAccount,
			AuthMethod:     gateway.AuthOAuthBearer,
		},
		Transport: gateway.TransportREST,
		MessageID: msgID,
		Message:   msg,
		Sender:    sender,
		ReplyTo:   replyTo,
		SizeBytes: estimateSize(req, atts),
	})
	writeResult(w, msgID, res)
}

// writeResult maps a gateway Result onto the REST status codes of US-1.1.
func writeResult(w http.ResponseWriter, msgID string, res gateway.Result) {
	switch res.Status {
	case gateway.StatusAccepted:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(responseBody{
			MessageID:     msgID,
			PolicyMatched: res.Policy,
			AcceptedAt:    res.AcceptedAt,
		})
	case gateway.StatusDenied:
		writePolicyDeny(w, msgID, res)
	case gateway.StatusRateLimited:
		w.Header().Set("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds())))
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypeRateLimited,
			Title:     "Rate limit exceeded",
			Status:    http.StatusTooManyRequests,
			Detail:    res.Detail,
			Policy:    res.Policy,
			MessageID: msgID,
		})
	case gateway.StatusUnavailable:
		w.Header().Set("Retry-After", "5")
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypeUnavailable,
			Title:     "Service temporarily unavailable",
			Status:    http.StatusServiceUnavailable,
			Detail:    res.Detail,
			Policy:    res.Policy,
			MessageID: msgID,
		})
	case gateway.StatusBackendNotReady:
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypeBackendNotReady,
			Title:     "Backend not ready",
			Status:    http.StatusServiceUnavailable,
			Detail:    res.Detail,
			Policy:    res.Policy,
			MessageID: msgID,
		})
	case gateway.StatusPolicyInvalid:
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypePolicyInvalid,
			Title:     "Policy is invalid",
			Status:    http.StatusServiceUnavailable,
			Detail:    res.Detail,
			Policy:    res.Policy,
			MessageID: msgID,
		})
	case gateway.StatusUpstreamError:
		if !res.Permanent {
			writeUpstreamError(w, msgID, res)
			return
		}
		// The relay refused this message for good (5xx to MAIL, RCPT or
		// DATA): retrying the same request cannot succeed (G-1).
		problem.Write(w, problem.Problem{
			Type:      problem.TypeBase + problem.TypeUpstreamRejected,
			Title:     "Upstream backend rejected the message",
			Status:    http.StatusUnprocessableEntity,
			Detail:    res.Detail,
			Policy:    res.Policy,
			MessageID: msgID,
		})
	default:
		writeUpstreamError(w, msgID, res)
	}
}

// writeUpstreamError answers 502 upstream-error: a transient upstream
// failure the caller may retry.
func writeUpstreamError(w http.ResponseWriter, msgID string, res gateway.Result) {
	problem.Write(w, problem.Problem{
		Type:      problem.TypeBase + problem.TypeUpstreamError,
		Title:     "Upstream backend error",
		Status:    http.StatusBadGateway,
		Detail:    res.Detail,
		Policy:    res.Policy,
		MessageID: msgID,
	})
}

func writePolicyDeny(w http.ResponseWriter, msgID string, res gateway.Result) {
	p := problem.Problem{Status: http.StatusForbidden, Detail: res.Detail, Policy: res.Policy, MessageID: msgID}
	switch res.DenyReason {
	case policy.DenyNoPolicy:
		p.Type, p.Title = problem.TypeBase+problem.TypeNoPolicyMatched, "No matching policy"
	case policy.DenySenderNotAllowed:
		p.Type, p.Title = problem.TypeBase+problem.TypeSenderNotAllowed, "Sender address not allowed by policy"
		if res.Backend != "" { // only a backend's allowedSenders refusal carries the backend (US-2.8)
			p.Title = "Sender address not allowed by backend"
		}
	case policy.DenyRecipientBlocked:
		p.Type, p.Title = problem.TypeBase+problem.TypeRecipientBlocked, "Recipient address not allowed by policy"
	case policy.DenyMessageTooLarge:
		p.Type, p.Title = problem.TypeBase+problem.TypeMessageTooLarge, "Message exceeds policy size limit"
		p.Status = http.StatusRequestEntityTooLarge
	case policy.DenyTooManyRecipient:
		p.Type, p.Title = problem.TypeBase+problem.TypeTooManyRecipients, "Too many recipients for policy"
	default:
		p.Type, p.Title = problem.TypeBase+problem.TypeNoPolicyMatched, "Request denied"
	}
	problem.Write(w, p)
}

// parseAddress parses one address and rejects local parts with routing
// semantics (see policy.ValidateMailbox).
func parseAddress(s string) (mail.Address, error) {
	a, err := mail.ParseAddress(strings.TrimSpace(s))
	if err != nil {
		return mail.Address{}, fmt.Errorf("%q: %w", s, err)
	}
	if err := policy.ValidateMailbox(a.Address); err != nil {
		return mail.Address{}, err
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

// requestFields holds the top-level keys of requestBody, lower-cased
// (encoding/json matches keys case-insensitively).
var requestFields = func() map[string]bool {
	fields := map[string]bool{}
	t := reflect.TypeOf(requestBody{})
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		fields[strings.ToLower(name)] = true
	}
	return fields
}()

// misplacedFields maps unknown top-level keys that callers commonly use
// (lower-cased) to the field they meant.
var misplacedFields = map[string]string{
	"text":     "body.text",
	"html":     "body.html",
	"replyto":  `headers["Reply-To"]`,
	"reply_to": `headers["Reply-To"]`,
	"sender":   `headers["Sender"]`,
}

// decodeRequestJSON decodes one JSON message object and rejects unknown
// fields: an ignored typo (a top-level "text" instead of body.text) would
// otherwise deliver an empty or incomplete message with 202.
func decodeRequestJSON(data []byte, req *requestBody) error {
	// Top-level keys are checked here rather than taken from the decoder
	// error, which names a nested unknown key without its path: a "text"
	// inside an attachment must not get the body.text hint.
	var top map[string]json.RawMessage
	if err := decodeOneJSON(data, &top, false); err != nil {
		return err
	}
	if top == nil {
		return errors.New("the payload must be a JSON object")
	}
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if requestFields[strings.ToLower(k)] {
			continue
		}
		if want, ok := misplacedFields[strings.ToLower(k)]; ok {
			return fmt.Errorf("unknown field %q; did you mean %s?", k, want)
		}
		return fmt.Errorf("unknown field %q", k)
	}
	return decodeOneJSON(data, req, true)
}

// decodeOneJSON decodes exactly one JSON value from data into v.
func decodeOneJSON(data []byte, v any, disallowUnknown bool) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if disallowUnknown {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty JSON payload")
		}
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the JSON object")
	}
	return nil
}

// hasContent reports whether a message would carry anything: the driver
// treats a whitespace-only body part as absent and an empty attachment
// carries nothing either.
func hasContent(body requestBodyContent, atts []driver.Attachment) bool {
	if strings.TrimSpace(body.Text) != "" || strings.TrimSpace(body.HTML) != "" {
		return true
	}
	for _, a := range atts {
		if len(a.Content) > 0 {
			return true
		}
	}
	return false
}

// estimateSize returns the post-decode payload weight used for size policy
// checks: subject, custom headers, body text/html and decoded attachments.
// Everything the caller controls and the driver relays is counted, so no
// field can carry data past maxSizeBytes.
func estimateSize(req requestBody, atts []driver.Attachment) int64 {
	var n int64
	n += int64(len(req.Subject))
	for k, v := range req.Headers {
		n += int64(len(k) + len(v))
	}
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

// maxHeaderValue is the RFC 5322 line limit (998 characters). The driver
// writes custom header values unfolded, so a longer one could not be
// relayed intact anyway.
const maxHeaderValue = 998

// validateRequestHeaders rejects header keys or values containing CR, LF, or
// NUL, which would allow SMTP header injection through the driver, values
// longer than one header line, the same field given twice (keys match case-
// insensitively, and which of them the driver keeps would be arbitrary), and
// Resent-* fields, which have no place in a submission.
func validateRequestHeaders(h map[string]string) error {
	seen := make(map[string]bool, len(h))
	for k, v := range h {
		if strings.ContainsAny(k, "\r\n\x00") {
			return fmt.Errorf("header key contains CR, LF, or NUL")
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("header %q value contains CR, LF, or NUL", k)
		}
		if len(v) > maxHeaderValue {
			return fmt.Errorf("header %q value exceeds %d characters", k, maxHeaderValue)
		}
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if seen[ck] {
			return fmt.Errorf("header %q given more than once", ck)
		}
		seen[ck] = true
		if strings.HasPrefix(ck, "Resent-") {
			return fmt.Errorf("header %q is not allowed", ck)
		}
	}
	return nil
}

// addressHeaders parses the Sender and Reply-To custom headers so the policy
// can check them: mail clients display Sender and send replies to Reply-To,
// so neither may name an address the policy would not accept. It expects
// headers already checked by validateRequestHeaders.
func addressHeaders(h map[string]string) (sender string, replyTo []string, err error) {
	for k, v := range h {
		switch textproto.CanonicalMIMEHeaderKey(k) {
		case "Sender":
			a, err := parseAddress(v)
			if err == nil {
				err = policy.ValidateAddressHeader(v, 1)
			}
			if err != nil {
				return "", nil, fmt.Errorf("header \"Sender\": %w", err)
			}
			sender = a.Address
		case "Reply-To":
			list, err := mail.ParseAddressList(v)
			if err == nil {
				err = policy.ValidateAddressHeader(v, len(list))
			}
			for i := 0; err == nil && i < len(list); i++ {
				err = policy.ValidateMailbox(list[i].Address)
				replyTo = append(replyTo, list[i].Address)
			}
			if err != nil {
				return "", nil, fmt.Errorf("header \"Reply-To\": %w", err)
			}
		}
	}
	return sender, replyTo, nil
}

// validateAttachmentMeta rejects attachment metadata fields (filename,
// contentType, disposition) that cannot be safely written into MIME headers:
// CR, LF or NUL in any field; a Unicode bidirectional or format control in the
// filename (U+202A–202E, U+2066–2069, U+200E/F), which can make a filename
// display as a different extension than it saves under; and a contentType that
// is not a valid media type.
func validateAttachmentMeta(a requestAttachment) error {
	if strings.ContainsAny(a.Filename, "\r\n\x00") {
		return fmt.Errorf("filename %q contains CR, LF, or NUL", a.Filename)
	}
	if r := firstBidiOrFormatControl(a.Filename); r != 0 {
		return fmt.Errorf("filename %q contains the Unicode control U+%04X", a.Filename, r)
	}
	if strings.ContainsAny(a.ContentType, "\r\n\x00") {
		return fmt.Errorf("contentType %q contains CR, LF, or NUL", a.ContentType)
	}
	if strings.TrimSpace(a.ContentType) != "" {
		if _, _, err := mime.ParseMediaType(a.ContentType); err != nil {
			return fmt.Errorf("contentType %q is not a valid media type: %w", a.ContentType, err)
		}
	}
	if strings.ContainsAny(a.Disposition, "\r\n\x00") {
		return fmt.Errorf("disposition %q contains CR, LF, or NUL", a.Disposition)
	}
	return nil
}

// firstBidiOrFormatControl returns the first Unicode bidirectional or format
// control rune in s (the ones used to spoof a filename's apparent extension),
// or 0 if there is none.
func firstBidiOrFormatControl(s string) rune {
	for _, r := range s {
		switch {
		case r >= 0x202A && r <= 0x202E, // LRE RLE PDF LRO RLO
			r >= 0x2066 && r <= 0x2069, // LRI RLI FSI PDI
			r == 0x200E, r == 0x200F:   // LRM RLM
			return r
		}
	}
	return 0
}

var errBodyTooLarge = errors.New("aggregate request body exceeds 32 MiB ceiling")

// parseMultipartMessage parses a multipart/form-data request body.
// The part named "data" holds the same JSON object as a JSON request;
// Base64 attachments in it are sent too. Every other part is a file
// attachment, named after its filename or else its form name. A part
// without a filename that is named like a message field is refused: it
// was meant for the data part and would otherwise go out as a file.
func parseMultipartMessage(r *http.Request, maxBytes int64) (requestBody, []driver.Attachment, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return requestBody{}, nil, fmt.Errorf("multipart: %w", err)
	}

	var req requestBody
	var atts []driver.Attachment
	var total int64
	var seenData bool

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
			if seenData {
				return requestBody{}, nil, errors.New("more than one data part")
			}
			seenData = true
			if jsonErr := decodeRequestJSON(content, &req); jsonErr != nil {
				return requestBody{}, nil, fmt.Errorf("data part: %w", jsonErr)
			}
			continue
		}

		if filename == "" {
			lower := strings.ToLower(name)
			if want, ok := misplacedFields[lower]; ok {
				return requestBody{}, nil, fmt.Errorf("form field %q is not a file; did you mean %s in the data part?", name, want)
			}
			if requestFields[lower] {
				return requestBody{}, nil, fmt.Errorf("form field %q is not a file; it belongs in the data part", name)
			}
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

	for i, a := range req.Attachments {
		if err := validateAttachmentMeta(a); err != nil {
			return requestBody{}, nil, fmt.Errorf("data part: attachment[%d]: %w", i, err)
		}
	}
	inline, err := decodeAttachments(req.Attachments)
	if err != nil {
		return requestBody{}, nil, fmt.Errorf("data part: %w", err)
	}
	return req, append(inline, atts...), nil
}

// Package driver defines the backend Driver interface and the in-memory
// driver registry. v1 ships only the SMTP driver. Read/Subscribe are
// reserved on purpose — the interface stays send-only until a Read-capable
// driver lands (SPEC §4.5).
package driver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Type is the wire-level discriminator stored in MailBackend.spec.type.
type Type string

const (
	TypeSMTP           Type = "smtp"
	TypeMicrosoftGraph Type = "microsoftGraph"
	TypeSendGrid       Type = "sendgrid"
	TypeGmail          Type = "gmail"
)

// Capability is a backend feature flag. v1 only emits CapabilitySend.
type Capability string

const (
	CapabilitySend            Capability = "send"
	CapabilityRead            Capability = "read"
	CapabilitySubscribeEvents Capability = "subscribeEvents"
	CapabilityFolders         Capability = "folders"
)

// EndpointHealth describes the liveness of one configured endpoint.
type EndpointHealth struct {
	Host    string
	Port    int32
	Ready   bool
	Message string
}

// Address is one parsed RFC-5322 address (display name + addr-spec).
type Address struct {
	Name    string
	Address string
}

// Attachment is one inline or attached body part.
type Attachment struct {
	Filename    string
	ContentType string
	Disposition string // "attachment" (default) or "inline"
	// ContentID identifies an inline part for cid: references in the HTML
	// body, without the angle brackets (see ValidateContentID).
	ContentID string
	Content   []byte
}

// maxContentID bounds a content ID, so its header line stays far below
// the RFC 5322 line limit.
const maxContentID = 250

// ValidateContentID checks a content ID as RFC 5322 msg-id content without
// the angle brackets: id-left "@" id-right, each a dot-atom-text. That
// excludes CR, LF, spaces, quotes and "<>", so it is safe in a header.
func ValidateContentID(id string) error {
	if id == "" || len(id) > maxContentID {
		return fmt.Errorf("content ID must be 1 to %d characters", maxContentID)
	}
	left, right, ok := strings.Cut(id, "@")
	if !ok || !isDotAtom(left) || !isDotAtom(right) {
		return fmt.Errorf("content ID %q must look like id-left@id-right (letters, digits, dots and !#$%%&'*+-/=?^_`{|}~), without <>", id)
	}
	return nil
}

// isDotAtom reports whether s is an RFC 5322 dot-atom-text.
func isDotAtom(s string) bool {
	if s == "" || s[0] == '.' || s[len(s)-1] == '.' || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			c == '.' || strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0) {
			return false
		}
	}
	return true
}

// Body holds the optional plain-text and HTML alternatives.
type Body struct {
	Text string
	HTML string
}

// Message is the protocol-agnostic shape passed to Driver.Send.
type Message struct {
	MessageID   string
	From        Address
	To          []Address
	Cc          []Address
	Bcc         []Address
	Subject     string
	Body        Body
	Attachments []Attachment
	Headers     map[string]string
}

// SendResult captures the upstream-assigned identifier and timing for one Send.
type SendResult struct {
	UpstreamID string
	AcceptedAt time.Time
}

// Driver is implemented by every backend (SMTP today, Graph/Gmail/SendGrid
// tomorrow). The interface is intentionally narrow — Read/Subscribe will be
// added when the first read-capable driver is implemented.
type Driver interface {
	Type() Type
	Capabilities() []Capability

	// HealthCheck probes every configured endpoint; the per-endpoint result
	// is reflected in MailBackend.status.endpointStatus.
	HealthCheck(ctx context.Context) []EndpointHealth

	// Send delivers msg via the first Ready endpoint. Returns a typed error
	// (see ErrUpstream*) so the api-server can map to RFC-7807 problems.
	Send(ctx context.Context, msg *Message) (*SendResult, error)

	// Close releases pooled resources. Drivers may be long-lived.
	io.Closer
}

// RawSender is implemented by drivers that can relay an already-assembled
// RFC 5322 message unchanged. The SMTP proxy path relies on it so a legacy
// client's MIME structure, headers and signatures survive untouched.
type RawSender interface {
	SendRaw(ctx context.Context, envelopeFrom string, recipients []string, raw []byte) (*SendResult, error)
}

// Sentinel errors used for mapping upstream failures to HTTP status codes.
var (
	// ErrNoReadyEndpoint is returned by Send when every configured endpoint
	// failed a recent health check or refused this attempt.
	ErrNoReadyEndpoint = errors.New("no ready endpoint")

	// ErrUpstreamTransient maps to HTTP 502 — the caller may retry.
	ErrUpstreamTransient = errors.New("upstream transient error")

	// ErrUpstreamPermanent maps to HTTP 502 with non-retryable semantics.
	ErrUpstreamPermanent = errors.New("upstream permanent error")

	// ErrRecipientNotInEnvelope marks a message whose To or Cc header names
	// an address that is not an envelope recipient. API backends (Graph,
	// Gmail) deliver to the header addresses, while the policy checked the
	// envelope, so such a message is refused (SPEC US-6.1). It is always
	// wrapped together with ErrUpstreamPermanent.
	ErrRecipientNotInEnvelope = errors.New("header recipient is not an envelope recipient")
)

// MaxRetryAfter caps an upstream's requested delay, like the token
// endpoint's (internal/oauth): a misbehaving upstream must not park
// callers for hours.
const MaxRetryAfter = 10 * time.Minute

// retryAfterError carries how long the upstream asked to be left alone
// (Graph's Retry-After on 429 and 503, an SMTP 421/451 reply's "try again
// in N seconds").
type retryAfterError struct {
	err   error
	after time.Duration
}

func (e *retryAfterError) Error() string { return e.err.Error() }
func (e *retryAfterError) Unwrap() error { return e.err }

// WithRetryAfter attaches the upstream's requested delay to err, capped at
// MaxRetryAfter. A non-positive delay returns err unchanged.
func WithRetryAfter(err error, after time.Duration) error {
	if err == nil || after <= 0 {
		return err
	}
	return &retryAfterError{err: err, after: min(after, MaxRetryAfter)}
}

// RetryAfter returns the delay attached to err by WithRetryAfter, or 0.
func RetryAfter(err error) time.Duration {
	var e *retryAfterError
	if errors.As(err, &e) {
		return e.after
	}
	return 0
}

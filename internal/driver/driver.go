// Package driver defines the backend Driver interface and the in-memory
// driver registry. v1 ships only the SMTP driver. Read/Subscribe are
// reserved on purpose — the interface stays send-only until a Read-capable
// driver lands (SPEC §4.5).
package driver

import (
	"context"
	"errors"
	"io"
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
	Content     []byte
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

// Sentinel errors used for mapping upstream failures to HTTP status codes.
var (
	// ErrNoReadyEndpoint is returned by Send when every configured endpoint
	// failed a recent health check or refused this attempt.
	ErrNoReadyEndpoint = errors.New("no ready endpoint")

	// ErrUpstreamTransient maps to HTTP 502 — the caller may retry.
	ErrUpstreamTransient = errors.New("upstream transient error")

	// ErrUpstreamPermanent maps to HTTP 502 with non-retryable semantics.
	ErrUpstreamPermanent = errors.New("upstream permanent error")
)

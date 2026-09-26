// Package audit implements the compliance audit stream (US-4.3). It is kept
// separate from the operational slog logger: the record shape is fixed, every
// mail request produces exactly one record (accepted or rejected), and no
// message content (subject, body, attachments) is ever written.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Decision is the terminal outcome of one mail request.
type Decision string

const (
	DecisionAccept Decision = "accept"
	DecisionReject Decision = "reject"
)

// Event is one audit record. Field names are part of the public contract —
// SIEM pipelines key on them, so do not rename without a version bump.
type Event struct {
	// Stream is always "audit" so aggregators can split it from the
	// operational log when both share stdout.
	Stream         string    `json:"stream"`
	Timestamp      time.Time `json:"timestamp"`
	MessageID      string    `json:"message_id"`
	Namespace      string    `json:"namespace,omitempty"`
	ServiceAccount string    `json:"service_account,omitempty"`
	AuthMethod     string    `json:"auth_method,omitempty"`
	// Credential is the MailCredential username (auth_method
	// smtp_credential only).
	Credential string `json:"credential,omitempty"`
	// CredentialPrevious marks a login with the previous password of a
	// rotated credential, still inside its grace period, so stragglers can
	// be found before it ends.
	CredentialPrevious bool     `json:"credential_previous,omitempty"`
	Cluster            string   `json:"cluster,omitempty"`
	Transport          string   `json:"transport"`
	From               string   `json:"from,omitempty"`
	To                 []string `json:"to"`
	Policy             string   `json:"policy,omitempty"`
	Backend            string   `json:"backend,omitempty"`
	Decision           Decision `json:"decision"`
	Reason             string   `json:"reason,omitempty"`
}

// Logger records audit events. Implementations must be safe for concurrent use.
type Logger interface {
	Record(e Event)
}

// Discard drops every event (audit stream disabled).
var Discard Logger = discard{}

type discard struct{}

func (discard) Record(Event) {}

// JSONLogger writes one JSON object per line to w.
type JSONLogger struct {
	mu  sync.Mutex
	w   io.Writer
	now func() time.Time
}

// NewJSONLogger returns a JSONLogger writing to w.
func NewJSONLogger(w io.Writer) *JSONLogger {
	return &JSONLogger{w: w, now: time.Now}
}

// Record implements Logger. Write errors are swallowed: a broken audit sink
// must not take down the send path, and there is nowhere better to report it.
func (l *JSONLogger) Record(e Event) {
	e.Stream = "audit"
	if e.Timestamp.IsZero() {
		e.Timestamp = l.now().UTC()
	}
	if e.To == nil {
		e.To = []string{}
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(b)
}

// WithCluster sets the cluster field (--cluster-name, US-4.5) on every
// record written through l. An empty name returns l unchanged.
func WithCluster(l Logger, cluster string) Logger {
	if cluster == "" {
		return l
	}
	return clusterLogger{l, cluster}
}

type clusterLogger struct {
	Logger
	cluster string
}

func (c clusterLogger) Record(e Event) {
	e.Cluster = c.cluster
	c.Logger.Record(e)
}

// FromFlag builds a Logger from the --audit-log flag value:
// "stdout" (default), "stderr", "none", or a file path (appended to).
func FromFlag(v string) (Logger, error) {
	switch v {
	case "", "stdout":
		return NewJSONLogger(os.Stdout), nil
	case "stderr":
		return NewJSONLogger(os.Stderr), nil
	case "none", "off":
		return Discard, nil
	default:
		f, err := os.OpenFile(v, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open audit log %q: %w", v, err)
		}
		return NewJSONLogger(f), nil
	}
}

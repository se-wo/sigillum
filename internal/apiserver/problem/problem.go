// Package problem renders RFC-7807 Problem Details responses.
package problem

import (
	"encoding/json"
	"net/http"
)

// Type prefixes used in the `type` field. The full URI is constructed at
// emit-time so deployments can override the base via the Sigillum docs site.
const (
	TypeBase = "https://sigillum.dev/errors/"

	TypeInvalidPayload    = "invalid-payload"
	TypeInvalidToken      = "invalid-token"
	TypeNoPolicyMatched   = "no-policy-matched"
	TypeSenderNotAllowed  = "sender-not-allowed"
	TypeRecipientBlocked  = "recipient-not-allowed"
	TypeMessageTooLarge   = "message-too-large"
	TypeTooManyRecipients = "too-many-recipients"
	TypeRateLimited       = "rate-limited"
	TypeUpstreamError     = "upstream-error"
	TypeBackendNotReady   = "backend-not-ready"
	TypeNotImplemented    = "not-implemented"
	TypeShuttingDown      = "shutting-down"
	TypeInternal          = "internal-error"
)

// Problem is the RFC-7807 envelope plus a couple of Sigillum-specific keys.
type Problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	Instance  string `json:"instance,omitempty"`
	Policy    string `json:"policy,omitempty"`
	MessageID string `json:"messageId,omitempty"`
}

// Write serializes p as application/problem+json and writes status p.Status.
func Write(w http.ResponseWriter, p Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// New builds a Problem with the canonical type URI.
func New(slug string, status int, title, detail string) Problem {
	return Problem{
		Type:   TypeBase + slug,
		Title:  title,
		Status: status,
		Detail: detail,
	}
}

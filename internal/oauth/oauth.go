// Package oauth obtains and caches OAuth 2.0 access tokens for backends
// whose upstream accepts no password (SPEC US-6.1 to US-6.3). A Source
// fetches a new token from the provider's token endpoint; a Cache hands
// out the current one and fetches the next once for all callers, shortly
// before it expires.
package oauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Token is an access token and the time it expires.
type Token struct {
	AccessToken string
	Expiry      time.Time
}

// String hides the token value, so a Token in a log line or error message
// does not leak it.
func (t Token) String() string {
	if t.AccessToken == "" {
		return "oauth.Token{}"
	}
	return "oauth.Token{expires " + t.Expiry.UTC().Format(time.RFC3339) + "}"
}

// GoString hides the token value from %#v as well.
func (t Token) GoString() string { return t.String() }

// Source fetches a new token from a provider. It does not cache; wrap it
// in a Cache.
type Source interface {
	Token(ctx context.Context) (Token, error)
}

// Error is a failed token request.
type Error struct {
	// Status is the HTTP status of the token endpoint, 0 if there was no
	// answer.
	Status int
	// Code and Description are the OAuth error fields of the answer,
	// reduced to printable ASCII and shortened.
	Code        string
	Description string
	// Permanent marks a failure that will not go away on retry: wrong
	// client ID or secret, a scope not granted, a misconfigured endpoint.
	Permanent bool
	// RetryAfter is the endpoint's Retry-After, if it sent one.
	RetryAfter time.Duration
	// Err is the transport error, if there was no answer.
	Err error
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("oauth token request failed")
	if e.Status != 0 {
		fmt.Fprintf(&b, " (HTTP %d)", e.Status)
	}
	for _, s := range []string{e.Code, e.Description} {
		if s != "" {
			b.WriteString(": " + s)
		}
	}
	if e.Err != nil {
		b.WriteString(": " + e.Err.Error())
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// IsPermanent reports whether err is a token request failure that will
// not go away on retry.
func IsPermanent(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Permanent
}

// retryAfterOf returns the Retry-After of a token request failure, or 0.
func retryAfterOf(err error) time.Duration {
	var e *Error
	if errors.As(err, &e) {
		return e.RetryAfter
	}
	return 0
}

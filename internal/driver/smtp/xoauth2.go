package smtp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/smtp"
	"slices"
	"strings"
	"time"

	"github.com/se-wo/sigillum/internal/driver"
	"github.com/se-wo/sigillum/internal/oauth"
)

// AuthXOAUTH2 is the SASL mechanism of Microsoft and Google for OAuth 2.0
// bearer tokens on SMTP (SPEC US-6.1 stage 2). The driver authenticates
// as SMTPConfig.Username with the access token from SMTPConfig.Tokens.
const AuthXOAUTH2 = "XOAUTH2"

// xoauth2Auth implements the XOAUTH2 SASL mechanism: one initial response
// "user=<mailbox>\x01auth=Bearer <token>\x01\x01". A server that rejects
// the token answers with a 334 challenge holding a JSON error, which the
// client acknowledges with an empty response before the final 535.
type xoauth2Auth struct {
	username, token string
	// rejected is the server's JSON error, kept for the error message.
	rejected *string
}

func (a xoauth2Auth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// The token grants sending as the mailbox until it expires, so like
	// net/smtp's PlainAuth it is only sent over TLS (or to localhost, for
	// tests and a local relay).
	if !server.TLS && !isLocalhost(server.Name) {
		return "", nil, errors.New("XOAUTH2 needs an encrypted connection: set tls to starttls or tls")
	}
	if !slices.ContainsFunc(server.Auth, func(m string) bool { return strings.EqualFold(m, AuthXOAUTH2) }) {
		return "", nil, fmt.Errorf("server does not offer AUTH XOAUTH2 (offers %s)", strings.Join(server.Auth, " "))
	}
	return AuthXOAUTH2, []byte("user=" + a.username + "\x01auth=Bearer " + a.token + "\x01\x01"), nil
}

func (a xoauth2Auth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	if a.rejected != nil {
		*a.rejected = describeXOAUTH2Error(fromServer)
	}
	// An empty response ends the exchange; the server then answers 535.
	return []byte{}, nil
}

// describeXOAUTH2Error reads the status and scope of the server's JSON
// error challenge, reduced to printable ASCII. It returns "" for anything
// else.
func describeXOAUTH2Error(challenge []byte) string {
	var e struct {
		Status string `json:"status"`
		Scope  string `json:"scope"`
	}
	if json.Unmarshal(challenge, &e) != nil || e.Status == "" {
		return ""
	}
	s := "status " + printable(e.Status, 16)
	if e.Scope != "" {
		s += ", scope " + printable(e.Scope, 200)
	}
	return s
}

// accessToken fetches the token for one send or health check. It is
// checked here as well as by internal/oauth, because sources other than a
// token endpoint (the token Secret of a delegated backend) hand it over
// unchecked, and the SASL string uses control characters as separators.
func (d *Driver) accessToken(ctx context.Context) (string, error) {
	tok, err := d.cfg.SMTP.Tokens.Token(ctx)
	if err != nil {
		return "", err
	}
	if !oauth.ValidAccessToken(tok.AccessToken) {
		return "", errors.New("the access token is missing or not a valid bearer token")
	}
	if !tok.Expiry.IsZero() && !time.Now().Before(tok.Expiry) {
		return "", fmt.Errorf("the access token expired at %s", tok.Expiry.UTC().Format(time.RFC3339))
	}
	return tok.AccessToken, nil
}

// tokenError maps a failed token request like the Graph driver: a wrong
// client, a missing grant or a misconfigured endpoint is permanent,
// anything else (provider unreachable, a token not refreshed yet)
// transient.
func tokenError(err error) error {
	kind := driver.ErrUpstreamTransient
	if oauth.IsPermanent(err) {
		kind = driver.ErrUpstreamPermanent
	}
	return fmt.Errorf("%w: XOAUTH2 access token: %w", kind, err)
}

// validSASLUser reports whether s can be the user= value: the mailbox
// address, without the separators of the XOAUTH2 string.
func validSASLUser(s string) bool {
	if s == "" || len(s) > 320 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func printable(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			b.WriteString("...")
			break
		}
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

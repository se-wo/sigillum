package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// DefaultLifetime is assumed for a token whose answer has no
	// expires_in, so it is refreshed early rather than kept forever.
	DefaultLifetime = 5 * time.Minute
	// maxLifetime caps expires_in.
	maxLifetime = 24 * time.Hour
	// maxRetryAfter caps the endpoint's Retry-After.
	maxRetryAfter = 10 * time.Minute

	maxResponseBytes     = 1 << 20
	maxRefreshTokenBytes = 16 << 10
	maxCodeLen           = 64
	maxDescLen           = 300
	requestTimeout       = 30 * time.Second
)

// ClientCredentials is a Source for the client credentials grant (RFC 6749
// §4.4), for example app-only access to Microsoft Graph. The client
// authenticates with client_id and client_secret in the request body.
type ClientCredentials struct {
	// TokenURL is the token endpoint; it must be an https URL.
	TokenURL     string
	ClientID     string
	ClientSecret string
	// Scopes are sent space-separated in the scope parameter.
	Scopes []string
	// HTTPClient sends the request; nil uses a client with a 30 s
	// timeout. Redirects are never followed, whichever client is used,
	// so the secret is only ever sent to TokenURL.
	HTTPClient *http.Client

	now func() time.Time
}

// Token implements Source.
func (c *ClientCredentials) Token(ctx context.Context) (Token, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
	}
	if len(c.Scopes) > 0 {
		form.Set("scope", strings.Join(c.Scopes, " "))
	}
	tok, _, err := post(ctx, c.TokenURL, c.HTTPClient, form, c.now)
	return tok, err
}

// post sends a token request and parses the answer. The client is copied
// so that redirects are never followed: the form carries a secret.
func post(ctx context.Context, tokenURL string, hc *http.Client, form url.Values, now func() time.Time) (Token, string, error) {
	if u, err := url.Parse(tokenURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return Token{}, "", &Error{Permanent: true, Description: "the token URL must be an https URL"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, "", &Error{Permanent: true, Err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: requestTimeout}
	if hc != nil {
		cp := *hc
		client = &cp
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	if now == nil {
		now = time.Now
	}
	// The token's lifetime counts from before the request, so the cached
	// expiry is never later than the provider's.
	start := now()
	resp, err := client.Do(req)
	if err != nil {
		return Token{}, "", &Error{Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return Token{}, "", &Error{Status: resp.StatusCode, Err: err}
	}
	return parseResponse(resp.StatusCode, resp.Header.Get("Retry-After"), body, start)
}

// parseResponse turns a token endpoint answer into a Token and the
// refresh_token it carries (empty if none), or an *Error. now is the time
// the request was sent.
func parseResponse(status int, retryAfter string, body []byte, now time.Time) (Token, string, error) {
	if len(body) > maxResponseBytes {
		return Token{}, "", &Error{Status: status, Description: "response larger than 1 MiB"}
	}
	if status != http.StatusOK {
		var r struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &r)
		e := &Error{Status: status, Code: printable(r.Error, maxCodeLen), Description: printable(r.Description, maxDescLen)}
		switch {
		case status == http.StatusTooManyRequests, status == http.StatusRequestTimeout, status >= 500,
			r.Error == "temporarily_unavailable", r.Error == "server_error":
			e.RetryAfter = parseRetryAfter(retryAfter, now)
		default:
			// invalid_client, invalid_scope, unauthorized_client, a
			// redirect or an unknown path: a configuration problem.
			e.Permanent = true
		}
		return Token{}, "", e
	}

	var r struct {
		AccessToken  string    `json:"access_token"`
		TokenType    string    `json:"token_type"`
		ExpiresIn    expiresIn `json:"expires_in"`
		RefreshToken string    `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return Token{}, "", &Error{Status: status, Description: "malformed token response"}
	}
	if !strings.EqualFold(r.TokenType, "bearer") {
		return Token{}, "", &Error{Status: status, Description: "token_type " + strconv.Quote(printable(r.TokenType, maxCodeLen)) + " is not Bearer"}
	}
	// The token ends up in an Authorization header and in SASL XOAUTH2
	// strings, which use control characters as separators.
	if !isB64Token(r.AccessToken) {
		return Token{}, "", &Error{Status: status, Description: "access_token is missing or not a valid bearer token"}
	}
	// Refresh tokens are opaque and longer; they only travel in form
	// bodies and Secrets, but a control character has no place there.
	if r.RefreshToken != "" && !isVisibleASCII(r.RefreshToken, maxRefreshTokenBytes) {
		return Token{}, "", &Error{Status: status, Description: "refresh_token is not printable ASCII or too long"}
	}
	lifetime := time.Duration(r.ExpiresIn) * time.Second
	switch {
	case r.ExpiresIn <= 0:
		lifetime = DefaultLifetime
	case r.ExpiresIn > expiresIn(maxLifetime/time.Second):
		lifetime = maxLifetime
	}
	return Token{AccessToken: r.AccessToken, Expiry: now.Add(lifetime)}, r.RefreshToken, nil
}

// isVisibleASCII reports whether s is 1 to max bytes of 0x21-0x7e.
func isVisibleASCII(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// expiresIn accepts a number or a quoted number, as some endpoints send.
type expiresIn int64

func (e *expiresIn) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" || s == "" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*e = expiresIn(n)
	return nil
}

// isB64Token reports whether s matches b64token of RFC 6750 §2.1:
// 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=".
func isB64Token(s string) bool {
	body := strings.TrimRight(s, "=")
	if body == "" {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("-._~+/", c) >= 0) {
			return false
		}
	}
	return true
}

// parseRetryAfter reads delay-seconds or an HTTP date, capped at
// maxRetryAfter.
func parseRetryAfter(v string, now time.Time) time.Duration {
	var d time.Duration
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, 0), maxRetryAfter)
}

// printable keeps the printable ASCII of s, at most n bytes, so a provider's
// error text cannot break a log line or an SMTP reply.
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

// MicrosoftTokenURL returns the Microsoft identity platform v2.0 token
// endpoint of a tenant: its ID, a verified domain, or "organizations" /
// "consumers". The tenant becomes part of the URL path, so anything that
// is not a DNS name is refused.
func MicrosoftTokenURL(tenant string) (string, error) {
	if errs := validation.IsDNS1123Subdomain(tenant); len(errs) > 0 {
		return "", &Error{Permanent: true, Description: "tenant " + strconv.Quote(printable(tenant, maxCodeLen)) +
			" must be a tenant ID or a domain name in lower case"}
	}
	return "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token", nil
}

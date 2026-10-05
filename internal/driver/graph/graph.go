// Package graph is the Microsoft Graph send driver (SPEC US-6.1 stage 1):
// app-only access with the Mail.Send application permission, sending the
// MIME message through POST /users/{From}/sendMail. It does not depend on
// SMTP AUTH being enabled for the tenant or the mailbox.
package graph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/se-wo/sigillum/internal/driver"
	smtpdriver "github.com/se-wo/sigillum/internal/driver/smtp"
	"github.com/se-wo/sigillum/internal/oauth"
)

const (
	// Scope requests the application permissions granted to the app.
	Scope = "https://graph.microsoft.com/.default"
	// BaseURL is the Graph v1.0 endpoint of the global cloud.
	BaseURL = "https://graph.microsoft.com/v1.0"

	// MaxRequestBytes is Graph's limit for one request, Base64 MIME
	// included. Larger messages need the draft and upload session path
	// (SPEC US-6.1, opt-in, not implemented yet).
	MaxRequestBytes = 4 << 20

	requestTimeout = 60 * time.Second
	maxErrorBody   = 64 << 10
)

// environment holds what tests replace: the Graph base URL, the token
// endpoint and the HTTP client.
type environment struct {
	baseURL    string
	tokenURL   func(tenant string) (string, error)
	httpClient *http.Client
}

// production is the environment of the registered factory (wired up with
// the microsoftGraph backend type, roadmap row 4b).
var production = environment{baseURL: BaseURL, tokenURL: oauth.MicrosoftTokenURL}

// Driver sends through Microsoft Graph. Drivers are built per send; the
// access token lives in a cache shared by every Driver of the same
// application (tokens.go).
type Driver struct {
	key     string
	baseURL string
	host    string
	tokens  *oauth.Cache
	hc      *http.Client
}

func newDriver(cfg driver.Config, env environment) (*Driver, error) {
	g := cfg.Graph
	if g == nil {
		return nil, fmt.Errorf("graph driver: missing microsoftGraph configuration")
	}
	if g.ClientID == "" || g.ClientSecret == "" {
		return nil, fmt.Errorf("graph driver: client ID and client secret are required")
	}
	tokenURL, err := env.tokenURL(g.TenantID)
	if err != nil {
		return nil, fmt.Errorf("graph driver: %w", err)
	}
	u, err := url.Parse(env.baseURL)
	if err != nil {
		return nil, fmt.Errorf("graph driver: %w", err)
	}
	hc := &http.Client{Timeout: requestTimeout}
	if env.httpClient != nil {
		cp := *env.httpClient
		hc = &cp
	}
	// The bearer token goes only to Graph.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	src := &oauth.ClientCredentials{TokenURL: tokenURL, ClientID: g.ClientID, ClientSecret: g.ClientSecret,
		Scopes: []string{Scope}, HTTPClient: env.httpClient}
	return &Driver{key: cfg.BackendKey, baseURL: env.baseURL, host: u.Hostname(), hc: hc,
		tokens: sharedCache(src)}, nil
}

func (d *Driver) Type() driver.Type { return driver.TypeMicrosoftGraph }

func (d *Driver) Capabilities() []driver.Capability {
	return []driver.Capability{driver.CapabilitySend}
}

func (d *Driver) Close() error { return nil }

// HealthCheck acquires a token, so a wrong tenant, client ID or secret
// shows up as Ready=False instead of on the first send. Graph itself has
// no unauthenticated probe.
func (d *Driver) HealthCheck(ctx context.Context) []driver.EndpointHealth {
	h := driver.EndpointHealth{Host: d.host, Port: 443, Ready: true}
	if _, err := d.tokens.Token(ctx); err != nil {
		h.Ready, h.Message = false, err.Error()
	}
	return []driver.EndpointHealth{h}
}

// Send assembles msg like the SMTP driver and sends it with its To, Cc and
// Bcc as the envelope.
func (d *Driver) Send(ctx context.Context, msg *driver.Message) (*driver.SendResult, error) {
	raw, _, err := smtpdriver.AssembleMessage(msg, "sigillum")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", driver.ErrUpstreamPermanent, err)
	}
	var rcpts []string
	for _, set := range [][]driver.Address{msg.To, msg.Cc, msg.Bcc} {
		for _, a := range set {
			rcpts = append(rcpts, a.Address)
		}
	}
	return d.SendRaw(ctx, msg.From.Address, rcpts, raw)
}

// SendRaw implements driver.RawSender. Graph sends as the From mailbox of
// the message; the envelope sender has no counterpart and was checked by
// the policy like From.
func (d *Driver) SendRaw(ctx context.Context, _ string, recipients []string, raw []byte) (*driver.SendResult, error) {
	body, from, err := prepare(raw, recipients)
	if err != nil {
		return nil, err
	}
	if n := base64.StdEncoding.EncodedLen(len(body)); n > MaxRequestBytes {
		return nil, fmt.Errorf("%w: the message is %d bytes as Base64; Microsoft Graph accepts at most 4 MiB per request",
			driver.ErrUpstreamPermanent, n)
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	endpoint := d.baseURL + "/users/" + url.PathEscape(from) + "/sendMail"

	// A rejected token is dropped and fetched once more: it may have been
	// revoked or rotated before its expiry.
	for attempt := 0; ; attempt++ {
		tok, err := d.tokens.Token(ctx)
		if err != nil {
			return nil, tokenError(err)
		}
		res, status, err := d.post(ctx, endpoint, tok.AccessToken, encoded)
		if status == http.StatusUnauthorized && attempt == 0 {
			d.tokens.Invalidate(tok)
			continue
		}
		return res, err
	}
}

func (d *Driver) post(ctx context.Context, endpoint, token, body string) (*driver.SendResult, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", driver.ErrUpstreamPermanent, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := d.hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: microsoft graph: %v", driver.ErrUpstreamTransient, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		return &driver.SendResult{UpstreamID: resp.Header.Get("request-id"), AcceptedAt: time.Now()}, resp.StatusCode, nil
	}
	detail := errorDetail(resp)
	switch {
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode >= 500:
		return nil, resp.StatusCode, fmt.Errorf("%w: microsoft graph: HTTP %d%s", driver.ErrUpstreamTransient, resp.StatusCode, detail)
	default:
		// 400 malformed, 401 twice, 403 missing permission or mailbox
		// outside the app's scope, 404 unknown mailbox, 413 too large.
		return nil, resp.StatusCode, fmt.Errorf("%w: microsoft graph: HTTP %d%s", driver.ErrUpstreamPermanent, resp.StatusCode, detail)
	}
}

// errorDetail reads Graph's error code and message, reduced to printable
// ASCII so it is safe in logs and SMTP replies.
func errorDetail(resp *http.Response) string {
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if json.Unmarshal(raw, &e) != nil || e.Error.Code == "" {
		return ""
	}
	return ": " + printable(e.Error.Code, 64) + ": " + printable(e.Error.Message, 300)
}

// tokenError maps a failed token request: a wrong secret, tenant or
// missing consent is permanent, anything else (Entra unreachable, a
// cancelled send) transient.
func tokenError(err error) error {
	kind := driver.ErrUpstreamTransient
	if oauth.IsPermanent(err) {
		kind = driver.ErrUpstreamPermanent
	}
	return fmt.Errorf("%w: microsoft graph token: %w", kind, err)
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

var _ driver.RawSender = (*Driver)(nil)

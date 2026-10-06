// Package gmail is the Gmail API send driver (SPEC US-6.2 stage 1): a
// Google service account with domain-wide delegation impersonates the From
// mailbox of each message and sends the MIME message through
// users.messages.send, so Google Workspace mailboxes need no app password.
package gmail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/se-wo/sigillum/internal/driver"
	smtpdriver "github.com/se-wo/sigillum/internal/driver/smtp"
	"github.com/se-wo/sigillum/internal/oauth"
)

const (
	// Scope allows sending only, not reading the mailbox.
	Scope = "https://www.googleapis.com/auth/gmail.send"
	// UploadURL sends a raw RFC 5322 message as the impersonated user.
	UploadURL = "https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/send?uploadType=media"
	// MaxMessageBytes is Gmail's limit for one message.
	MaxMessageBytes = 35 << 20

	requestTimeout = 120 * time.Second
	maxErrorBody   = 64 << 10
	// maxCaches bounds the token caches: one per key file and mailbox.
	maxCaches = 1024
)

// environment holds what tests replace.
type environment struct {
	uploadURL  string
	tokenURL   string // empty: Google's
	httpClient *http.Client
}

var production = environment{uploadURL: UploadURL}

func init() {
	driver.Register(driver.TypeGmail, func(cfg driver.Config) (driver.Driver, error) {
		return newDriver(cfg, production)
	})
}

// Driver sends through the Gmail API. Drivers are built per send; tokens
// live in caches shared by every Driver, one per key file and mailbox.
type Driver struct {
	sa      *oauth.GoogleServiceAccount
	keyHash string
	env     environment
	hc      *http.Client
	host    string
}

func newDriver(cfg driver.Config, env environment) (*Driver, error) {
	if cfg.Gmail == nil {
		return nil, fmt.Errorf("gmail driver: missing gmail configuration")
	}
	sa, err := oauth.ParseGoogleServiceAccount(cfg.Gmail.ServiceAccountJSON)
	if err != nil {
		return nil, fmt.Errorf("gmail driver: %w", err)
	}
	u, err := url.Parse(env.uploadURL)
	if err != nil {
		return nil, fmt.Errorf("gmail driver: %w", err)
	}
	hc := &http.Client{Timeout: requestTimeout}
	if env.httpClient != nil {
		cp := *env.httpClient
		hc = &cp
	}
	// The bearer token goes only to Gmail.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	sum := sha256.Sum256(cfg.Gmail.ServiceAccountJSON)
	return &Driver{sa: sa, keyHash: hex.EncodeToString(sum[:]), env: env, hc: hc, host: u.Hostname()}, nil
}

func (d *Driver) Type() driver.Type { return driver.TypeGmail }

func (d *Driver) Capabilities() []driver.Capability {
	return []driver.Capability{driver.CapabilitySend}
}

func (d *Driver) Close() error { return nil }

// HealthCheck acquires a token for the service account itself, so a
// broken or revoked key shows up as Ready=False. Missing domain-wide
// delegation for a mailbox shows on its first send.
func (d *Driver) HealthCheck(ctx context.Context) []driver.EndpointHealth {
	h := driver.EndpointHealth{Host: d.host, Port: 443, Ready: true}
	if _, err := d.tokens("").Token(ctx); err != nil {
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

// SendRaw implements driver.RawSender. Gmail sends as the From mailbox of
// the message, which the service account impersonates; the envelope sender
// was checked by the policy like From.
func (d *Driver) SendRaw(ctx context.Context, _ string, recipients []string, raw []byte) (*driver.SendResult, error) {
	body, from, err := driver.BindToEnvelope(raw, recipients)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxMessageBytes {
		return nil, fmt.Errorf("%w: the message is %d bytes; Gmail accepts at most 35 MB", driver.ErrUpstreamPermanent, len(body))
	}
	tokens := d.tokens(from)
	// A rejected token is dropped and fetched once more: it may have been
	// revoked before its expiry.
	for attempt := 0; ; attempt++ {
		tok, err := tokens.Token(ctx)
		if err != nil {
			return nil, tokenError(err)
		}
		res, status, err := d.post(ctx, tok.AccessToken, body)
		if status == http.StatusUnauthorized && attempt == 0 {
			tokens.Invalidate(tok)
			continue
		}
		return res, err
	}
}

func (d *Driver) post(ctx context.Context, token string, body []byte) (*driver.SendResult, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.env.uploadURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", driver.ErrUpstreamPermanent, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "message/rfc822")
	resp, err := d.hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: gmail: %v", driver.ErrUpstreamTransient, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if resp.StatusCode == http.StatusOK {
		var r struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &r)
		return &driver.SendResult{UpstreamID: printable(r.ID, 64), AcceptedAt: time.Now()}, resp.StatusCode, nil
	}
	detail := errorDetail(raw)
	switch {
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode >= 500:
		return nil, resp.StatusCode, fmt.Errorf("%w: gmail: HTTP %d%s", driver.ErrUpstreamTransient, resp.StatusCode, detail)
	default:
		// 400 malformed, 401 twice, 403 delegation or scope missing,
		// 413 too large.
		return nil, resp.StatusCode, fmt.Errorf("%w: gmail: HTTP %d%s", driver.ErrUpstreamPermanent, resp.StatusCode, detail)
	}
}

var (
	cachesMu sync.Mutex
	caches   = map[string]*oauth.Cache{}
)

// tokens returns the token cache of the service account acting as
// subject ("" for the account itself). The gateway builds a driver per
// send, so the caches are shared by every Driver: one per key file and
// mailbox, the key file hashed so it is not kept in memory twice.
func (d *Driver) tokens(subject string) *oauth.Cache {
	key := d.keyHash + "\x00" + strings.ToLower(subject) + "\x00" + d.env.tokenURL
	cachesMu.Lock()
	defer cachesMu.Unlock()
	if c, ok := caches[key]; ok {
		return c
	}
	if len(caches) >= maxCaches {
		caches = map[string]*oauth.Cache{}
	}
	sa := *d.sa
	sa.Scopes, sa.Subject, sa.TokenURL, sa.HTTPClient = []string{Scope}, subject, d.env.tokenURL, d.env.httpClient
	c := oauth.NewCache(&sa)
	caches[key] = c
	return c
}

// tokenError maps a failed token request: missing domain-wide delegation
// (unauthorized_client), a revoked key or a bad scope is permanent;
// anything else (Google unreachable, a cancelled send) transient.
func tokenError(err error) error {
	kind := driver.ErrUpstreamTransient
	if oauth.IsPermanent(err) {
		kind = driver.ErrUpstreamPermanent
	}
	return fmt.Errorf("%w: gmail token: %w", kind, err)
}

// errorDetail reads the API error's status and message, reduced to
// printable ASCII so it is safe in logs and SMTP replies.
func errorDetail(raw []byte) string {
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) != nil || (e.Error.Status == "" && e.Error.Message == "") {
		return ""
	}
	return ": " + printable(e.Error.Status, 64) + ": " + printable(e.Error.Message, 300)
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

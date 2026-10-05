package graph

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strings"
	"sync"
	"testing"

	"github.com/se-wo/sigillum/internal/driver"
	"github.com/se-wo/sigillum/internal/oauth/oauthtest"
)

// fakeGraph records sendMail requests and answers with the scripted
// statuses (202 once the script is used up).
type fakeGraph struct {
	*httptest.Server
	mu       sync.Mutex
	statuses []int
	header   http.Header
	body     string
	calls    []call
}

type call struct {
	path, auth, contentType string
	mime                    []byte
}

func newFakeGraph(t *testing.T) *fakeGraph {
	g := &fakeGraph{}
	g.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mime, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			t.Errorf("body is not Base64: %v", err)
		}
		g.mu.Lock()
		g.calls = append(g.calls, call{r.URL.EscapedPath(), r.Header.Get("Authorization"), r.Header.Get("Content-Type"), mime})
		status, header, body := http.StatusAccepted, g.header, g.body
		if len(g.statuses) > 0 {
			status, g.statuses = g.statuses[0], g.statuses[1:]
		}
		g.mu.Unlock()
		for k, v := range header {
			w.Header()[k] = v
		}
		w.Header().Set("request-id", "req-1")
		w.WriteHeader(status)
		if status != http.StatusAccepted {
			_, _ = io.WriteString(w, body)
		}
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *fakeGraph) last(t *testing.T) call {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.calls) == 0 {
		t.Fatal("no request to Graph")
	}
	return g.calls[len(g.calls)-1]
}

func (g *fakeGraph) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.calls)
}

type fixture struct {
	graph  *fakeGraph
	tokens *oauthtest.Server
	driver *Driver
}

// newFixture builds a driver against fake Graph and token endpoints. Each
// test gets its own client secret, so the shared token cache is not shared
// between tests.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	secret := "secret-" + t.Name()
	f := &fixture{graph: newFakeGraph(t), tokens: oauthtest.New(t, "app", secret)}
	f.driver = f.newDriver(t, secret)
	return f
}

func (f *fixture) newDriver(t *testing.T, secret string) *Driver {
	t.Helper()
	env := environment{
		baseURL:    f.graph.URL + "/v1.0",
		tokenURL:   func(string) (string, error) { return f.tokens.TokenURL(), nil },
		httpClient: f.graph.Client(), // httptest servers share one certificate
	}
	d, err := newDriver(driver.Config{Type: driver.TypeMicrosoftGraph, BackendKey: "/m365",
		Graph: &driver.GraphConfig{TenantID: "contoso.onmicrosoft.com", ClientID: "app", ClientSecret: secret}}, env)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func header(t *testing.T, mime []byte) mail.Header {
	t.Helper()
	m, err := mail.ReadMessage(bytes.NewReader(mime))
	if err != nil {
		t.Fatalf("Graph got an unparsable message: %v\n%s", err, mime)
	}
	return m.Header
}

func addrs(t *testing.T, h mail.Header, field string) []string {
	t.Helper()
	list, err := h.AddressList(field)
	if errors.Is(err, mail.ErrHeaderNotPresent) {
		return nil
	}
	if err != nil {
		t.Fatalf("%s: %v", field, err)
	}
	var out []string
	for _, a := range list {
		out = append(out, a.Address)
	}
	return out
}

func TestSend_RESTMessage(t *testing.T) {
	f := newFixture(t)
	res, err := f.driver.Send(context.Background(), &driver.Message{
		From:    driver.Address{Name: "Alerts", Address: "alerts@contoso.com"},
		To:      []driver.Address{{Address: "a@example.com"}},
		Cc:      []driver.Address{{Address: "b@example.com"}},
		Bcc:     []driver.Address{{Address: "c@example.com"}, {Address: "d@example.com"}},
		Subject: "disk full",
		Body:    driver.Body{Text: "hello"},
	})
	if err != nil || res.UpstreamID != "req-1" {
		t.Fatalf("send: %+v %v", res, err)
	}
	c := f.graph.last(t)
	if c.path != "/v1.0/users/alerts@contoso.com/sendMail" || c.auth != "Bearer token-1" || c.contentType != "text/plain" {
		t.Fatalf("unexpected request %+v", c)
	}
	h := header(t, c.mime)
	if got := addrs(t, h, "Bcc"); strings.Join(got, ",") != "c@example.com,d@example.com" {
		t.Fatalf("blind copies must go into Bcc, got %v", got)
	}
	if got := addrs(t, h, "To"); strings.Join(got, ",") != "a@example.com" {
		t.Fatalf("To changed: %v", got)
	}
	if f.tokens.LastForm().Get("scope") != Scope {
		t.Fatal("the token must be requested for Graph's .default scope")
	}
}

func TestSendRaw_EnvelopeRule(t *testing.T) {
	const msg = "From: app@contoso.com\r\nTo: a@example.com\r\nSubject: x\r\n\r\nbody\r\n"
	for _, tc := range []struct {
		name     string
		raw      string
		envelope []string
		bcc      string
		err      error
	}{
		{name: "all in To", raw: msg, envelope: []string{"A@example.com"}},
		{name: "blind copy", raw: msg, envelope: []string{"a@example.com", "x@example.com"}, bcc: "x@example.com"},
		{name: "To outside the envelope", raw: msg, envelope: []string{"x@example.com"}, err: driver.ErrRecipientNotInEnvelope},
		{name: "Cc outside the envelope", raw: "From: app@contoso.com\r\nTo: a@example.com\r\nCc: evil@example.net\r\n\r\nb\r\n",
			envelope: []string{"a@example.com"}, err: driver.ErrRecipientNotInEnvelope},
		{name: "Bcc left in the message", raw: "From: app@contoso.com\r\nBcc: a@example.com\r\n\r\nb\r\n",
			envelope: []string{"a@example.com"}, err: driver.ErrUpstreamPermanent},
		{name: "two From", raw: "From: a@contoso.com, b@contoso.com\r\nTo: a@example.com\r\n\r\nb\r\n",
			envelope: []string{"a@example.com"}, err: driver.ErrUpstreamPermanent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			_, err := f.driver.SendRaw(context.Background(), "bounce@contoso.com", tc.envelope, []byte(tc.raw))
			if tc.err != nil {
				if !errors.Is(err, tc.err) || !errors.Is(err, driver.ErrUpstreamPermanent) || f.graph.count() != 0 {
					t.Fatalf("want permanent %v before any request, got %v (%d requests)", tc.err, err, f.graph.count())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			c := f.graph.last(t)
			if got := strings.Join(addrs(t, header(t, c.mime), "Bcc"), ","); got != tc.bcc {
				t.Fatalf("Bcc %q, want %q", got, tc.bcc)
			}
			if !bytes.HasSuffix(c.mime, []byte(tc.raw)) {
				t.Fatal("the message itself must be relayed unchanged")
			}
		})
	}
}

func TestSendRaw_SizeLimit(t *testing.T) {
	f := newFixture(t)
	raw := "From: app@contoso.com\r\nTo: a@example.com\r\n\r\n" + strings.Repeat("x", MaxRequestBytes/4*3) + "\r\n"
	_, err := f.driver.SendRaw(context.Background(), "", []string{"a@example.com"}, []byte(raw))
	if !errors.Is(err, driver.ErrUpstreamPermanent) || !strings.Contains(err.Error(), "4 MiB") || f.graph.count() != 0 {
		t.Fatalf("want a permanent error naming the limit, got %v", err)
	}
}

func TestSend_GraphErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
		detail string
	}{
		{429, "", driver.ErrUpstreamTransient, "HTTP 429"},
		{503, "", driver.ErrUpstreamTransient, "HTTP 503"},
		{403, `{"error":{"code":"ErrorAccessDenied","message":"Access is denied.\r\nCheck credentials"}}`, driver.ErrUpstreamPermanent,
			"ErrorAccessDenied: Access is denied.??Check credentials"},
		{404, `{"error":{"code":"ErrorInvalidUser","message":"The requested user is invalid."}}`, driver.ErrUpstreamPermanent, "ErrorInvalidUser"},
		{400, "not json", driver.ErrUpstreamPermanent, "HTTP 400"},
	} {
		f := newFixture(t)
		f.graph.statuses, f.graph.body = []int{tc.status}, tc.body
		_, err := f.driver.Send(context.Background(), &driver.Message{From: driver.Address{Address: "app@contoso.com"},
			To: []driver.Address{{Address: "a@example.com"}}, Body: driver.Body{Text: "x"}})
		if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.detail) {
			t.Errorf("HTTP %d: want %v with %q, got %v", tc.status, tc.want, tc.detail, err)
		}
	}
}

func TestSend_RejectedTokenIsReplacedOnce(t *testing.T) {
	msg := &driver.Message{From: driver.Address{Address: "app@contoso.com"},
		To: []driver.Address{{Address: "a@example.com"}}, Body: driver.Body{Text: "x"}}

	f := newFixture(t)
	f.graph.statuses = []int{http.StatusUnauthorized}
	if _, err := f.driver.Send(context.Background(), msg); err != nil {
		t.Fatalf("a revoked token must be replaced: %v", err)
	}
	if c := f.graph.last(t); c.auth != "Bearer token-2" || f.tokens.Requests() != 2 {
		t.Fatalf("want a new token, got %q after %d token requests", c.auth, f.tokens.Requests())
	}

	f = newFixture(t)
	f.graph.statuses = []int{http.StatusUnauthorized, http.StatusUnauthorized}
	if _, err := f.driver.Send(context.Background(), msg); !errors.Is(err, driver.ErrUpstreamPermanent) || f.graph.count() != 2 {
		t.Fatalf("a second 401 is permanent and not retried again: %v (%d requests)", err, f.graph.count())
	}
}

func TestTokenFailures(t *testing.T) {
	msg := &driver.Message{From: driver.Address{Address: "app@contoso.com"},
		To: []driver.Address{{Address: "a@example.com"}}, Body: driver.Body{Text: "x"}}
	f := newFixture(t)
	wrong := f.newDriver(t, "wrong-secret-"+t.Name())
	if _, err := wrong.Send(context.Background(), msg); !errors.Is(err, driver.ErrUpstreamPermanent) || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("a wrong secret is permanent: %v", err)
	}
	if h := wrong.HealthCheck(context.Background()); len(h) != 1 || h[0].Ready || !strings.Contains(h[0].Message, "invalid_client") {
		t.Fatalf("the health check must report the wrong secret: %+v", h)
	}

	f.tokens.Fail(http.StatusServiceUnavailable, nil, "")
	if _, err := f.driver.Send(context.Background(), msg); !errors.Is(err, driver.ErrUpstreamTransient) {
		t.Fatalf("Entra unavailable is transient: %v", err)
	}
	if f.graph.count() != 0 {
		t.Fatal("no request to Graph without a token")
	}
}

func TestHealthCheckAndSharedToken(t *testing.T) {
	f := newFixture(t)
	h := f.driver.HealthCheck(context.Background())
	if len(h) != 1 || !h[0].Ready || h[0].Host != "127.0.0.1" || h[0].Port != 443 {
		t.Fatalf("unexpected health %+v", h)
	}
	// The gateway builds a driver per send: they share the token.
	other := f.newDriver(t, "secret-"+t.Name())
	if _, err := other.Send(context.Background(), &driver.Message{From: driver.Address{Address: "app@contoso.com"},
		To: []driver.Address{{Address: "a@example.com"}}, Body: driver.Body{Text: "x"}}); err != nil {
		t.Fatal(err)
	}
	if f.tokens.Requests() != 1 {
		t.Fatalf("drivers of one application must share a token, %d token requests", f.tokens.Requests())
	}
}

func TestNewDriver_RejectsIncompleteConfig(t *testing.T) {
	for _, g := range []*driver.GraphConfig{nil, {TenantID: "t", ClientID: "app"}, {TenantID: "a/b", ClientID: "app", ClientSecret: "s"}} {
		if _, err := newDriver(driver.Config{Graph: g}, production); err == nil {
			t.Errorf("%+v: want an error", g)
		}
	}
}

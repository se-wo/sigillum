package gmail

import (
	"bytes"
	"context"
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

const saEmail = "sender@project.iam.gserviceaccount.com"

// fakeGmail records sends and answers with the scripted statuses (200
// once the script is used up).
type fakeGmail struct {
	*httptest.Server
	mu       sync.Mutex
	statuses []int
	body     string
	calls    []gmailCall
}

type gmailCall struct {
	auth, contentType string
	raw               []byte
}

func newFakeGmail(t *testing.T) *fakeGmail {
	g := &fakeGmail{}
	g.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		g.mu.Lock()
		g.calls = append(g.calls, gmailCall{r.Header.Get("Authorization"), r.Header.Get("Content-Type"), raw})
		status, body := http.StatusOK, g.body
		if len(g.statuses) > 0 {
			status, g.statuses = g.statuses[0], g.statuses[1:]
		}
		g.mu.Unlock()
		w.WriteHeader(status)
		if status == http.StatusOK {
			body = `{"id":"18c2f0a1b2c3d4e5","threadId":"18c2f0a1b2c3d4e5"}`
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(g.Close)
	return g
}

type fixture struct {
	gmail  *fakeGmail
	tokens *oauthtest.Server
	d      *Driver
}

func newFixture(t *testing.T, delegated ...string) *fixture {
	t.Helper()
	tokens := oauthtest.New(t, "", "")
	key, raw := oauthtest.ServiceAccountKey(t, saEmail, "")
	tokens.SetServiceAccount(&key.PublicKey, saEmail, delegated...)
	g := newFakeGmail(t)
	d, err := newDriver(driver.Config{Type: driver.TypeGmail, Gmail: &driver.GmailConfig{ServiceAccountJSON: raw}},
		environment{uploadURL: g.URL + "/upload", tokenURL: tokens.TokenURL(), httpClient: g.Client()})
	if err != nil {
		t.Fatal(err)
	}
	// The fake Gmail and the fake token endpoint have their own
	// certificates; trust both.
	pool := g.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	pool.AddCert(tokens.Certificate())
	return &fixture{gmail: g, tokens: tokens, d: d}
}

func TestSend_ImpersonatesFromAndBindsTheEnvelope(t *testing.T) {
	f := newFixture(t, "noreply@example.com")
	raw := []byte("From: noreply@example.com\r\nTo: a@example.net\r\nSubject: x\r\n\r\nbody\r\n")
	res, err := f.d.SendRaw(context.Background(), "bounce@example.com", []string{"a@example.net", "hidden@example.net"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.UpstreamID != "18c2f0a1b2c3d4e5" {
		t.Fatalf("upstream ID %q", res.UpstreamID)
	}
	if got := f.tokens.Subjects(); len(got) != 1 || got[0] != "noreply@example.com" {
		t.Fatalf("the service account must act as the From mailbox, got %v", got)
	}
	c := f.gmail.calls[0]
	if !strings.HasPrefix(c.auth, "Bearer token-") || c.contentType != "message/rfc822" {
		t.Fatalf("request %+v", c)
	}
	m, err := mail.ReadMessage(bytes.NewReader(c.raw))
	if err != nil {
		t.Fatal(err)
	}
	if bcc := m.Header.Get("Bcc"); bcc != "hidden@example.net" {
		t.Fatalf("the blind envelope recipient must go into Bcc, got %q", bcc)
	}
}

func TestSend_HeaderRecipientOutsideEnvelope(t *testing.T) {
	f := newFixture(t, "noreply@example.com")
	raw := []byte("From: noreply@example.com\r\nTo: a@example.net, evil@example.org\r\n\r\nx\r\n")
	_, err := f.d.SendRaw(context.Background(), "noreply@example.com", []string{"a@example.net"}, raw)
	if !errors.Is(err, driver.ErrRecipientNotInEnvelope) || len(f.gmail.calls) != 0 {
		t.Fatalf("want a refusal before any request, got %v", err)
	}
}

func TestSend_ErrorMapping(t *testing.T) {
	raw := []byte("From: noreply@example.com\r\nTo: a@example.net\r\n\r\nx\r\n")
	for _, tc := range []struct {
		name     string
		statuses []int
		body     string
		want     error
		detail   string
		calls    int
	}{
		{"rejected token is replaced once", []int{401}, "", nil, "", 2},
		{"rejected twice", []int{401, 401}, "", driver.ErrUpstreamPermanent, "HTTP 401", 2},
		{"rate limited", []int{429}, `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","message":"Too many"}}`, driver.ErrUpstreamTransient, "RESOURCE_EXHAUSTED", 1},
		{"server error", []int{503}, "", driver.ErrUpstreamTransient, "HTTP 503", 1},
		{"forbidden", []int{403}, `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"Delegation denied\r\n550 fake"}}`,
			driver.ErrUpstreamPermanent, "Delegation denied??550 fake", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "noreply@example.com")
			f.gmail.statuses, f.gmail.body = tc.statuses, tc.body
			_, err := f.d.SendRaw(context.Background(), "noreply@example.com", []string{"a@example.net"}, raw)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if tc.detail != "" && !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("error %q lacks %q", err, tc.detail)
			}
			if len(f.gmail.calls) != tc.calls {
				t.Fatalf("%d calls, want %d", len(f.gmail.calls), tc.calls)
			}
		})
	}
}

func TestSend_UndelegatedMailboxIsPermanent(t *testing.T) {
	f := newFixture(t, "noreply@example.com")
	raw := []byte("From: ceo@example.com\r\nTo: a@example.net\r\n\r\nx\r\n")
	_, err := f.d.SendRaw(context.Background(), "ceo@example.com", []string{"a@example.net"}, raw)
	if !errors.Is(err, driver.ErrUpstreamPermanent) || !strings.Contains(err.Error(), "unauthorized_client") || len(f.gmail.calls) != 0 {
		t.Fatalf("want a permanent token error without a send, got %v", err)
	}
}

func TestSend_TooLarge(t *testing.T) {
	f := newFixture(t, "noreply@example.com")
	raw := append([]byte("From: noreply@example.com\r\nTo: a@example.net\r\n\r\n"), bytes.Repeat([]byte("x"), MaxMessageBytes)...)
	_, err := f.d.SendRaw(context.Background(), "noreply@example.com", []string{"a@example.net"}, raw)
	if !errors.Is(err, driver.ErrUpstreamPermanent) || !strings.Contains(err.Error(), "35 MB") {
		t.Fatalf("want the size limit, got %v", err)
	}
}

func TestHealthCheck(t *testing.T) {
	f := newFixture(t)
	if h := f.d.HealthCheck(context.Background()); len(h) != 1 || !h[0].Ready {
		t.Fatalf("valid key: %+v", h)
	}
	// A key the provider does not know.
	f.tokens.SetServiceAccount(nil, saEmail)
	f2 := *f.d
	f2.keyHash = "other" // a fresh cache
	if h := f2.HealthCheck(context.Background()); len(h) != 1 || h[0].Ready || h[0].Message == "" {
		t.Fatalf("unknown key: %+v", h)
	}
}

func TestNewDriverRefusesBadKeys(t *testing.T) {
	for name, cfg := range map[string]*driver.GmailConfig{
		"missing":   nil,
		"not a key": {ServiceAccountJSON: []byte(`{"type":"authorized_user"}`)},
	} {
		if _, err := newDriver(driver.Config{Type: driver.TypeGmail, Gmail: cfg}, production); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

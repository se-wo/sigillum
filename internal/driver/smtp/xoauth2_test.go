package smtp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/se-wo/sigillum/internal/driver"
	"github.com/se-wo/sigillum/internal/oauth"
)

// tokenFunc is an oauth.Source for tests.
type tokenFunc func(ctx context.Context) (oauth.Token, error)

func (f tokenFunc) Token(ctx context.Context) (oauth.Token, error) { return f(ctx) }

func staticToken(tok string) oauth.Source {
	return tokenFunc(func(context.Context) (oauth.Token, error) {
		return oauth.Token{AccessToken: tok, Expiry: time.Now().Add(time.Hour)}, nil
	})
}

// xoauth2Server is a relay that offers AUTH XOAUTH2 and accepts exactly one
// mailbox and token. A wrong token gets the JSON error challenge and, after
// the client's empty response, 535, as Outlook.com answers.
type xoauth2Server struct {
	ln        net.Listener
	user, tok string

	mu        sync.Mutex
	conns     int
	authLines []string // decoded initial responses
	delivered int
}

func newXOAUTH2Server(t *testing.T, user, tok string) *xoauth2Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &xoauth2Server{ln: ln, user: user, tok: tok}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *xoauth2Server) port() int32 { return int32(s.ln.Addr().(*net.TCPAddr).Port) }

func (s *xoauth2Server) stats() (conns, delivered int, auth []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns, s.delivered, append([]string(nil), s.authLines...)
}

func (s *xoauth2Server) serve(c net.Conn) {
	defer c.Close()
	s.mu.Lock()
	s.conns++
	s.mu.Unlock()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	w := func(line string) { _, _ = c.Write([]byte(line + "\r\n")) }
	w("220 relay.localhost ESMTP")
	authed := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			w("250-relay.localhost")
			w("250 AUTH LOGIN XOAUTH2")
		case strings.HasPrefix(up, "AUTH XOAUTH2 "):
			raw, err := base64.StdEncoding.DecodeString(line[len("AUTH XOAUTH2 "):])
			if err != nil {
				w("501 5.5.2 bad base64")
				continue
			}
			s.mu.Lock()
			s.authLines = append(s.authLines, string(raw))
			s.mu.Unlock()
			if string(raw) == "user="+s.user+"\x01auth=Bearer "+s.tok+"\x01\x01" {
				authed = true
				w("235 2.7.0 Authentication successful")
				continue
			}
			w("334 " + base64.StdEncoding.EncodeToString(
				[]byte(`{"status":"401","schemes":"bearer","scope":"https://outlook.office.com/SMTP.Send"}`)))
			if resp, err := br.ReadString('\n'); err != nil || strings.TrimRight(resp, "\r\n") != "" {
				return
			}
			w("535 5.7.3 Authentication unsuccessful")
		case strings.HasPrefix(up, "MAIL FROM:"):
			if !authed {
				w("530 5.7.57 Client not authenticated")
				continue
			}
			w("250 OK")
		case strings.HasPrefix(up, "RCPT TO:"):
			w("250 OK")
		case up == "DATA":
			w("354 send")
			for {
				dl, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if dl == ".\r\n" {
					break
				}
			}
			s.mu.Lock()
			s.delivered++
			s.mu.Unlock()
			w("250 OK queued")
		case up == "QUIT":
			w("221 bye")
			return
		default:
			w("250 OK")
		}
	}
}

func newXOAUTH2Driver(t *testing.T, port int32, user string, tokens oauth.Source) driver.Driver {
	t.Helper()
	d, err := driver.New(driver.Config{Type: driver.TypeSMTP, SMTP: &driver.SMTPConfig{
		Endpoints: []driver.SMTPEndpoint{{Host: "127.0.0.1", Port: port, TLS: "none"}},
		AuthType:  AuthXOAUTH2, Username: user, Tokens: tokens, Timeout: 5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

var rawMsg = []byte("From: me@outlook.com\r\nTo: a@example.com\r\nSubject: x\r\n\r\nbody\r\n")

func TestXOAUTH2_SendsBearerToken(t *testing.T) {
	srv := newXOAUTH2Server(t, "me@outlook.com", "EwB.good-token_~+/=")
	d := newXOAUTH2Driver(t, srv.port(), "me@outlook.com", staticToken("EwB.good-token_~+/="))

	if _, err := d.(driver.RawSender).SendRaw(context.Background(), "me@outlook.com", []string{"a@example.com"}, rawMsg); err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	if _, delivered, auth := srv.stats(); delivered != 1 || len(auth) != 1 {
		t.Fatalf("delivered=%d auth=%q, want one authenticated delivery", delivered, auth)
	}
}

func TestXOAUTH2_RejectedTokenIsTransientAndNamesTheScope(t *testing.T) {
	srv := newXOAUTH2Server(t, "me@outlook.com", "right")
	d := newXOAUTH2Driver(t, srv.port(), "me@outlook.com", staticToken("wrong"))

	_, err := d.(driver.RawSender).SendRaw(context.Background(), "me@outlook.com", []string{"a@example.com"}, rawMsg)
	// Like a rejected password: the backend's sign-in is broken, not the
	// message, so clients keep the message and retry.
	if !errors.Is(err, driver.ErrUpstreamTransient) {
		t.Fatalf("want transient, got %v", err)
	}
	for _, want := range []string{"535", "status 401", "scope https://outlook.office.com/SMTP.Send"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if _, delivered, _ := srv.stats(); delivered != 0 {
		t.Fatal("a rejected token must not deliver")
	}
}

func TestXOAUTH2_TokenErrorsStopBeforeConnecting(t *testing.T) {
	cases := []struct {
		name string
		src  oauth.Source
		want error
	}{
		{"permanent token error", tokenFunc(func(context.Context) (oauth.Token, error) {
			return oauth.Token{}, &oauth.Error{Status: 400, Code: "invalid_client", Permanent: true}
		}), driver.ErrUpstreamPermanent},
		{"transient token error", tokenFunc(func(context.Context) (oauth.Token, error) {
			return oauth.Token{}, &oauth.Error{Status: 503}
		}), driver.ErrUpstreamTransient},
		{"no token yet", tokenFunc(func(context.Context) (oauth.Token, error) {
			return oauth.Token{}, errors.New("token Secret has no access token yet")
		}), driver.ErrUpstreamTransient},
		{"separator in token", staticToken("tok\x01auth=Bearer other"), driver.ErrUpstreamTransient},
		{"empty token", staticToken(""), driver.ErrUpstreamTransient},
		{"expired token", tokenFunc(func(context.Context) (oauth.Token, error) {
			return oauth.Token{AccessToken: "tok", Expiry: time.Now().Add(-time.Minute)}, nil
		}), driver.ErrUpstreamTransient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newXOAUTH2Server(t, "me@outlook.com", "tok")
			d := newXOAUTH2Driver(t, srv.port(), "me@outlook.com", tc.src)
			_, err := d.(driver.RawSender).SendRaw(context.Background(), "me@outlook.com", []string{"a@example.com"}, rawMsg)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if conns, _, _ := srv.stats(); conns != 0 {
				t.Fatalf("connected %d times without a usable token", conns)
			}
		})
	}
}

func TestXOAUTH2_OneTokenPerSend(t *testing.T) {
	srv := newXOAUTH2Server(t, "me@outlook.com", "tok")
	var calls int
	src := tokenFunc(func(context.Context) (oauth.Token, error) {
		calls++
		return oauth.Token{AccessToken: "tok"}, nil
	})
	down := rejectingServer(t, "421 4.3.2 not now")
	d, err := driver.New(driver.Config{Type: driver.TypeSMTP, SMTP: &driver.SMTPConfig{
		Endpoints: []driver.SMTPEndpoint{
			{Host: "127.0.0.1", Port: down, TLS: "none"},
			{Host: "127.0.0.1", Port: srv.port(), TLS: "none"},
		},
		AuthType: AuthXOAUTH2, Username: "me@outlook.com", Tokens: src, Timeout: 5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.(driver.RawSender).SendRaw(context.Background(), "me@outlook.com", []string{"a@example.com"}, rawMsg); err != nil {
		t.Fatalf("failover to the second endpoint: %v", err)
	}
	if calls != 1 {
		t.Fatalf("token fetched %d times for one send, want 1", calls)
	}
}

func TestXOAUTH2_HealthCheckNeedsAToken(t *testing.T) {
	srv := newXOAUTH2Server(t, "me@outlook.com", "tok")

	d := newXOAUTH2Driver(t, srv.port(), "me@outlook.com", staticToken("tok"))
	if h := d.HealthCheck(context.Background()); len(h) != 1 || !h[0].Ready {
		t.Fatalf("with a token: %+v", h)
	}

	d = newXOAUTH2Driver(t, srv.port(), "me@outlook.com", tokenFunc(func(context.Context) (oauth.Token, error) {
		return oauth.Token{}, errors.New("token Secret has no access token yet")
	}))
	h := d.HealthCheck(context.Background())
	if len(h) != 1 || h[0].Ready || !strings.Contains(h[0].Message, "no access token yet") || h[0].Port != srv.port() {
		t.Fatalf("without a token: %+v", h)
	}
}

func TestXOAUTH2_Start(t *testing.T) {
	a := xoauth2Auth{username: "me@outlook.com", token: "tok"}
	if _, _, err := a.Start(&smtp.ServerInfo{Name: "smtp-mail.outlook.com", Auth: []string{"XOAUTH2"}}); err == nil ||
		!strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("plaintext to a remote relay must be refused, got %v", err)
	}
	if _, _, err := a.Start(&smtp.ServerInfo{Name: "smtp-mail.outlook.com", TLS: true, Auth: []string{"LOGIN", "PLAIN"}}); err == nil ||
		!strings.Contains(err.Error(), "does not offer AUTH XOAUTH2") {
		t.Fatalf("a relay without XOAUTH2 must be refused, got %v", err)
	}
	mech, resp, err := a.Start(&smtp.ServerInfo{Name: "smtp-mail.outlook.com", TLS: true, Auth: []string{"LOGIN", "xoauth2"}})
	if err != nil || mech != "XOAUTH2" || string(resp) != "user=me@outlook.com\x01auth=Bearer tok\x01\x01" {
		t.Fatalf("Start = %q, %q, %v", mech, resp, err)
	}
	if next, err := a.Next([]byte("235 ok"), false); next != nil || err != nil {
		t.Fatalf("Next after success = %q, %v", next, err)
	}
}

// TestXOAUTH2_OverSTARTTLS runs the exchange after a real TLS upgrade, the
// path an Outlook.com backend takes, and checks that AUTH is only sent on
// the encrypted connection.
func TestXOAUTH2_OverSTARTTLS(t *testing.T) {
	cert := selfSignedCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		var conn net.Conn = c
		br := bufio.NewReader(conn)
		w := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
		w("220 relay ESMTP")
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			up := strings.ToUpper(strings.TrimRight(line, "\r\n"))
			switch {
			case strings.HasPrefix(up, "EHLO"):
				if _, ok := conn.(*tls.Conn); ok {
					w("250-relay")
					w("250 AUTH XOAUTH2")
				} else {
					w("250-relay")
					w("250 STARTTLS")
				}
			case up == "STARTTLS":
				w("220 go ahead")
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				conn, br = tc, bufio.NewReader(tc)
				w = func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
			case strings.HasPrefix(up, "AUTH XOAUTH2 "):
				if _, ok := conn.(*tls.Conn); !ok {
					got <- "AUTH before STARTTLS"
					return
				}
				raw, _ := base64.StdEncoding.DecodeString(strings.TrimRight(line, "\r\n")[len("AUTH XOAUTH2 "):])
				got <- string(raw)
				w("235 ok")
			case up == "DATA":
				w("354 go")
				for {
					dl, err := br.ReadString('\n')
					if err != nil || dl == ".\r\n" {
						break
					}
				}
				w("250 queued")
			case up == "QUIT":
				w("221 bye")
				return
			default:
				w("250 ok")
			}
		}
	}()

	// The certificate is self-signed, so verification is skipped.
	d, err := driver.New(driver.Config{Type: driver.TypeSMTP, SMTP: &driver.SMTPConfig{
		Endpoints: []driver.SMTPEndpoint{{Host: "127.0.0.1", Port: int32(ln.Addr().(*net.TCPAddr).Port), TLS: "starttls", InsecureSkipVerify: true}},
		AuthType:  AuthXOAUTH2, Username: "me@outlook.com", Tokens: staticToken("tok"), Timeout: 5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.(driver.RawSender).SendRaw(context.Background(), "me@outlook.com", []string{"a@example.com"}, rawMsg); err != nil {
		t.Fatalf("SendRaw over STARTTLS: %v", err)
	}
	if s := <-got; s != "user=me@outlook.com\x01auth=Bearer tok\x01\x01" {
		t.Fatalf("initial response %q", s)
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay.test"},
		DNSNames:     []string{"relay.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestXOAUTH2_ConfigValidation(t *testing.T) {
	ep := []driver.SMTPEndpoint{{Host: "smtp-mail.outlook.com", Port: 587, TLS: "starttls"}}
	for name, cfg := range map[string]driver.SMTPConfig{
		"no token source":   {Endpoints: ep, AuthType: AuthXOAUTH2, Username: "me@outlook.com"},
		"no username":       {Endpoints: ep, AuthType: AuthXOAUTH2, Tokens: staticToken("t")},
		"separator in user": {Endpoints: ep, AuthType: AuthXOAUTH2, Username: "me@outlook.com\x01auth=x", Tokens: staticToken("t")},
		"space in user":     {Endpoints: ep, AuthType: AuthXOAUTH2, Username: "me @outlook.com", Tokens: staticToken("t")},
		"non-ASCII user":    {Endpoints: ep, AuthType: AuthXOAUTH2, Username: "jörg@outlook.com", Tokens: staticToken("t")},
		"user of 321 bytes": {Endpoints: ep, AuthType: AuthXOAUTH2, Username: strings.Repeat("a", 309) + "@outlook.com", Tokens: staticToken("t")},
	} {
		if _, err := driver.New(driver.Config{Type: driver.TypeSMTP, SMTP: &cfg}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDescribeXOAUTH2Error(t *testing.T) {
	for in, want := range map[string]string{
		`{"status":"401","schemes":"bearer","scope":"https://outlook.office.com/SMTP.Send"}`: "status 401, scope https://outlook.office.com/SMTP.Send",
		`{"status":"400","schemes":"Bearer"}`:                                                "status 400",
		`{"status":"401\r\n550 fake"}`:                                                       "status 401??550 fake",
		`not json`:                                                                           "",
		`{}`:                                                                                 "",
	} {
		if got := describeXOAUTH2Error([]byte(in)); got != want {
			t.Errorf("describeXOAUTH2Error(%q) = %q, want %q", in, got, want)
		}
	}
}

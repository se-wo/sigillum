package smtp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/se-wo/sigillum/internal/driver"
)

// fakeSMTP is a minimal RFC-5321 listener — enough for our driver to push a
// message through. It captures the parsed envelope + DATA and exposes both for
// assertions.
type fakeSMTP struct {
	listener net.Listener
	mu       sync.Mutex
	envelope []envelope
}

type envelope struct {
	from string
	to   []string
	data []byte
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{listener: ln}
	go f.accept()
	return f
}

func (f *fakeSMTP) addr() string { return f.listener.Addr().String() }

func (f *fakeSMTP) port() int32 {
	_, p, _ := net.SplitHostPort(f.listener.Addr().String())
	var n int
	fmt.Sscanf(p, "%d", &n)
	return int32(n)
}

func (f *fakeSMTP) accept() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.serve(conn)
	}
}

func (f *fakeSMTP) close() { _ = f.listener.Close() }

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }

	w("220 fake.localhost ESMTP")

	var env envelope
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			// Single-line response — STARTTLS not advertised, simpler to test.
			w("250 fake.localhost")
		case strings.HasPrefix(up, "MAIL FROM:"):
			env.from = strings.TrimSpace(line[len("MAIL FROM:"):])
			env.from = strings.Trim(env.from, "<>")
			w("250 OK")
		case strings.HasPrefix(up, "RCPT TO:"):
			rcpt := strings.TrimSpace(line[len("RCPT TO:"):])
			rcpt = strings.Trim(rcpt, "<>")
			switch {
			case strings.HasPrefix(rcpt, "reject@"):
				w("550 5.1.1 no such user")
				continue
			case strings.HasPrefix(rcpt, "busy@"):
				w("451 4.3.0 try later")
				continue
			case strings.HasPrefix(rcpt, "toomany@"):
				w("452 4.5.3 Too many recipients")
				continue
			}
			env.to = append(env.to, rcpt)
			w("250 OK")
		case up == "DATA":
			w("354 send")
			var buf bytes.Buffer
			for {
				dl, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if dl == ".\r\n" || dl == ".\n" {
					break
				}
				buf.WriteString(dl)
			}
			env.data = buf.Bytes()
			w("250 OK")
			f.mu.Lock()
			f.envelope = append(f.envelope, env)
			f.mu.Unlock()
			env = envelope{}
		case up == "QUIT":
			w("221 bye")
			return
		case up == "RSET":
			env = envelope{}
			w("250 OK")
		default:
			w("250 OK")
		}
	}
}

func (f *fakeSMTP) lastEnvelope() (envelope, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.envelope) == 0 {
		return envelope{}, false
	}
	return f.envelope[len(f.envelope)-1], true
}

func TestSMTPDriver_SendEndToEnd(t *testing.T) {
	srv := newFakeSMTP(t)
	defer srv.close()

	d, err := driver.New(driver.Config{
		Type: driver.TypeSMTP,
		SMTP: &driver.SMTPConfig{
			Endpoints: []driver.SMTPEndpoint{{Host: "127.0.0.1", Port: srv.port(), TLS: "none"}},
			AuthType:  "NONE",
			Timeout:   5,
			Helo:      "test.local",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	msg := &driver.Message{
		From:    driver.Address{Address: "alice@example.com"},
		To:      []driver.Address{{Address: "bob@example.com"}},
		Subject: "hi",
		Body:    driver.Body{Text: "the body"},
	}
	res, err := d.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if res.UpstreamID == "" {
		t.Fatal("expected upstream id")
	}
	env, ok := srv.lastEnvelope()
	if !ok {
		t.Fatal("server received nothing")
	}
	if env.from != "alice@example.com" {
		t.Fatalf("from: %q", env.from)
	}
	if len(env.to) != 1 || env.to[0] != "bob@example.com" {
		t.Fatalf("to: %v", env.to)
	}
	if !bytes.Contains(env.data, []byte("the body")) {
		t.Fatalf("body not in DATA: %q", env.data)
	}
	if !bytes.Contains(env.data, []byte("From: alice@example.com")) {
		t.Fatalf("missing From header: %q", env.data)
	}
}

func TestSMTPDriver_FailoverPicksSecondEndpoint(t *testing.T) {
	// First endpoint points at a closed socket; second is the real fake server.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()

	srv := newFakeSMTP(t)
	defer srv.close()

	_, deadPort, _ := net.SplitHostPort(deadAddr)
	var deadP int32
	fmt.Sscanf(deadPort, "%d", &deadP)

	d, err := driver.New(driver.Config{
		Type: driver.TypeSMTP,
		SMTP: &driver.SMTPConfig{
			Endpoints: []driver.SMTPEndpoint{
				{Host: "127.0.0.1", Port: deadP, TLS: "none"},
				{Host: "127.0.0.1", Port: srv.port(), TLS: "none"},
			},
			AuthType: "NONE",
			Timeout:  2,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	_, err = d.Send(context.Background(), &driver.Message{
		From: driver.Address{Address: "a@x"},
		To:   []driver.Address{{Address: "b@y"}},
		Body: driver.Body{Text: "hi"},
	})
	if err != nil {
		t.Fatalf("expected failover success, got %v", err)
	}
	if _, ok := srv.lastEnvelope(); !ok {
		t.Fatal("second endpoint should have received the message")
	}
}

// dialPing exercises driver.HealthCheck against a live socket.
func TestSMTPDriver_HealthCheckMarksReady(t *testing.T) {
	srv := newFakeSMTP(t)
	defer srv.close()

	d, _ := driver.New(driver.Config{
		Type: driver.TypeSMTP,
		SMTP: &driver.SMTPConfig{
			Endpoints: []driver.SMTPEndpoint{{Host: "127.0.0.1", Port: srv.port(), TLS: "none"}},
			Timeout:   2,
		},
	})
	defer d.Close()

	res := d.HealthCheck(context.Background())
	if len(res) != 1 || !res[0].Ready {
		t.Fatalf("want ready, got %+v", res)
	}
}

// Ensures Send returns ErrUpstreamTransient when all endpoints time out.
func TestSMTPDriver_AllDownReturnsTransient(t *testing.T) {
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := dead.Addr().String()
	dead.Close()
	_, port, _ := net.SplitHostPort(addr)
	var p int32
	fmt.Sscanf(port, "%d", &p)

	d, _ := driver.New(driver.Config{
		Type: driver.TypeSMTP,
		SMTP: &driver.SMTPConfig{
			Endpoints: []driver.SMTPEndpoint{{Host: "127.0.0.1", Port: p, TLS: "none"}},
			Timeout:   1,
		},
	})
	defer d.Close()
	_, err := d.Send(context.Background(), &driver.Message{
		From: driver.Address{Address: "a@x"},
		To:   []driver.Address{{Address: "b@y"}},
		Body: driver.Body{Text: "x"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "upstream") {
		t.Fatalf("expected upstream error, got %v", err)
	}
}

var _ = io.EOF

func newTestDriver(t *testing.T, port int32) driver.Driver {
	t.Helper()
	d, err := driver.New(driver.Config{
		Type: driver.TypeSMTP,
		SMTP: &driver.SMTPConfig{
			Endpoints: []driver.SMTPEndpoint{{Host: "127.0.0.1", Port: port, TLS: "none"}},
			AuthType:  "NONE",
			Timeout:   5,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSMTPDriver_SendRawRelaysUnchanged(t *testing.T) {
	srv := newFakeSMTP(t)
	defer srv.close()
	d := newTestDriver(t, srv.port())

	raw := []byte("From: legacy@app.example\r\nTo: a@x.example\r\nSubject: raw\r\nX-Custom: kept\r\n\r\n.leading dot\r\nbody\r\n")
	if _, err := d.(driver.RawSender).SendRaw(context.Background(), "bounce@app.example",
		[]string{"a@x.example", "hidden@x.example"}, raw); err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	env, _ := srv.lastEnvelope()
	if env.from != "bounce@app.example" || len(env.to) != 2 {
		t.Fatalf("envelope not preserved: %+v", env)
	}
	// The fake server does not undo dot-stuffing, so the leading dot arrives doubled.
	if !bytes.Contains(env.data, []byte("X-Custom: kept")) || !bytes.Contains(env.data, []byte("..leading dot")) {
		t.Fatalf("raw message altered: %q", env.data)
	}
}

func TestSMTPDriver_UpstreamReplyClassification(t *testing.T) {
	srv := newFakeSMTP(t)
	defer srv.close()
	d := newTestDriver(t, srv.port())
	raw := []byte("Subject: x\r\n\r\nbody\r\n")

	_, err := d.(driver.RawSender).SendRaw(context.Background(), "a@x.example", []string{"reject@x.example"}, raw)
	if !errors.Is(err, driver.ErrUpstreamPermanent) {
		t.Fatalf("5xx must be permanent, got %v", err)
	}
	_, err = d.(driver.RawSender).SendRaw(context.Background(), "a@x.example", []string{"busy@x.example"}, raw)
	if !errors.Is(err, driver.ErrUpstreamTransient) {
		t.Fatalf("4xx must be transient, got %v", err)
	}
	// 452 4.5.3 (too many recipients) is permanent for this message: the
	// same recipients fail the same way on every retry (#62).
	_, err = d.(driver.RawSender).SendRaw(context.Background(), "a@x.example", []string{"toomany@x.example"}, raw)
	if !errors.Is(err, driver.ErrUpstreamPermanent) {
		t.Fatalf("452 4.5.3 must be permanent, got %v", err)
	}
}

func TestIsTooManyRecipients(t *testing.T) {
	for msg, want := range map[string]bool{
		"4.5.3 Too many recipients": true,
		"Too many recipients":       true,
		"too many recipient":        true,
		"4.2.2 Mailbox full":        false,
		"4.3.0 try later":           false,
	} {
		if got := isTooManyRecipients(msg); got != want {
			t.Errorf("isTooManyRecipients(%q) = %v, want %v", msg, got, want)
		}
	}
}

// rejectingServer greets with a 5xx, as a misconfigured or hostile relay would.
func rejectingServer(t *testing.T, greeting string) int32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(greeting + "\r\n"))
			_ = c.Close()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	var n int
	fmt.Sscanf(p, "%d", &n)
	return int32(n)
}

func TestSMTPDriver_HandshakeRejectionIsTransient(t *testing.T) {
	d := newTestDriver(t, rejectingServer(t, "554 5.7.1 go away"))
	_, err := d.(driver.RawSender).SendRaw(context.Background(), "a@x.example", []string{"b@x.example"},
		[]byte("Subject: x\r\n\r\nbody\r\n"))
	if !errors.Is(err, driver.ErrUpstreamTransient) {
		t.Fatalf("a 5xx before MAIL reflects backend config, not the message; want transient, got %v", err)
	}
}

// stallingServer accepts the SMTP conversation and never answers the final dot.
func stallingServer(t *testing.T) (port int32, dataSeen chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	dataSeen = make(chan struct{}, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
				w("220 slow ESMTP")
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					switch up := strings.ToUpper(strings.TrimSpace(line)); {
					case up == "DATA":
						w("354 go ahead")
					case up == ".":
						dataSeen <- struct{}{}
						time.Sleep(10 * time.Second) // never acknowledge
						return
					case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"),
						strings.HasPrefix(up, "MAIL"), strings.HasPrefix(up, "RCPT"):
						w("250 ok")
					}
				}
			}(c)
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	var n int
	fmt.Sscanf(p, "%d", &n)
	return int32(n), dataSeen
}

func TestSMTPDriver_StalledRelayHonoursDeadlineAndDoesNotFailOver(t *testing.T) {
	stalled, dataSeen := stallingServer(t)
	second := newFakeSMTP(t)
	defer second.close()
	d, err := driver.New(driver.Config{Type: driver.TypeSMTP, SMTP: &driver.SMTPConfig{
		Endpoints: []driver.SMTPEndpoint{
			{Host: "127.0.0.1", Port: stalled, TLS: "none"},
			{Host: "127.0.0.1", Port: second.port(), TLS: "none"},
		},
		AuthType: "NONE", Timeout: 5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = d.(driver.RawSender).SendRaw(ctx, "a@x.example", []string{"b@x.example"}, []byte("Subject: x\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("want an error from the stalled relay")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("send must honour the context deadline, took %v", elapsed)
	}
	<-dataSeen
	if _, ok := second.lastEnvelope(); ok {
		t.Fatal("after the first relay received the whole message, it must not be re-sent to the next endpoint")
	}
	if !errors.Is(err, driver.ErrUpstreamTransient) {
		t.Fatalf("a lost final reply is transient, got %v", err)
	}
}

// silentServer accepts connections and never sends the 220 banner, like a
// hung relay or a load balancer with no healthy backend behind it (#61).
func silentServer(t *testing.T) int32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { <-done; _ = c.Close() }()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	var n int
	fmt.Sscanf(p, "%d", &n)
	return int32(n)
}

// A relay that accepts the connection and never greets costs one
// connectionTimeoutSeconds, not the whole send budget, and the next
// endpoint delivers.
func TestSMTPDriver_SilentEndpointFailsOverWithinConnectionTimeout(t *testing.T) {
	second := newFakeSMTP(t)
	defer second.close()
	d, err := driver.New(driver.Config{Type: driver.TypeSMTP, SMTP: &driver.SMTPConfig{
		Endpoints: []driver.SMTPEndpoint{
			{Host: "127.0.0.1", Port: silentServer(t), TLS: "none"},
			{Host: "127.0.0.1", Port: second.port(), TLS: "none"},
		},
		AuthType: "NONE", Timeout: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := d.(driver.RawSender).SendRaw(ctx, "a@x.example", []string{"b@x.example"}, []byte("Subject: x\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("want failover to the second endpoint, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("a silent endpoint must cost about connectionTimeoutSeconds (1 s), took %v", elapsed)
	}
	if _, ok := second.lastEnvelope(); !ok {
		t.Fatal("second endpoint should have received the message")
	}
}

// Cancelling the caller's context (the REST client went away) unblocks a
// conversation that has no deadline of its own.
func TestSMTPDriver_CancelUnblocksSend(t *testing.T) {
	stalled, _ := stallingServer(t)
	d, err := driver.New(driver.Config{Type: driver.TypeSMTP, SMTP: &driver.SMTPConfig{
		Endpoints: []driver.SMTPEndpoint{{Host: "127.0.0.1", Port: stalled, TLS: "none"}},
		AuthType:  "NONE", Timeout: 5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	if _, err := d.(driver.RawSender).SendRaw(ctx, "a@x.example", []string{"b@x.example"}, []byte("Subject: x\r\n\r\nbody\r\n")); err == nil {
		t.Fatal("want an error after cancellation")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("cancellation must stop the send, took %v", elapsed)
	}
}

// authAdvertisingServer greets and, on EHLO, advertises the given AUTH
// mechanisms (empty = no AUTH line). Plaintext, for probe tests.
func authAdvertisingServer(t *testing.T, mechs string) int32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
				w("220 fake ESMTP")
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					switch up := strings.ToUpper(strings.TrimSpace(line)); {
					case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
						if mechs != "" {
							w("250-fake")
							w("250 AUTH " + mechs)
						} else {
							w("250 fake")
						}
					case up == "QUIT":
						w("221 bye")
						return
					default:
						w("250 OK")
					}
				}
			}(c)
		}
	}()
	return int32(ln.Addr().(*net.TCPAddr).Port)
}

// #58: the probe is not Ready when the relay does not advertise the
// configured SASL mechanism, and Ready when it does.
func TestSMTPDriver_ProbeChecksAuthMechanism(t *testing.T) {
	newD := func(port int32, auth string) driver.Driver {
		d, err := driver.New(driver.Config{Type: driver.TypeSMTP, SMTP: &driver.SMTPConfig{
			Endpoints: []driver.SMTPEndpoint{{Host: "127.0.0.1", Port: port, TLS: "none"}},
			AuthType:  auth, Timeout: 3,
		}})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	// CRAM-MD5 configured, relay offers only PLAIN LOGIN -> not Ready.
	h := newD(authAdvertisingServer(t, "PLAIN LOGIN"), "CRAM-MD5").HealthCheck(context.Background())
	if h[0].Ready || !strings.Contains(h[0].Message, "does not offer AUTH CRAM-MD5") {
		t.Fatalf("want not Ready naming the missing mechanism, got %+v", h[0])
	}
	// PLAIN configured and offered -> Ready.
	if h := newD(authAdvertisingServer(t, "PLAIN LOGIN"), "PLAIN").HealthCheck(context.Background()); !h[0].Ready {
		t.Fatalf("want Ready when PLAIN is offered, got %+v", h[0])
	}
	// Relay advertises no AUTH at all, auth required -> not Ready.
	if h := newD(authAdvertisingServer(t, ""), "PLAIN").HealthCheck(context.Background()); h[0].Ready {
		t.Fatalf("want not Ready when the relay offers no AUTH, got %+v", h[0])
	}
	// authType NONE never checks AUTH -> Ready.
	if h := newD(authAdvertisingServer(t, ""), "NONE").HealthCheck(context.Background()); !h[0].Ready {
		t.Fatalf("want Ready for authType NONE, got %+v", h[0])
	}
}

func TestAuthMechOffered(t *testing.T) {
	if !authMechOffered("PLAIN LOGIN CRAM-MD5", "cram-md5") {
		t.Fatal("case-insensitive match expected")
	}
	if authMechOffered("PLAIN LOGIN", "CRAM-MD5") {
		t.Fatal("CRAM-MD5 is not in the list")
	}
	if authMechOffered("", "PLAIN") {
		t.Fatal("empty list offers nothing")
	}
}

// #43: AUTH over a cleartext (tls: none) endpoint is refused before any
// credential is sent, and is permanent so the caller stops retrying.
func TestSMTPDriver_AuthOverCleartextIsRefused(t *testing.T) {
	// A server that records whether it ever saw an AUTH command.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	sawAuth := make(chan struct{}, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
				w("220 fake ESMTP")
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					up := strings.ToUpper(strings.TrimSpace(line))
					switch {
					case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
						w("250-fake")
						w("250 AUTH PLAIN LOGIN")
					case strings.HasPrefix(up, "AUTH"):
						select {
						case sawAuth <- struct{}{}:
						default:
						}
						w("235 ok")
					case up == "QUIT":
						w("221 bye")
						return
					default:
						w("250 OK")
					}
				}
			}(c)
		}
	}()
	port := int32(ln.Addr().(*net.TCPAddr).Port)

	for _, mech := range []string{"PLAIN", "LOGIN"} {
		d, err := driver.New(driver.Config{Type: driver.TypeSMTP, BackendKey: "/b", SMTP: &driver.SMTPConfig{
			Endpoints: []driver.SMTPEndpoint{{Host: "127.0.0.1", Port: port, TLS: "none"}},
			AuthType:  mech, Username: "u", Password: "secret", Timeout: 3,
		}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = d.(driver.RawSender).SendRaw(context.Background(), "a@x.example", []string{"b@x.example"}, []byte("Subject: x\r\n\r\nbody\r\n"))
		if err == nil || !errors.Is(err, driver.ErrUpstreamPermanent) {
			t.Fatalf("%s over tls:none must fail permanently, got %v", mech, err)
		}
		if !strings.Contains(err.Error(), "cleartext") {
			t.Fatalf("%s: want a cleartext-refusal message, got %v", mech, err)
		}
	}
	select {
	case <-sawAuth:
		t.Fatal("no AUTH command must reach the relay over a cleartext connection")
	default:
	}
}

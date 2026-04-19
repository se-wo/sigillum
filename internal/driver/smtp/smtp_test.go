package smtp

import (
	"bufio"
	"bytes"
	"context"
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

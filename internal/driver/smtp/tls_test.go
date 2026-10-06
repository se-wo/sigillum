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
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/se-wo/sigillum/internal/driver"
)

// privateCA returns a CA certificate and a server certificate for
// 127.0.0.1 that it issued.
func privateCA(t *testing.T) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Corp CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "relay"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, ca, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return ca, tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}
}

// tlsRelay is a minimal relay that offers STARTTLS (implicit=false) or
// speaks TLS from the start (implicit=true) and accepts every message.
func tlsRelay(t *testing.T, cert tls.Certificate, implicit bool) (port int32, delivered chan string) {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	var ln net.Listener
	var err error
	if implicit {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", cfg)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	delivered = make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, secure := c.(*tls.Conn)
				br := bufio.NewReader(c)
				w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
				w("220 relay ESMTP")
				var data strings.Builder
				inData := false
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if inData {
						if line == ".\r\n" {
							inData = false
							delivered <- data.String()
							w("250 queued")
							continue
						}
						data.WriteString(line)
						continue
					}
					switch up := strings.ToUpper(strings.TrimSpace(line)); {
					case strings.HasPrefix(up, "EHLO"):
						if secure {
							w("250 relay")
						} else {
							w("250-relay")
							w("250 STARTTLS")
						}
					case up == "STARTTLS":
						w("220 go ahead")
						tc := tls.Server(c, cfg)
						if tc.Handshake() != nil {
							return
						}
						c, secure, br = tc, true, bufio.NewReader(tc)
						w = func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
					case up == "DATA":
						inData = true
						w("354 go ahead")
					case up == "QUIT":
						w("221 bye")
						return
					default:
						w("250 ok")
					}
				}
			}(c)
		}
	}()
	return int32(ln.Addr().(*net.TCPAddr).Port), delivered
}

// #57: a relay with a certificate from a private CA is trusted only with
// that CA in RootCAs, over STARTTLS and implicit TLS, for sends and probes.
func TestSMTPDriver_PrivateCA(t *testing.T) {
	ca, cert := privateCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	for _, mode := range []string{"starttls", "tls"} {
		port, delivered := tlsRelay(t, cert, mode == "tls")
		build := func(roots *x509.CertPool) driver.Driver {
			d, err := driver.New(driver.Config{Type: driver.TypeSMTP, SMTP: &driver.SMTPConfig{
				Endpoints: []driver.SMTPEndpoint{{Host: "127.0.0.1", Port: port, TLS: mode}},
				AuthType:  "NONE", Timeout: 5, RootCAs: roots,
			}})
			if err != nil {
				t.Fatal(err)
			}
			return d
		}
		raw := []byte("Subject: x\r\n\r\nbody\r\n")

		untrusted := build(nil)
		if h := untrusted.HealthCheck(context.Background()); h[0].Ready || !strings.Contains(h[0].Message, "unknown authority") {
			t.Fatalf("%s: without the CA the probe must fail verification, got %+v", mode, h)
		}
		if _, err := untrusted.(driver.RawSender).SendRaw(context.Background(), "a@x.example", []string{"b@x.example"}, raw); err == nil {
			t.Fatalf("%s: without the CA the send must fail", mode)
		}

		trusted := build(pool)
		if h := trusted.HealthCheck(context.Background()); !h[0].Ready {
			t.Fatalf("%s: with the CA the probe must pass, got %+v", mode, h)
		}
		if _, err := trusted.(driver.RawSender).SendRaw(context.Background(), "a@x.example", []string{"b@x.example"}, raw); err != nil {
			t.Fatalf("%s: with the CA the send must succeed, got %v", mode, err)
		}
		select {
		case got := <-delivered:
			if !strings.Contains(got, "body") {
				t.Fatalf("%s: unexpected message %q", mode, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: nothing delivered", mode)
		}
	}
}

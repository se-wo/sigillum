package tlsreload

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a self-signed certificate with the given serial.
func writePair(t *testing.T, certFile, keyFile string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// servedSerial completes a handshake with addr and returns the serial of
// the certificate it presented.
func servedSerial(t *testing.T, addr string) int64 {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the test reads the served certificate
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

// #75: a renewed certificate is served to new handshakes without a restart.
func TestReloaderServesRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, certFile, keyFile, 1)
	r, err := New(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", r.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, 20*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if got := servedSerial(t, ln.Addr().String()); got != 1 {
		t.Fatalf("want serial 1, got %d", got)
	}
	writePair(t, certFile, keyFile, 2)
	deadline := time.Now().Add(5 * time.Second)
	for servedSerial(t, ln.Addr().String()) != 2 {
		if time.Now().After(deadline) {
			t.Fatal("the renewed certificate was not picked up")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A half-written renewal (new certificate, old key) keeps the previous pair.
func TestReloaderKeepsPairOnMismatch(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, certFile, keyFile, 1)
	r, err := New(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, _ := os.ReadFile(keyFile)
	writePair(t, certFile, keyFile, 2)
	if err := os.WriteFile(keyFile, oldKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reload(); err == nil {
		t.Fatal("want an error for a mismatched pair")
	}
	cert, _ := r.GetCertificate(nil)
	if cert.Leaf.SerialNumber.Int64() != 1 {
		t.Fatalf("the previous pair must stay in use, got serial %d", cert.Leaf.SerialNumber.Int64())
	}
}

func TestNewFailsOnMissingFiles(t *testing.T) {
	if _, err := New("/nonexistent/tls.crt", "/nonexistent/tls.key"); err == nil {
		t.Fatal("want an error")
	}
}

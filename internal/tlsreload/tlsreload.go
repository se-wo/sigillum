// Package tlsreload serves a certificate pair from files and picks up
// renewals without a restart. The files are typically a mounted Secret
// that cert-manager renews; the kubelet swaps them in place.
package tlsreload

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Interval is how often the files are checked for changes.
const Interval = 10 * time.Second

// Reloader holds the current certificate pair.
type Reloader struct {
	certFile, keyFile string

	mu      sync.RWMutex
	cert    *tls.Certificate
	certPEM []byte
	keyPEM  []byte
}

// New loads the pair once; an error means the files are missing or do not
// form a valid pair.
func New(certFile, keyFile string) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile}
	if _, err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload reads both files and swaps in the pair if it changed. It reports
// whether it did. On an error (for example a certificate already replaced
// while its key is not yet) the previous pair stays in use.
func (r *Reloader) Reload() (bool, error) {
	certPEM, err := os.ReadFile(r.certFile)
	if err != nil {
		return false, err
	}
	keyPEM, err := os.ReadFile(r.keyFile)
	if err != nil {
		return false, err
	}
	r.mu.RLock()
	same := bytes.Equal(certPEM, r.certPEM) && bytes.Equal(keyPEM, r.keyPEM)
	r.mu.RUnlock()
	if same {
		return false, nil
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return false, fmt.Errorf("load TLS certificate %s: %w", r.certFile, err)
	}
	if pair.Leaf == nil {
		if pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return false, fmt.Errorf("parse TLS certificate %s: %w", r.certFile, err)
		}
	}
	r.mu.Lock()
	r.cert, r.certPEM, r.keyPEM = &pair, certPEM, keyPEM
	r.mu.Unlock()
	return true, nil
}

// Run checks the files every interval until ctx ends.
func (r *Reloader) Run(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		changed, err := r.Reload()
		switch {
		case err != nil:
			logger.Warn("TLS certificate reload failed; serving the previous certificate", "file", r.certFile, "err", err)
		case changed:
			r.mu.RLock()
			leaf := r.cert.Leaf
			r.mu.RUnlock()
			logger.Info("TLS certificate reloaded", "file", r.certFile, "subject", leaf.Subject.String(),
				"not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
		}
	}
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// TLSConfig returns a server configuration that always presents the
// current certificate.
func (r *Reloader) TLSConfig() *tls.Config {
	return &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS12}
}

// FromEnv starts a Reloader for SIGILLUM_TLS_CERT and SIGILLUM_TLS_KEY and
// returns its configuration, or nil when TLS is not configured.
func FromEnv(ctx context.Context, logger *slog.Logger) (*tls.Config, error) {
	cert, key := os.Getenv("SIGILLUM_TLS_CERT"), os.Getenv("SIGILLUM_TLS_KEY")
	if cert == "" || key == "" {
		return nil, nil
	}
	r, err := New(cert, key)
	if err != nil {
		return nil, err
	}
	go r.Run(ctx, Interval, logger)
	return r.TLSConfig(), nil
}

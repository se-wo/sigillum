package smtpproxy

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/codes"

	"github.com/se-wo/sigillum/internal/audit"
	"github.com/se-wo/sigillum/internal/credential"
	"github.com/se-wo/sigillum/internal/gateway"
	"github.com/se-wo/sigillum/internal/telemetry"
)

// CredentialVerifier checks AUTH PLAIN / LOGIN against MailCredentials
// (US-3.7).
type CredentialVerifier interface {
	Verify(ctx context.Context, username, password string) (*credential.Result, error)
	StillValid(ctx context.Context, r *credential.Result) bool
}

var (
	errInvalidCredentials = &smtp.SMTPError{
		Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8},
		Message: "Authentication credentials invalid",
	}
	errEncryptionRequired = &smtp.SMTPError{
		Code: 538, EnhancedCode: smtp.EnhancedCode{5, 7, 11},
		Message: "Encryption required for requested authentication mechanism (use STARTTLS)",
	}
	errAuthThrottled = &smtp.SMTPError{
		Code: 454, EnhancedCode: smtp.EnhancedCode{4, 7, 0},
		Message: "Too many failed authentication attempts, try again later",
	}
	errAuthUnavailable = &smtp.SMTPError{
		Code: 454, EnhancedCode: smtp.EnhancedCode{4, 7, 0},
		Message: "Temporary authentication failure",
	}
	errCredentialRevoked = &smtp.SMTPError{
		Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0},
		Message: "Credential no longer valid; reconnect and authenticate again",
	}
)

// credentialAuthAllowed reports whether PLAIN and LOGIN may be offered on
// this connection. A static password can be replayed for months, so unlike
// tokens it requires TLS unless explicitly allowed (mesh mTLS).
func (s *session) credentialAuthAllowed() bool {
	return s.b.Credentials != nil && (s.isTLS() || s.b.AllowInsecureCredentialAuth)
}

func (s *session) isTLS() bool {
	if s.conn == nil {
		return false
	}
	_, ok := s.conn.TLSConnectionState()
	return ok
}

// credentialAuth returns the SASL server for PLAIN or LOGIN.
func (s *session) credentialAuth(mech string) (sasl.Server, error) {
	if s.b.Credentials == nil {
		return nil, smtp.ErrAuthUnknownMechanism
	}
	if !s.credentialAuthAllowed() {
		return nil, errEncryptionRequired
	}
	if mech == sasl.Plain {
		return authFailedAs535{sasl.NewPlainServer(func(identity, username, password string) error {
			// The authorization identity must be empty or the user itself:
			// a credential never acts for another identity.
			if identity != "" && identity != username {
				s.b.AuthFailures.Fail(username, s.remoteIP)
				s.authFailed(username, "invalid_credentials")
				return errInvalidCredentials
			}
			return s.credentialLogin(username, password)
		})}, nil
	}
	return authFailedAs535{&loginServer{authenticate: s.credentialLogin}}, nil
}

// credentialLogin verifies one username/password pair and, on success,
// sets the session identity to the credential's ServiceAccount.
func (s *session) credentialLogin(username, password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.b.AuthTimeout)
	defer cancel()
	ctx, span := telemetry.Tracer().Start(ctx, "auth.credential")
	defer span.End()

	if s.b.AuthFailures.Blocked(username, s.remoteIP) {
		span.SetStatus(codes.Error, "throttled")
		s.authFailed(username, "auth_rate_limited")
		return errAuthThrottled
	}
	res, err := s.b.Credentials.Verify(ctx, username, password)
	if err != nil {
		span.SetStatus(codes.Error, "credential rejected")
		if !errors.Is(err, credential.ErrInvalid) {
			s.b.Logger.Warn("smtp credential lookup failed", "remote_ip", s.remoteIP, "err", err)
			s.authFailed(username, "auth_unavailable")
			return errAuthUnavailable
		}
		s.b.AuthFailures.Fail(username, s.remoteIP)
		s.b.Logger.Info("smtp auth failed", "remote_ip", s.remoteIP, "auth_method", gateway.AuthSMTPCredential,
			"credential", auditUsername(username))
		s.authFailed(username, "invalid_credentials")
		return errInvalidCredentials
	}
	if res.Previous {
		s.b.Logger.Warn("smtp credential used with its previous password; the app has not picked up the rotated one",
			"credential", res.Username, "namespace", res.Namespace)
	}
	s.cred = res
	s.identity = &gateway.Identity{
		Namespace:          res.Namespace,
		ServiceAccount:     res.ServiceAccount,
		AuthMethod:         gateway.AuthSMTPCredential,
		Credential:         res.Username,
		CredentialPrevious: res.Previous,
	}
	return nil
}

func (s *session) authFailed(username, reason string) {
	telemetry.AuthFailuresTotal.WithLabelValues(gateway.TransportSMTP, gateway.AuthSMTPCredential, reason).Inc()
	s.b.Sender.Reject(audit.Event{
		MessageID:  uuid.NewString(),
		AuthMethod: gateway.AuthSMTPCredential,
		Credential: auditUsername(username),
		Transport:  gateway.TransportSMTP,
	}, reason)
}

// auditUsername returns username if it is shaped like a credential
// username, else "": the value is client-supplied and must not let a
// client write arbitrary text into the audit stream.
func auditUsername(u string) string {
	if len(u) > 317 { // 253 (name) + "." + 63 (namespace)
		return ""
	}
	if _, _, ok := credential.ParseUsername(u); !ok {
		return ""
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return ""
		}
	}
	return u
}

// loginServer implements the (obsolete but widely used) LOGIN mechanism:
// "Username:" and "Password:" challenges, one value each.
type loginServer struct {
	step         int
	username     string
	authenticate func(username, password string) error
}

func (l *loginServer) Next(response []byte) ([]byte, bool, error) {
	switch l.step {
	case 0:
		if len(response) > 0 { // initial response carries the username
			l.username, l.step = string(response), 2
			return []byte("Password:"), false, nil
		}
		l.step = 1
		return []byte("Username:"), false, nil
	case 1:
		l.username, l.step = string(response), 2
		return []byte("Password:"), false, nil
	case 2:
		l.step = 3
		return nil, true, l.authenticate(l.username, string(response))
	}
	return nil, false, sasl.ErrUnexpectedClientResponse
}

// FailureLimiter throttles repeated failed logins per username and source
// IP, and per source IP (sliding window, per process). Once a key reaches
// its limit, further attempts are refused with 454 without checking the
// password. Failures are deliberately not counted per username alone:
// anyone who can reach the proxy could then lock out a credential's real
// app by failing on its username. The throttle mainly protects
// bring-your-own (possibly weak) passwords and bounds argon2id work;
// generated 256-bit passwords cannot be guessed anyway.
type FailureLimiter struct {
	Window    time.Duration
	PerUserIP int
	PerIP     int

	mu   sync.Mutex
	hits map[string][]time.Time
	now  func() time.Time
}

// maxFailureKeys bounds memory; beyond it the tracker starts over.
const maxFailureKeys = 100_000

// Blocked reports whether username from ip, or ip, has used up its
// failures.
func (f *FailureLimiter) Blocked(username, ip string) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return (f.PerUserIP > 0 && f.countLocked(userIPKey(username, ip)) >= f.PerUserIP) ||
		(f.PerIP > 0 && f.countLocked("ip:"+ip) >= f.PerIP)
}

// Fail records a failed attempt.
func (f *FailureLimiter) Fail(username, ip string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hits == nil || len(f.hits) > maxFailureKeys {
		f.hits = map[string][]time.Time{}
	}
	now := f.clock()
	for _, k := range []string{userIPKey(username, ip), "ip:" + ip} {
		f.countLocked(k)
		f.hits[k] = append(f.hits[k], now)
	}
}

func userIPKey(username, ip string) string { return "u:" + ip + "\x00" + username }

// countLocked prunes and counts the failures of key inside the window.
func (f *FailureLimiter) countLocked(key string) int {
	ts := f.hits[key]
	cut := f.clock().Add(-f.Window)
	i := 0
	for i < len(ts) && !ts[i].After(cut) {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(f.hits, key)
		return 0
	}
	f.hits[key] = ts
	return len(ts)
}

func (f *FailureLimiter) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

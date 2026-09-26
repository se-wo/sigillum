package smtpproxy

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"go.opentelemetry.io/otel/codes"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/audit"
	"github.com/se-wo/sigillum/internal/credential"
	"github.com/se-wo/sigillum/internal/gateway"
	"github.com/se-wo/sigillum/internal/telemetry"
)

// CredentialVerifier checks AUTH PLAIN / LOGIN against MailCredentials
// (US-3.7).
type CredentialVerifier interface {
	Lookup(ctx context.Context, username string) (*sigv1.MailCredential, error)
	Check(ctx context.Context, mc *sigv1.MailCredential, password string) (*credential.Result, error)
	// StillValid returns credential.ErrInvalid once the credential is
	// revoked, other errors for failed lookups.
	StillValid(ctx context.Context, r *credential.Result) (previous bool, err error)
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
	// errCredentialRevoked is temporary: after a rotation the client can
	// reconnect with the new password and deliver the message it retries,
	// and a deleted credential then fails AUTH permanently (535).
	errCredentialRevoked = &smtp.SMTPError{
		Code: 454, EnhancedCode: smtp.EnhancedCode{4, 7, 0},
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

	mc, err := s.b.Credentials.Lookup(ctx, username)
	var res *credential.Result
	switch {
	case err != nil:
	case mc.Generated() || s.b.AuthFailures == nil:
		res, err = s.b.Credentials.Check(ctx, mc, password)
	default:
		// Only bring-your-own-hash credentials are throttled (see
		// FailureLimiter). Attempts per username and source IP run one
		// at a time, so parallel connections cannot pass the limit while
		// their checks wait for an argon2id slot, and parallel correct
		// logins are not counted as failures.
		var done func(failed bool)
		done, err = s.b.AuthFailures.Begin(ctx, username, s.remoteIP)
		if errors.Is(err, errThrottled) {
			span.SetStatus(codes.Error, "throttled")
			s.authFailed(username, "auth_rate_limited")
			return errAuthThrottled
		}
		if err == nil {
			res, err = s.b.Credentials.Check(ctx, mc, password)
			done(errors.Is(err, credential.ErrInvalid))
		}
	}
	if err != nil {
		span.SetStatus(codes.Error, "credential rejected")
		if !errors.Is(err, credential.ErrInvalid) {
			s.b.Logger.Warn("smtp credential lookup failed", "remote_ip", s.remoteIP, "err", err)
			s.authFailed(username, "auth_unavailable")
			return errAuthUnavailable
		}
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
// IP (sliding window, per process). Once a key reaches its limit, further
// attempts with that username from that IP are refused with 454 without
// checking the password. Attempts of one key run one at a time (Begin), so
// the count is always settled before the next attempt is let in.
//
// Only bring-your-own-hash credentials are throttled (see credentialLogin):
// they may carry a weak, user-chosen password, and every attempt costs an
// argon2id computation. Generated passwords have 256 bits and cannot be
// guessed, so throttling them would only let anyone who reaches the proxy
// lock out a real app. For the same reason nothing is counted per username
// or per source IP alone; behind a mesh sidecar or SNAT all callers share
// one source IP.
type FailureLimiter struct {
	Window    time.Duration
	PerUserIP int

	once sync.Once
	mu   sync.Mutex
	// hits holds failure timestamps per key, bounded as an LRU: a key that
	// keeps failing stays recent, so flooding the tracker with new keys
	// cannot evict an active block.
	hits *lru.Cache[string, []time.Time]
	// busy serializes the attempts of a key; entries exist only while
	// attempts are running or waiting.
	busy map[string]*keyTurn
	now  func() time.Time
}

type keyTurn struct {
	ch      chan struct{}
	waiters int
}

// maxFailureKeys bounds the memory of the failure tracker.
const maxFailureKeys = 100_000

// errThrottled is returned by Begin for a key that used up its failures.
var errThrottled = errors.New("too many failed logins")

func (f *FailureLimiter) init() {
	f.once.Do(func() {
		f.hits, _ = lru.New[string, []time.Time](maxFailureKeys)
		f.busy = map[string]*keyTurn{}
	})
}

// Begin waits for the turn of username from ip and reports errThrottled
// once the key has used up its failures, or ctx's error. Otherwise the
// caller checks the password and calls done with the outcome, which frees
// the turn.
func (f *FailureLimiter) Begin(ctx context.Context, username, ip string) (done func(failed bool), err error) {
	if f == nil || f.PerUserIP <= 0 {
		return func(bool) {}, nil
	}
	f.init()
	k := userIPKey(username, ip)
	f.mu.Lock()
	turn := f.busy[k]
	if turn == nil {
		turn = &keyTurn{ch: make(chan struct{}, 1)}
		f.busy[k] = turn
	}
	turn.waiters++
	f.mu.Unlock()
	leave := func() {
		f.mu.Lock()
		if turn.waiters--; turn.waiters == 0 {
			delete(f.busy, k)
		}
		f.mu.Unlock()
	}
	select {
	case turn.ch <- struct{}{}:
	case <-ctx.Done():
		leave()
		return nil, ctx.Err()
	}
	release := func() {
		<-turn.ch
		leave()
	}
	f.mu.Lock()
	blocked := f.countLocked(k) >= f.PerUserIP
	f.mu.Unlock()
	if blocked {
		release()
		return nil, errThrottled
	}
	return func(failed bool) {
		if failed {
			f.mu.Lock()
			ts, _ := f.hits.Get(k)
			f.hits.Add(k, append(ts, f.clock()))
			f.mu.Unlock()
		}
		release()
	}, nil
}

func userIPKey(username, ip string) string { return ip + "\x00" + username }

// countLocked prunes and counts the failures of key inside the window.
func (f *FailureLimiter) countLocked(key string) int {
	ts, ok := f.hits.Get(key)
	if !ok {
		return 0
	}
	cut := f.clock().Add(-f.Window)
	i := 0
	for i < len(ts) && !ts[i].After(cut) {
		i++
	}
	if i == len(ts) {
		f.hits.Remove(key)
		return 0
	}
	if i > 0 {
		f.hits.Add(key, ts[i:])
	}
	return len(ts) - i
}

func (f *FailureLimiter) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

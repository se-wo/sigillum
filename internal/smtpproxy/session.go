// Package smtpproxy implements the SMTP submission front end for legacy
// workloads (US-1.2). Callers authenticate with their ServiceAccount token via
// AUTH OAUTHBEARER (US-3.4), with a Sigillum-issued MailCredential via AUTH
// PLAIN or LOGIN (US-3.7) or, only where a policy explicitly opts in, by the
// source pod's IP (US-3.5). Accepted messages run through the same
// gateway pipeline as the REST path and are relayed byte-for-byte.
package smtpproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/se-wo/sigillum/internal/apiserver/auth"
	"github.com/se-wo/sigillum/internal/audit"
	"github.com/se-wo/sigillum/internal/credential"
	"github.com/se-wo/sigillum/internal/driver"
	"github.com/se-wo/sigillum/internal/gateway"
	"github.com/se-wo/sigillum/internal/policy"
	"github.com/se-wo/sigillum/internal/telemetry"
)

// TokenAuthenticator validates a ServiceAccount token (TokenReview).
type TokenAuthenticator interface {
	Authenticate(ctx context.Context, token string) (*auth.Subject, error)
}

// Sender is the gateway pipeline (an interface so tests can stub it).
type Sender interface {
	Send(ctx context.Context, req gateway.Request) gateway.Result
	Reject(ev audit.Event, reason string)
}

// Backend implements smtp.Backend.
type Backend struct {
	Logger *slog.Logger
	Sender Sender
	// Tokens enables AUTH OAUTHBEARER when non-nil.
	Tokens TokenAuthenticator
	// Pods enables the pod-IP legacy fallback when non-nil.
	Pods PodResolver
	// Credentials enables AUTH PLAIN and LOGIN with MailCredentials when
	// non-nil. They are offered on TLS connections only, unless
	// AllowInsecureCredentialAuth is set.
	Credentials                 CredentialVerifier
	AllowInsecureCredentialAuth bool
	// AuthFailures throttles repeated failed credential logins (nil: off).
	AuthFailures *FailureLimiter
	// AuthTimeout bounds TokenReview and pod lookups.
	AuthTimeout time.Duration
	// SendTimeout bounds the pipeline for one message (rate limiter and
	// upstream relay). Zero means no bound.
	SendTimeout time.Duration
	// Slots, when non-nil, caps how many messages are buffered and relayed
	// at once; each holds up to MaxMessageBytes in memory. Its capacity is
	// the limit.
	Slots chan struct{}
}

// NewSession implements smtp.Backend.
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &session{b: b, conn: c, remoteIP: remoteIP(c.Conn().RemoteAddr())}, nil
}

type session struct {
	b        *Backend
	conn     *smtp.Conn
	remoteIP string

	identity *gateway.Identity  // set by AUTH or pod-IP lookup
	cred     *credential.Result // set by a credential login
	from     string
	rcpts    []string
	// revoked is set once the credential was revoked mid-session; every
	// later MAIL is refused.
	revoked bool
}

var (
	_ smtp.Session     = (*session)(nil)
	_ smtp.AuthSession = (*session)(nil)
)

var errAuthRequired = &smtp.SMTPError{
	Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0},
	Message: "Authentication required",
}

// AuthMechanisms implements smtp.AuthSession.
func (s *session) AuthMechanisms() []string {
	var mechs []string
	if s.b.Tokens != nil {
		mechs = append(mechs, sasl.OAuthBearer)
	}
	if s.credentialAuthAllowed() {
		mechs = append(mechs, sasl.Plain, sasl.Login)
	}
	return mechs
}

// Auth implements smtp.AuthSession.
func (s *session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain, sasl.Login:
		return s.credentialAuth(mech)
	case sasl.OAuthBearer:
	default:
		return nil, smtp.ErrAuthUnknownMechanism
	}
	if s.b.Tokens == nil {
		return nil, smtp.ErrAuthUnknownMechanism
	}
	var unavailable bool
	srv := sasl.NewOAuthBearerServer(func(opts sasl.OAuthBearerOptions) *sasl.OAuthBearerError {
		ctx, cancel := context.WithTimeout(context.Background(), s.b.AuthTimeout)
		defer cancel()
		ctx, span := telemetry.Tracer().Start(ctx, "auth.tokenreview")
		defer span.End()
		subj, err := s.b.Tokens.Authenticate(ctx, opts.Token)
		if errors.Is(err, auth.ErrUnavailable) {
			// Not a rejected token: answered with 454 below.
			span.SetStatus(codes.Error, "token review failed")
			telemetry.AuthFailuresTotal.WithLabelValues(gateway.TransportSMTP, gateway.AuthOAuthBearer, "auth_unavailable").Inc()
			s.b.Logger.Warn("smtp token review failed", "remote_ip", s.remoteIP, "err", err)
			s.b.Sender.Reject(audit.Event{
				MessageID:  uuid.NewString(),
				AuthMethod: gateway.AuthOAuthBearer,
				Transport:  gateway.TransportSMTP,
			}, "auth_unavailable")
			unavailable = true
			return &sasl.OAuthBearerError{Status: "invalid_token", Schemes: "bearer"}
		}
		if err != nil {
			span.SetStatus(codes.Error, "token rejected")
			telemetry.AuthFailuresTotal.WithLabelValues(gateway.TransportSMTP, gateway.AuthOAuthBearer, "invalid_token").Inc()
			s.b.Logger.Info("smtp auth failed", "remote_ip", s.remoteIP, "err", err)
			s.b.Sender.Reject(audit.Event{
				MessageID:  uuid.NewString(),
				AuthMethod: gateway.AuthOAuthBearer,
				Transport:  gateway.TransportSMTP,
			}, "invalid_token")
			return &sasl.OAuthBearerError{Status: "invalid_token", Schemes: "bearer"}
		}
		s.identity = &gateway.Identity{
			Namespace:      subj.Namespace,
			ServiceAccount: subj.ServiceAccount,
			AuthMethod:     gateway.AuthOAuthBearer,
		}
		return nil
	})
	return authFailedAs535{unavailableAs454{srv, &unavailable}}, nil
}

// unavailableAs454 answers a failed OAUTHBEARER exchange with a temporary
// 454 when the token could not be reviewed, instead of 535.
type unavailableAs454 struct {
	sasl.Server
	unavailable *bool
}

func (u unavailableAs454) Next(response []byte) ([]byte, bool, error) {
	challenge, done, err := u.Server.Next(response)
	if err != nil && *u.unavailable {
		return nil, false, errAuthUnavailable
	}
	return challenge, done, err
}

// authFailedAs535 maps any SASL failure to "535 5.7.8 Authentication
// credentials invalid" as required by US-3.4 (go-smtp would answer 454).
// Explicit SMTP replies (throttling, temporary failures) pass through.
type authFailedAs535 struct{ sasl.Server }

func (a authFailedAs535) Next(response []byte) ([]byte, bool, error) {
	challenge, done, err := a.Server.Next(response)
	if err != nil {
		var se *smtp.SMTPError
		if errors.As(err, &se) {
			return nil, false, se
		}
		return nil, false, &smtp.SMTPError{
			Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8},
			Message: "Authentication credentials invalid",
		}
	}
	return challenge, done, nil
}

// Mail implements smtp.Session. A client that did not AUTH is identified by
// its pod IP if (and only if) the fallback is enabled for this deployment;
// whether a policy then accepts it is decided by legacyAuth.podIPFallback.
func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if err := s.checkCredential(from, nil); err != nil {
		return err
	}
	if s.identity == nil {
		if err := s.identifyByPodIP(); err != nil {
			return err
		}
	}
	// The null reverse-path "<>" is for bounces generated by MTAs. Workloads
	// submitting application mail have no use for it, and it would skip
	// the envelope-sender half of allowedSenders.
	if from == "" {
		s.rejectCommand("null_sender", "", nil)
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message: "Null sender <> is not accepted for submission"}
	}
	if err := checkPath(from); err != nil {
		s.rejectCommand("invalid_payload", from, nil)
		return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 1, 7}, Message: "Malformed sender address"}
	}
	s.from = from
	return nil
}

// rejectCommand audits a refused MAIL or RCPT command for an identified caller.
func (s *session) rejectCommand(reason, from string, to []string) {
	s.b.Sender.Reject(s.event(uuid.NewString(), from, to), reason)
}

// event is the audit skeleton for the identified caller.
func (s *session) event(msgID, from string, to []string) audit.Event {
	ev := audit.Event{MessageID: msgID, Transport: gateway.TransportSMTP, From: from, To: to}
	if s.identity != nil {
		ev.Namespace = s.identity.Namespace
		ev.ServiceAccount = s.identity.ServiceAccount
		ev.AuthMethod = s.identity.AuthMethod
		ev.Credential = s.identity.Credential
		ev.CredentialPrevious = s.identity.CredentialPrevious
	}
	return ev
}

func (s *session) identifyByPodIP() error {
	if s.b.Pods == nil {
		s.rejectUnauthenticated("auth_required")
		return errAuthRequired
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.b.AuthTimeout)
	defer cancel()
	pod, err := s.b.Pods.ResolveIP(ctx, s.remoteIP)
	if err != nil {
		s.b.Logger.Info("pod-ip identification failed", "remote_ip", s.remoteIP, "err", err)
		s.rejectUnauthenticated("pod_ip_unresolved")
		return errAuthRequired
	}
	s.identity = &gateway.Identity{
		Namespace:      pod.Namespace,
		ServiceAccount: pod.ServiceAccount,
		AuthMethod:     gateway.AuthPodIPLegacy,
		PodLabels:      pod.Labels,
	}
	return nil
}

func (s *session) rejectUnauthenticated(reason string) {
	s.b.Sender.Reject(audit.Event{MessageID: uuid.NewString(), Transport: gateway.TransportSMTP}, reason)
}

// Rcpt implements smtp.Session. Policy checks happen at end of DATA, where the
// whole message (size, header From) is known.
func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if err := checkPath(to); err != nil {
		s.rejectCommand("invalid_payload", s.from, []string{to})
		return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 1, 3}, Message: "Malformed recipient address"}
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

// Data implements smtp.Session.
func (s *session) Data(r io.Reader) error {
	msgID := uuid.NewString()
	ctx, span := telemetry.Tracer().Start(context.Background(), "smtp.data",
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("sigillum.message_id", msgID)))
	defer span.End()

	if s.identity == nil { // go-smtp only allows DATA after MAIL, which sets it
		return errAuthRequired
	}
	baseEvent := s.event(msgID, s.from, s.rcpts)

	if s.b.SendTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.b.SendTimeout)
		defer cancel()
	}
	if s.b.Slots != nil {
		select {
		case s.b.Slots <- struct{}{}:
			defer func() { <-s.b.Slots }()
		case <-ctx.Done():
			// go-smtp drains the rest of DATA after we return.
			s.b.Sender.Reject(baseEvent, "busy")
			return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 2},
				Message: "Too many concurrent messages, try again later (id " + msgID + ")"}
		}
	}

	// Read straight into a buffer that already holds the Received trace
	// header, so the relayed message is never copied a second time.
	trace := receivedHeader(s.remoteIP, msgID, s.identity.AuthMethod, s.isTLS())
	buf := bytes.NewBuffer(make([]byte, 0, len(trace)+64*1024))
	buf.WriteString(trace)
	// go-smtp enforces Server.MaxMessageBytes while we read.
	if _, err := io.Copy(buf, r); err != nil {
		reason := "invalid_payload"
		if errors.Is(err, smtp.ErrDataTooLarge) {
			reason = "message_too_large"
		}
		s.b.Sender.Reject(baseEvent, reason)
		return err
	}
	raw := stripBcc(buf.Bytes()[len(trace):])
	msg, hdr, err := parseMessage(raw)
	if err != nil {
		s.b.Sender.Reject(baseEvent, "invalid_payload")
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: err.Error()}
	}

	// The credential may have been revoked since MAIL FROM.
	if err := s.checkCredential(s.from, s.rcpts); err != nil {
		return err
	}
	to := make([]driver.Address, len(s.rcpts))
	for i, rc := range s.rcpts {
		to[i] = driver.Address{Address: rc}
	}
	res := s.b.Sender.Send(ctx, gateway.Request{
		Identity:     *s.identity,
		Transport:    gateway.TransportSMTP,
		MessageID:    msgID,
		Message:      &driver.Message{From: driver.Address{Address: hdr.from}, To: to},
		Raw:          buf.Bytes()[:len(trace)+len(raw)],
		EnvelopeFrom: s.from,
		Sender:       hdr.sender,
		ReplyTo:      hdr.replyTo,
		SizeBytes:    contentSize(msg, len(raw)),
	})
	if res.Status != gateway.StatusAccepted {
		span.SetStatus(codes.Error, "rejected")
	}
	return resultError(res, msgID)
}

// Reset implements smtp.Session. Authentication survives RSET.
func (s *session) Reset() {
	s.from = ""
	s.rcpts = nil
}

// Logout implements smtp.Session.
func (s *session) Logout() error { return nil }

// resultError maps a gateway Result onto an SMTP reply. 4xx replies tell the
// client to retry, 5xx replies make it bounce the message.
func resultError(res gateway.Result, msgID string) error {
	e := func(code int, enh smtp.EnhancedCode, msg string) error {
		return &smtp.SMTPError{Code: code, EnhancedCode: enh, Message: msg + " (id " + msgID + ")"}
	}
	switch res.Status {
	case gateway.StatusAccepted:
		return nil
	case gateway.StatusDenied:
		switch res.DenyReason {
		case policy.DenyMessageTooLarge:
			return e(552, smtp.EnhancedCode{5, 3, 4}, "Message exceeds policy size limit")
		case policy.DenyTooManyRecipient:
			return e(550, smtp.EnhancedCode{5, 5, 3}, "Too many recipients for policy")
		case policy.DenyNoPolicy:
			return e(550, smtp.EnhancedCode{5, 7, 1}, "No matching policy")
		default:
			return e(550, smtp.EnhancedCode{5, 7, 1}, fmt.Sprintf("Rejected by policy %s: %s", res.Policy, res.DenyReason))
		}
	case gateway.StatusRateLimited:
		// US-2.2: rate limits answer 421.
		return e(421, smtp.EnhancedCode{4, 7, 0}, fmt.Sprintf("Rate limit exceeded, retry in %ds", int(res.RetryAfter.Seconds())))
	case gateway.StatusUpstreamError:
		if res.Permanent {
			return e(554, smtp.EnhancedCode{5, 0, 0}, "Upstream relay rejected the message")
		}
		return e(451, smtp.EnhancedCode{4, 4, 1}, "Upstream relay unavailable")
	default: // backend not ready, limiter unavailable
		return e(451, smtp.EnhancedCode{4, 3, 0}, "Temporarily unavailable")
	}
}

var errNoFrom = errors.New("message has no valid From header")

// checkPath validates a MAIL FROM or RCPT TO path as go-smtp hands it over:
// quotes already removed, any source route stripped. It must be a plain
// address, equal to what is relayed (policy.ValidatePlainAddress).
func checkPath(path string) error { return policy.ValidatePlainAddress(path) }

// addressHeaders holds the header addresses the policy checks.
type addressHeaders struct {
	from    string
	sender  string
	replyTo []string
}

// parseMessage parses raw and returns the addresses of its From, Sender and
// Reply-To fields.
//
// RFC 5322 §3.6 allows each of these fields at most once. net/mail's
// Header.Get (and so AddressList) only reads the first one, while the raw
// bytes, duplicates included, are relayed unchanged and many clients display
// the last. So a duplicate field is rejected outright rather than
// half-checked. A From field with several addresses is rejected too: each
// would have to pass the sender policy, and it is virtually never legitimate
// for submission.
//
// Display names and comments must not contain '@' (policy.
// ValidateAddressHeader), and Resent-* fields, which make no sense in a
// submission, are refused.
func parseMessage(raw []byte) (*mail.Message, addressHeaders, error) {
	var hdr addressHeaders
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, hdr, fmt.Errorf("malformed message header: %v", err)
	}
	for k := range msg.Header {
		if strings.HasPrefix(k, "Resent-") {
			return nil, hdr, fmt.Errorf("%s header fields are not allowed", k)
		}
	}
	for _, k := range []string{"From", "Sender", "Reply-To"} {
		if len(msg.Header[k]) > 1 {
			return nil, hdr, fmt.Errorf("multiple %s header fields are not allowed", k)
		}
	}

	if len(msg.Header["From"]) == 0 {
		return nil, hdr, errNoFrom
	}
	list, err := addressField(msg.Header, "From")
	if err != nil {
		return nil, hdr, fmt.Errorf("invalid From header: %v", err)
	}
	if len(list) == 0 {
		return nil, hdr, errNoFrom
	}
	if len(list) > 1 {
		return nil, hdr, errors.New("multiple From addresses are not allowed")
	}
	hdr.from = list[0]

	if len(msg.Header["Sender"]) > 0 {
		list, err := addressField(msg.Header, "Sender")
		if err != nil {
			return nil, hdr, fmt.Errorf("invalid Sender header: %v", err)
		}
		if len(list) != 1 {
			return nil, hdr, errors.New("the Sender header must hold exactly one address")
		}
		hdr.sender = list[0]
	}
	if len(msg.Header["Reply-To"]) > 0 {
		hdr.replyTo, err = addressField(msg.Header, "Reply-To")
		if err != nil {
			return nil, hdr, fmt.Errorf("invalid Reply-To header: %v", err)
		}
	}
	return msg, hdr, nil
}

// addressField parses the address list in header field k and applies the
// display-name and local-part checks to it.
func addressField(h mail.Header, k string) ([]string, error) {
	list, err := h.AddressList(k)
	if err != nil {
		return nil, err
	}
	if err := policy.ValidateAddressHeader(h.Get(k), len(list)); err != nil {
		return nil, err
	}
	out := make([]string, len(list))
	for i, a := range list {
		if err := policy.ValidateMailbox(a.Address); err != nil {
			return nil, err
		}
		out[i] = a.Address
	}
	return out, nil
}

// receivedHeader builds the RFC 5321 trace header that is prepended to the
// relayed message, so it can be correlated with the audit log. The protocol
// follows RFC 3848: S for TLS, A for SMTP AUTH.
func receivedHeader(remoteIP, msgID, authMethod string, tls bool) string {
	proto := "ESMTP"
	if tls {
		proto += "S"
	}
	if authMethod == gateway.AuthOAuthBearer || authMethod == gateway.AuthSMTPCredential {
		proto += "A"
	}
	return fmt.Sprintf("Received: from [%s] by sigillum with %s id %s;\r\n\t%s\r\n",
		remoteIP, proto, msgID, time.Now().UTC().Format(time.RFC1123Z))
}

func remoteIP(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return strings.Trim(a.String(), "[]")
	}
	return host
}

// checkCredential re-checks a credential login before MAIL and before a
// message is relayed. A revoked session stays revoked: go-smtp allows no
// second AUTH, and falling back to the pod IP would continue the session
// under another identity.
func (s *session) checkCredential(from string, to []string) error {
	if s.revoked {
		return errCredentialRevoked
	}
	if s.cred == nil {
		return nil
	}
	previous, err := s.credentialStillValid()
	switch {
	case errors.Is(err, credential.ErrInvalid):
		// Deleted or rotated out since AUTH: revocation also ends open
		// sessions (US-3.7).
		s.rejectCommand("invalid_credentials", from, to)
		s.identity, s.cred, s.revoked = nil, nil, true
		return errCredentialRevoked
	case err != nil:
		s.b.Logger.Warn("smtp credential lookup failed", "remote_ip", s.remoteIP, "err", err)
		s.rejectCommand("auth_unavailable", from, to)
		return errAuthUnavailable
	}
	// After a rotation the session's password may now be the previous
	// one; audit it as such.
	s.identity.CredentialPrevious = previous
	return nil
}

func (s *session) credentialStillValid() (previous bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.b.AuthTimeout)
	defer cancel()
	return s.b.Credentials.StillValid(ctx, s.cred)
}

// Package smtpproxy implements the SMTP submission front end for legacy
// workloads (US-1.2). Callers authenticate with their ServiceAccount token via
// AUTH OAUTHBEARER (US-3.4) or, only where a policy explicitly opts in, by the
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
	// AuthTimeout bounds TokenReview and pod lookups.
	AuthTimeout time.Duration
}

// NewSession implements smtp.Backend.
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &session{b: b, remoteIP: remoteIP(c.Conn().RemoteAddr())}, nil
}

type session struct {
	b        *Backend
	remoteIP string

	identity *gateway.Identity // set by AUTH or pod-IP lookup
	from     string
	rcpts    []string
}

var (
	_ smtp.Session     = (*session)(nil)
	_ smtp.AuthSession = (*session)(nil)
)

var errAuthRequired = &smtp.SMTPError{
	Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0},
	Message: "Authentication required (AUTH OAUTHBEARER with a ServiceAccount token)",
}

// AuthMechanisms implements smtp.AuthSession.
func (s *session) AuthMechanisms() []string {
	if s.b.Tokens == nil {
		return nil
	}
	return []string{sasl.OAuthBearer}
}

// Auth implements smtp.AuthSession.
func (s *session) Auth(mech string) (sasl.Server, error) {
	if mech != sasl.OAuthBearer || s.b.Tokens == nil {
		return nil, smtp.ErrAuthUnknownMechanism
	}
	srv := sasl.NewOAuthBearerServer(func(opts sasl.OAuthBearerOptions) *sasl.OAuthBearerError {
		ctx, cancel := context.WithTimeout(context.Background(), s.b.AuthTimeout)
		defer cancel()
		ctx, span := telemetry.Tracer().Start(ctx, "auth.tokenreview")
		defer span.End()
		subj, err := s.b.Tokens.Authenticate(ctx, opts.Token)
		if err != nil {
			span.SetStatus(codes.Error, "token rejected")
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
	return authFailedAs535{srv}, nil
}

// authFailedAs535 maps any SASL failure to "535 5.7.8 Authentication
// credentials invalid" as required by US-3.4 (go-smtp would answer 454).
type authFailedAs535 struct{ sasl.Server }

func (a authFailedAs535) Next(response []byte) ([]byte, bool, error) {
	challenge, done, err := a.Server.Next(response)
	if err != nil {
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
	if s.identity == nil {
		if err := s.identifyByPodIP(); err != nil {
			return err
		}
	}
	if from != "" { // "<>" (null reverse-path) is allowed for bounces
		if _, err := mail.ParseAddress(from); err != nil {
			return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 1, 7}, Message: "Malformed sender address"}
		}
	}
	s.from = from
	return nil
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
	if _, err := mail.ParseAddress(to); err != nil {
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
	// go-smtp enforces Server.MaxMessageBytes while we read.
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	baseEvent := audit.Event{
		MessageID:      msgID,
		Namespace:      s.identity.Namespace,
		ServiceAccount: s.identity.ServiceAccount,
		AuthMethod:     s.identity.AuthMethod,
		Transport:      gateway.TransportSMTP,
		From:           s.from,
		To:             s.rcpts,
	}
	headerFrom, err := parseHeaderFrom(raw)
	if err != nil {
		s.b.Sender.Reject(baseEvent, "invalid_payload")
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: err.Error()}
	}

	to := make([]driver.Address, len(s.rcpts))
	for i, rc := range s.rcpts {
		to[i] = driver.Address{Address: rc}
	}
	res := s.b.Sender.Send(ctx, gateway.Request{
		Identity:     *s.identity,
		Transport:    gateway.TransportSMTP,
		MessageID:    msgID,
		Message:      &driver.Message{From: driver.Address{Address: headerFrom}, To: to},
		Raw:          withReceivedHeader(raw, s.remoteIP, msgID, s.identity.AuthMethod),
		EnvelopeFrom: s.from,
		SizeBytes:    int64(len(raw)),
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

// parseHeaderFrom returns the single From address of an RFC 5322 message.
// Multiple From addresses are rejected: each would have to pass the sender
// policy, and they are virtually never legitimate for submission.
func parseHeaderFrom(raw []byte) (string, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("malformed message header: %v", err)
	}
	list, err := msg.Header.AddressList("From")
	if err != nil || len(list) == 0 {
		return "", errNoFrom
	}
	if len(list) > 1 {
		return "", errors.New("multiple From addresses are not allowed")
	}
	return list[0].Address, nil
}

// withReceivedHeader prepends an RFC 5321 trace header so the relayed
// message can be correlated with the audit log.
func withReceivedHeader(raw []byte, remoteIP, msgID, authMethod string) []byte {
	proto := "ESMTP"
	if authMethod == gateway.AuthOAuthBearer {
		proto = "ESMTPA" // RFC 3848
	}
	h := fmt.Sprintf("Received: from [%s] by sigillum with %s id %s;\r\n\t%s\r\n",
		remoteIP, proto, msgID, time.Now().UTC().Format(time.RFC1123Z))
	return append([]byte(h), raw...)
}

func remoteIP(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return strings.Trim(a.String(), "[]")
	}
	return host
}

// Package smtp implements the SMTP backend driver. It supports STARTTLS,
// implicit TLS and plaintext, with PLAIN, LOGIN and CRAM-MD5 SASL.
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"sync"
	"time"

	"github.com/se-wo/sigillum/internal/driver"
)

const driverHelo = "sigillum"

func init() {
	driver.Register(driver.TypeSMTP, func(cfg driver.Config) (driver.Driver, error) {
		if cfg.SMTP == nil {
			return nil, errors.New("smtp: missing SMTPConfig")
		}
		if len(cfg.SMTP.Endpoints) == 0 {
			return nil, errors.New("smtp: at least one endpoint required")
		}
		return &Driver{cfg: cfg}, nil
	})
}

// Driver implements driver.Driver against one or more SMTP submission relays.
// Endpoints are tried in declaration order and the first one to accept the
// HELO/AUTH handshake handles the message.
type Driver struct {
	cfg driver.Config

	mu     sync.RWMutex
	health map[string]driver.EndpointHealth
}

func (d *Driver) Type() driver.Type { return driver.TypeSMTP }

func (d *Driver) Capabilities() []driver.Capability {
	return []driver.Capability{driver.CapabilitySend}
}

func (d *Driver) Close() error { return nil }

// HealthCheck dials each endpoint and runs HELO/EHLO + STARTTLS where
// configured. Auth is intentionally not exercised — failing auth would
// mask the underlying TCP/TLS state we want to advertise.
func (d *Driver) HealthCheck(ctx context.Context) []driver.EndpointHealth {
	out := make([]driver.EndpointHealth, 0, len(d.cfg.SMTP.Endpoints))
	for _, ep := range d.cfg.SMTP.Endpoints {
		out = append(out, d.probeEndpoint(ctx, ep))
	}
	d.mu.Lock()
	if d.health == nil {
		d.health = map[string]driver.EndpointHealth{}
	}
	for _, h := range out {
		d.health[endpointKey(h.Host, h.Port)] = h
	}
	d.mu.Unlock()
	return out
}

func (d *Driver) probeEndpoint(ctx context.Context, ep driver.SMTPEndpoint) driver.EndpointHealth {
	addr := net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port)))
	timeout := time.Duration(d.cfg.SMTP.Timeout) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dial(dialCtx, ep, timeout)
	if err != nil {
		return driver.EndpointHealth{Host: ep.Host, Port: ep.Port, Ready: false, Message: err.Error()}
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, ep.Host)
	if err != nil {
		return driver.EndpointHealth{Host: ep.Host, Port: ep.Port, Ready: false, Message: err.Error()}
	}
	defer c.Quit()

	if err := c.Hello(d.helo()); err != nil {
		return driver.EndpointHealth{Host: ep.Host, Port: ep.Port, Ready: false, Message: err.Error()}
	}
	if ep.TLS == "starttls" {
		ok, _ := c.Extension("STARTTLS")
		if !ok {
			return driver.EndpointHealth{Host: ep.Host, Port: ep.Port, Ready: false, Message: "server does not advertise STARTTLS"}
		}
		tlsCfg := &tls.Config{ServerName: ep.Host, InsecureSkipVerify: ep.InsecureSkipVerify}
		if err := c.StartTLS(tlsCfg); err != nil {
			return driver.EndpointHealth{Host: ep.Host, Port: ep.Port, Ready: false, Message: err.Error()}
		}
	}
	_ = addr
	return driver.EndpointHealth{Host: ep.Host, Port: ep.Port, Ready: true}
}

// Send writes msg to the first endpoint that accepts the handshake. If every
// endpoint fails the wrapped error indicates whether all errors look transient
// (caller may retry) or one looked permanent.
func (d *Driver) Send(ctx context.Context, msg *driver.Message) (*driver.SendResult, error) {
	if msg == nil {
		return nil, errors.New("nil message")
	}
	body, msgID, err := AssembleMessage(msg, d.helo())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", driver.ErrUpstreamPermanent, err)
	}
	allRecipients := append(append(append([]driver.Address{}, msg.To...), msg.Cc...), msg.Bcc...)
	rcpts := extractAddrs(allRecipients)

	var lastErr error
	transient := true
	for _, ep := range d.cfg.SMTP.Endpoints {
		if err := d.sendVia(ctx, ep, msg.From.Address, rcpts, body); err != nil {
			lastErr = err
			if !isTransient(err) {
				transient = false
			}
			continue
		}
		return &driver.SendResult{UpstreamID: msgID, AcceptedAt: time.Now().UTC()}, nil
	}
	if lastErr == nil {
		lastErr = driver.ErrNoReadyEndpoint
	}
	if transient {
		return nil, fmt.Errorf("%w: %v", driver.ErrUpstreamTransient, lastErr)
	}
	return nil, fmt.Errorf("%w: %v", driver.ErrUpstreamPermanent, lastErr)
}

func (d *Driver) sendVia(ctx context.Context, ep driver.SMTPEndpoint, from string, rcpts []string, body []byte) error {
	timeout := time.Duration(d.cfg.SMTP.Timeout) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dial(dialCtx, ep, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, ep.Host)
	if err != nil {
		return err
	}
	defer c.Quit()

	if err := c.Hello(d.helo()); err != nil {
		return err
	}
	if ep.TLS == "starttls" {
		ok, _ := c.Extension("STARTTLS")
		if !ok {
			return fmt.Errorf("server does not advertise STARTTLS")
		}
		tlsCfg := &tls.Config{ServerName: ep.Host, InsecureSkipVerify: ep.InsecureSkipVerify}
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if d.cfg.SMTP.AuthType != "" && d.cfg.SMTP.AuthType != "NONE" {
		auth, err := buildAuth(d.cfg.SMTP.AuthType, d.cfg.SMTP.Username, d.cfg.SMTP.Password, ep.Host)
		if err != nil {
			return err
		}
		if auth != nil {
			if err := c.Auth(auth); err != nil {
				return err
			}
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return w.Close()
}

func dial(ctx context.Context, ep driver.SMTPEndpoint, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port)))
	d := net.Dialer{Timeout: timeout}
	if ep.TLS == "tls" {
		tlsCfg := &tls.Config{ServerName: ep.Host, InsecureSkipVerify: ep.InsecureSkipVerify}
		return tls.DialWithDialer(&d, "tcp", addr, tlsCfg)
	}
	return d.DialContext(ctx, "tcp", addr)
}

func buildAuth(mech, username, password, host string) (smtp.Auth, error) {
	switch mech {
	case "PLAIN":
		return smtp.PlainAuth("", username, password, host), nil
	case "LOGIN":
		return loginAuth{username: username, password: password}, nil
	case "CRAM-MD5":
		return smtp.CRAMMD5Auth(username, password), nil
	default:
		return nil, fmt.Errorf("unsupported auth type %q", mech)
	}
}

func (d *Driver) helo() string {
	if d.cfg.SMTP.Helo != "" {
		return d.cfg.SMTP.Helo
	}
	return driverHelo
}

func endpointKey(host string, port int32) string {
	return host + ":" + strconv.Itoa(int(port))
}

// loginAuth implements the RFC-4954 LOGIN SASL mechanism, which Go's stdlib
// does not provide out of the box.
type loginAuth struct {
	username, password string
}

func (a loginAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

func (a loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch string(fromServer) {
	case "Username:":
		return []byte(a.username), nil
	case "Password:":
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("unexpected server challenge: %q", fromServer)
	}
}

// isTransient classifies errors so the caller can retry only safely.
// Any net.OpError, timeout, EOF or temporary error is transient.
func isTransient(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout() || ne.Temporary()
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	return true
}

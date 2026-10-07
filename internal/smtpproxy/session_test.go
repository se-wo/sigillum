package smtpproxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/se-wo/sigillum/internal/apiserver/auth"
	"github.com/se-wo/sigillum/internal/audit"
	"github.com/se-wo/sigillum/internal/gateway"
	"github.com/se-wo/sigillum/internal/policy"
)

type stubSender struct {
	mu      sync.Mutex
	result  gateway.Result
	reqs    []gateway.Request
	rejects []string
	events  []audit.Event
}

func (s *stubSender) Send(_ context.Context, req gateway.Request) gateway.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, req)
	return s.result
}

func (s *stubSender) Reject(ev audit.Event, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejects = append(s.rejects, reason)
	s.events = append(s.events, ev)
}

type stubTokens struct{}

func (stubTokens) Authenticate(_ context.Context, token string) (*auth.Subject, error) {
	if token == "review-down" {
		return nil, fmt.Errorf("%w: connection refused", auth.ErrUnavailable)
	}
	if token != "good-token" {
		return nil, errors.New("invalid")
	}
	return &auth.Subject{Namespace: "billing", ServiceAccount: "mailer"}, nil
}

type stubPods struct{ id *PodIdentity }

func (p stubPods) ResolveIP(context.Context, string) (*PodIdentity, error) {
	if p.id == nil {
		return nil, errPodNotFound
	}
	return p.id, nil
}

const testMessage = "From: App <app@billing.example>\r\nTo: a@x.example\r\nSubject: hi\r\n\r\nhello\r\n"

// startProxy runs the proxy on a random port and returns its address.
func startProxy(t *testing.T, b *Backend) string {
	t.Helper()
	return startProxyWith(t, b, nil)
}

func startProxyWith(t *testing.T, b *Backend, tweak func(*smtp.Server)) string {
	t.Helper()
	b.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	if b.AuthTimeout == 0 {
		b.AuthTimeout = time.Second
	}
	o, err := ParseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(o, b, nil)
	if tweak != nil {
		tweak(srv)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func dial(t *testing.T, addr string) *smtp.Client {
	t.Helper()
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Hello("client.test"); err != nil {
		t.Fatal(err)
	}
	return c
}

func send(c *smtp.Client, from string, to []string, msg string) error {
	if err := c.Mail(from, nil); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r, nil); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, msg); err != nil {
		return err
	}
	return w.Close()
}

func smtpCode(err error) int {
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

func TestOAuthBearer_AcceptedMessageReachesGateway(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	c := dial(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))

	if ok, params := c.Extension("AUTH"); !ok || !strings.Contains(params, "OAUTHBEARER") {
		t.Fatalf("AUTH OAUTHBEARER not advertised: %q", params)
	}
	if err := c.Auth(sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{Username: "x", Token: "good-token"})); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if err := send(c, "bounce@billing.example", []string{"a@x.example", "hidden@x.example"}, testMessage); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(sender.reqs) != 1 {
		t.Fatalf("want 1 gateway request, got %d", len(sender.reqs))
	}
	req := sender.reqs[0]
	if req.Identity.Namespace != "billing" || req.Identity.ServiceAccount != "mailer" ||
		req.Identity.AuthMethod != gateway.AuthOAuthBearer || req.Transport != gateway.TransportSMTP {
		t.Fatalf("unexpected identity %+v", req.Identity)
	}
	if req.EnvelopeFrom != "bounce@billing.example" || req.Message.From.Address != "app@billing.example" {
		t.Fatalf("senders not propagated: envelope=%q header=%q", req.EnvelopeFrom, req.Message.From.Address)
	}
	if got := gateway.Recipients(req.Message); len(got) != 2 || got[1] != "hidden@x.example" {
		t.Fatalf("envelope recipients must drive policy, got %v", got)
	}
	raw := string(req.Raw)
	if !strings.HasPrefix(raw, "Received: from [127.0.0.1] by sigillum with ESMTPA id "+req.MessageID) ||
		!strings.Contains(raw, "Subject: hi\r\n\r\nhello") {
		t.Fatalf("raw message not relayed as expected:\n%s", raw)
	}
}

// Review of #20: a TokenReview outage is a temporary failure, audited and
// counted as auth_unavailable, not as an invalid token.
func TestOAuthBearer_TokenReviewOutageIs454(t *testing.T) {
	sender := &stubSender{}
	conn, err := textproto.Dial("tcp", startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expect := func(code int) string {
		t.Helper()
		_, msg, err := conn.ReadResponse(code)
		if err != nil {
			t.Fatalf("want %d: %v", code, err)
		}
		return msg
	}
	expect(220)
	_ = conn.PrintfLine("EHLO client.test")
	expect(250)
	ir := base64.StdEncoding.EncodeToString([]byte("n,,\x01auth=Bearer review-down\x01\x01"))
	_ = conn.PrintfLine("AUTH OAUTHBEARER %s", ir)
	expect(334)
	_ = conn.PrintfLine("%s", base64.StdEncoding.EncodeToString([]byte{0x01}))
	if msg := expect(454); !strings.HasPrefix(msg, "4.7.0 ") {
		t.Fatalf("want 454 4.7.0, got %q", msg)
	}
	if len(sender.rejects) != 1 || sender.rejects[0] != "auth_unavailable" {
		t.Fatalf("want one auth_unavailable reject, got %v", sender.rejects)
	}
}

func TestOAuthBearer_InvalidTokenIs535(t *testing.T) {
	// RFC 7628 §3.2.3: the server answers a bad token with a JSON error
	// challenge, the client acknowledges with %x01, then the server sends
	// the final failure. go-sasl's client aborts early instead, so speak
	// the protocol by hand.
	sender := &stubSender{}
	conn, err := textproto.Dial("tcp", startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expect := func(code int) string {
		t.Helper()
		_, msg, err := conn.ReadResponse(code)
		if err != nil {
			t.Fatalf("want %d: %v", code, err)
		}
		return msg
	}
	expect(220)
	_ = conn.PrintfLine("EHLO client.test")
	expect(250)
	ir := base64.StdEncoding.EncodeToString([]byte("n,,\x01auth=Bearer bad\x01\x01"))
	_ = conn.PrintfLine("AUTH OAUTHBEARER %s", ir)
	challenge, _ := base64.StdEncoding.DecodeString(expect(334))
	if !strings.Contains(string(challenge), `"invalid_token"`) {
		t.Fatalf("unexpected error challenge %q", challenge)
	}
	_ = conn.PrintfLine("%s", base64.StdEncoding.EncodeToString([]byte{0x01}))
	if msg := expect(535); !strings.HasPrefix(msg, "5.7.8 ") {
		t.Fatalf("want 535 5.7.8, got %q", msg)
	}
	if len(sender.rejects) != 1 || sender.rejects[0] != "invalid_token" {
		t.Fatalf("auth failure must be audited, got %v", sender.rejects)
	}
}

func TestUnauthenticatedMailIsRefusedWithoutPodIPMode(t *testing.T) {
	sender := &stubSender{}
	c := dial(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	if err := c.Mail("app@billing.example", nil); smtpCode(err) != 530 {
		t.Fatalf("want 530, got %v", err)
	}
	if len(sender.reqs) != 0 || len(sender.rejects) != 1 {
		t.Fatalf("want audited reject and no send, got reqs=%d rejects=%v", len(sender.reqs), sender.rejects)
	}
}

func TestPodIPFallbackIdentifiesCaller(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	pods := stubPods{id: &PodIdentity{Namespace: "legacy", Name: "cron-1", ServiceAccount: "default",
		Labels: map[string]string{"app": "cron"}}}
	c := dial(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}, Pods: pods}))
	if err := send(c, "app@billing.example", []string{"a@x.example"}, testMessage); err != nil {
		t.Fatalf("send: %v", err)
	}
	id := sender.reqs[0].Identity
	if id.AuthMethod != gateway.AuthPodIPLegacy || id.Namespace != "legacy" || id.PodLabels["app"] != "cron" {
		t.Fatalf("unexpected identity %+v", id)
	}
	if !strings.Contains(string(sender.reqs[0].Raw), "with ESMTP id") {
		t.Fatal("pod-IP sessions must not be labelled ESMTPA")
	}
}

func TestPodIPFallbackUnresolvedIsRefused(t *testing.T) {
	sender := &stubSender{}
	c := dial(t, startProxy(t, &Backend{Sender: sender, Pods: stubPods{}}))
	if err := c.Mail("app@billing.example", nil); smtpCode(err) != 530 {
		t.Fatalf("want 530, got %v", err)
	}
	if len(sender.rejects) != 1 || sender.rejects[0] != "pod_ip_unresolved" {
		t.Fatalf("unexpected rejects %v", sender.rejects)
	}
}

func TestMissingFromHeaderIsRejected(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	c := dial(t, startProxy(t, &Backend{Sender: sender, Pods: stubPods{id: &PodIdentity{Namespace: "n", ServiceAccount: "s"}}}))
	err := send(c, "app@billing.example", []string{"a@x.example"}, "Subject: no from\r\n\r\nbody\r\n")
	if smtpCode(err) != 550 || len(sender.reqs) != 0 {
		t.Fatalf("want 550 without send, got %v (reqs=%d)", err, len(sender.reqs))
	}
}

func TestResultMapping(t *testing.T) {
	cases := []struct {
		res  gateway.Result
		code int
	}{
		{gateway.Result{Status: gateway.StatusDenied, DenyReason: policy.DenySenderNotAllowed}, 550},
		{gateway.Result{Status: gateway.StatusDenied, DenyReason: policy.DenyMessageTooLarge}, 552},
		{gateway.Result{Status: gateway.StatusRateLimited, RetryAfter: time.Minute}, 421},
		{gateway.Result{Status: gateway.StatusUpstreamError, Permanent: true}, 554},
		{gateway.Result{Status: gateway.StatusUpstreamError}, 451},
		{gateway.Result{Status: gateway.StatusBackendNotReady}, 451},
		{gateway.Result{Status: gateway.StatusUnavailable}, 451},
	}
	for _, tc := range cases {
		err := resultError(tc.res, "m")
		if smtpCode(err) != tc.code {
			t.Errorf("%+v: want %d, got %v", tc.res, tc.code, err)
		}
		if !strings.Contains(err.Error(), "(id m)") {
			t.Errorf("reply must carry the message id for support: %v", err)
		}
	}
	if resultError(gateway.Result{Status: gateway.StatusAccepted}, "m") != nil {
		t.Error("accepted must map to nil (250)")
	}
}

func TestDeniedMessageOverTheWire(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusDenied, Policy: "p", DenyReason: policy.DenyRecipientBlocked}}
	c := dial(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	if err := c.Auth(sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{Token: "good-token"})); err != nil {
		t.Fatal(err)
	}
	err := send(c, "app@billing.example", []string{"a@gmail.example"}, testMessage)
	if smtpCode(err) != 550 || !strings.Contains(err.Error(), "recipient_not_allowed") {
		t.Fatalf("want 550 naming the rule (US-1.4), got %v", err)
	}
	// The session stays usable after a rejected message.
	sender.result = gateway.Result{Status: gateway.StatusAccepted}
	if err := send(c, "app@billing.example", []string{"a@x.example"}, testMessage); err != nil {
		t.Fatalf("second message: %v", err)
	}
}

func authed(t *testing.T, addr string) *smtp.Client {
	t.Helper()
	c := dial(t, addr)
	if err := c.Auth(sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{Token: "good-token"})); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDuplicateFromHeaderIsRejected(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	c := authed(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	msg := "From: app@billing.example\r\nFrom: ceo@bank.example\r\nTo: a@x.example\r\nSubject: x\r\n\r\nbody\r\n"
	err := send(c, "app@billing.example", []string{"a@x.example"}, msg)
	if smtpCode(err) != 550 || len(sender.reqs) != 0 {
		t.Fatalf("a second From field must be refused before policy evaluation, got %v (reqs=%d)", err, len(sender.reqs))
	}
	if len(sender.rejects) != 1 || sender.rejects[0] != "invalid_payload" {
		t.Fatalf("want one audited reject, got %v", sender.rejects)
	}
}

func TestNullSenderIsRejectedAndAudited(t *testing.T) {
	sender := &stubSender{}
	c := authed(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	if err := c.Mail("", nil); smtpCode(err) != 550 {
		t.Fatalf("want 550 for MAIL FROM:<>, got %v", err)
	}
	if len(sender.rejects) != 1 || sender.rejects[0] != "null_sender" {
		t.Fatalf("unexpected rejects %v", sender.rejects)
	}
}

func TestMalformedRecipientIsAudited(t *testing.T) {
	sender := &stubSender{}
	c := authed(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	if err := c.Mail("app@billing.example", nil); err != nil {
		t.Fatal(err)
	}
	// Passes go-smtp's path parser, fails RFC 5322 (consecutive dots).
	if err := c.Rcpt("a..b@x.example", nil); smtpCode(err) != 553 {
		t.Fatalf("want a reject for a malformed recipient, got %v", err)
	}
	if len(sender.rejects) != 1 || sender.rejects[0] != "invalid_payload" {
		t.Fatalf("unexpected rejects %v", sender.rejects)
	}
}

func TestOversizedMessageIsAudited(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	addr := startProxyWith(t, &Backend{Sender: sender, Tokens: stubTokens{}},
		func(s *smtp.Server) { s.MaxMessageBytes = 256 })
	c := authed(t, addr)
	big := testMessage + strings.Repeat("x", 1024) + "\r\n"
	if err := send(c, "app@billing.example", []string{"a@x.example"}, big); smtpCode(err) != 552 {
		t.Fatalf("want 552 from go-smtp, got %v", err)
	}
	if len(sender.reqs) != 0 || len(sender.rejects) != 1 || sender.rejects[0] != "message_too_large" {
		t.Fatalf("oversized message must be audited, got reqs=%d rejects=%v", len(sender.reqs), sender.rejects)
	}
}

func TestSizeIsMeasuredLikeREST(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	c := authed(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	attachment := strings.Repeat("A", 30000)
	encoded := wrap76(base64.StdEncoding.EncodeToString([]byte(attachment)))
	msg := "From: app@billing.example\r\nTo: a@x.example\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b1\r\n\r\n" +
		"--b1\r\nContent-Type: text/plain\r\n\r\nhello\r\n" +
		"--b1\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		encoded + "\r\n--b1--\r\n"
	if err := send(c, "app@billing.example", []string{"a@x.example"}, msg); err != nil {
		t.Fatal(err)
	}
	// Everything relayed counts except the base64 overhead of the attachment.
	want := int64(len(msg) - (len(encoded) - len(attachment)))
	if got := sender.reqs[0].SizeBytes; got != want {
		t.Fatalf("want %d (raw %d minus base64 overhead), got %d", want, len(msg), got)
	}
}

func TestBccHeaderIsNotRelayed(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	c := authed(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	msg := "From: app@billing.example\r\nTo: a@x.example\r\nBcc: hidden@x.example\r\nSubject: s\r\n\r\nbody\r\n"
	if err := send(c, "app@billing.example", []string{"a@x.example", "hidden@x.example"}, msg); err != nil {
		t.Fatal(err)
	}
	req := sender.reqs[0]
	if strings.Contains(string(req.Raw), "hidden@") {
		t.Fatalf("Bcc header must be stripped before relaying:\n%s", req.Raw)
	}
	if got := gateway.Recipients(req.Message); len(got) != 2 {
		t.Fatalf("the Bcc recipient still gets the message via the envelope, got %v", got)
	}
}

func TestBusyProxyAnswers451(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	slots := make(chan struct{}, 1)
	slots <- struct{}{} // the only slot is taken
	c := authed(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{},
		Slots: slots, SendTimeout: 100 * time.Millisecond}))
	if err := send(c, "app@billing.example", []string{"a@x.example"}, testMessage); smtpCode(err) != 451 {
		t.Fatalf("want 451 when no slot frees up in time, got %v", err)
	}
	if len(sender.reqs) != 0 || len(sender.rejects) != 1 || sender.rejects[0] != "busy" {
		t.Fatalf("want an audited busy reject, got reqs=%d rejects=%v", len(sender.reqs), sender.rejects)
	}
	<-slots
	if err := send(c, "app@billing.example", []string{"a@x.example"}, testMessage); err != nil {
		t.Fatalf("session must stay usable once a slot is free: %v", err)
	}
}

func wrap76(s string) string {
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76] + "\r\n")
		s = s[76:]
	}
	b.WriteString(s)
	return b.String()
}

func TestRoutingRecipientsAreRefused(t *testing.T) {
	for _, rcpt := range []string{
		"attacker%evil.example@x.example",
		"evil.example!attacker@x.example",
		`"attacker@evil.example"@x.example`,
	} {
		sender := &stubSender{}
		c := authed(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
		if err := c.Mail("app@billing.example", nil); err != nil {
			t.Fatal(err)
		}
		if err := c.Rcpt(rcpt, nil); smtpCode(err) != 553 {
			t.Errorf("RCPT TO:<%s>: want 553, got %v", rcpt, err)
		}
		if len(sender.rejects) != 1 || sender.rejects[0] != "invalid_payload" {
			t.Errorf("RCPT TO:<%s>: unexpected rejects %v", rcpt, sender.rejects)
		}
	}
}

func TestRoutingEnvelopeSenderIsRefused(t *testing.T) {
	sender := &stubSender{}
	c := authed(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	if err := c.Mail("app%evil.example@billing.example", nil); smtpCode(err) != 553 {
		t.Fatalf("want 553, got %v", err)
	}
}

func TestSpoofedHeadersAreRejected(t *testing.T) {
	const tail = "To: a@x.example\r\nSubject: x\r\n\r\nbody\r\n"
	for name, headers := range map[string]string{
		"comment in From":        "From: app@billing.example(attacker@evil.example)\r\n",
		"display name in From":   "From: \"attacker@evil.example\" <app@billing.example>\r\n",
		"encoded-word in From":   "From: =?utf-8?B?YXR0YWNrZXJAZXZpbC5leGFtcGxl?= <app@billing.example>\r\n",
		"routing From":           "From: app%evil.example@billing.example\r\n",
		"duplicate Reply-To":     "From: app@billing.example\r\nReply-To: a@x.example\r\nReply-To: b@evil.example\r\n",
		"duplicate Sender":       "From: app@billing.example\r\nSender: app@billing.example\r\nSender: b@evil.example\r\n",
		"two Sender addresses":   "From: app@billing.example\r\nSender: app@billing.example, b@evil.example\r\n",
		"display name in Sender": "From: app@billing.example\r\nSender: \"x@evil.example\" <app@billing.example>\r\n",
		"Resent-From":            "From: app@billing.example\r\nResent-From: attacker@evil.example\r\n",
	} {
		sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
		c := authed(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
		err := send(c, "app@billing.example", []string{"a@x.example"}, headers+tail)
		if smtpCode(err) != 550 || len(sender.reqs) != 0 {
			t.Errorf("%s: want 550 before policy evaluation, got %v (reqs=%d)", name, err, len(sender.reqs))
		}
		if len(sender.rejects) != 1 || sender.rejects[0] != "invalid_payload" {
			t.Errorf("%s: want one audited reject, got %v", name, sender.rejects)
		}
	}
}

func TestSenderAndReplyToReachPolicy(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	c := authed(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	msg := "From: App <app@billing.example>\r\nSender: relay@billing.example\r\n" +
		"Reply-To: support@billing.example, Help <help@billing.example>\r\n" +
		"To: a@x.example\r\nSubject: x\r\n\r\nbody\r\n"
	if err := send(c, "app@billing.example", []string{"a@x.example"}, msg); err != nil {
		t.Fatal(err)
	}
	req := sender.reqs[0]
	if req.Sender != "relay@billing.example" || len(req.ReplyTo) != 2 || req.ReplyTo[1] != "help@billing.example" {
		t.Fatalf("got Sender=%q ReplyTo=%v", req.Sender, req.ReplyTo)
	}
}

// #47: the proxy adds Date and Message-ID when the client omits them, and
// leaves a message that already has them unchanged.
func TestRelayAddsDateAndMessageIDWhenAbsent(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	c := dial(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	if err := c.Auth(sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{Username: "x", Token: "good-token"})); err != nil {
		t.Fatal(err)
	}
	// No Date, no Message-ID.
	if err := send(c, "bounce@billing.example", []string{"a@x.example"},
		"From: App <app@billing.example>\r\nTo: a@x.example\r\nSubject: hi\r\n\r\nhello\r\n"); err != nil {
		t.Fatal(err)
	}
	raw := string(sender.reqs[0].Raw)
	if !strings.Contains(raw, "\r\nDate: ") {
		t.Fatalf("missing Date not added:\n%s", raw)
	}
	if !strings.Contains(raw, "Message-ID: <"+sender.reqs[0].MessageID+"@billing.example>") {
		t.Fatalf("missing Message-ID not added:\n%s", raw)
	}
	// The body and the client's own headers survive.
	if !strings.Contains(raw, "Subject: hi\r\n\r\nhello") {
		t.Fatalf("body not relayed:\n%s", raw)
	}
}

func TestRelayKeepsClientDateAndMessageID(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	c := dial(t, startProxy(t, &Backend{Sender: sender, Tokens: stubTokens{}}))
	if err := c.Auth(sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{Username: "x", Token: "good-token"})); err != nil {
		t.Fatal(err)
	}
	msg := "From: App <app@billing.example>\r\nTo: a@x.example\r\nDate: Wed, 01 Jan 2025 00:00:00 +0000\r\n" +
		"Message-ID: <client-123@billing.example>\r\nSubject: hi\r\n\r\nhello\r\n"
	if err := send(c, "bounce@billing.example", []string{"a@x.example"}, msg); err != nil {
		t.Fatal(err)
	}
	raw := string(sender.reqs[0].Raw)
	if strings.Count(raw, "Date: ") != 1 || strings.Count(raw, "Message-ID: ") != 1 {
		t.Fatalf("client's Date/Message-ID must not be duplicated:\n%s", raw)
	}
	if !strings.Contains(raw, "<client-123@billing.example>") {
		t.Fatalf("client's Message-ID must be kept:\n%s", raw)
	}
}

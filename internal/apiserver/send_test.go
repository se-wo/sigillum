package apiserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/audit"
	"github.com/se-wo/sigillum/internal/gateway"
)

type auditSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *auditSink) Record(e audit.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
}

type fixedLimiter struct{}

func (fixedLimiter) Refund(context.Context, string) error { return nil }

func (fixedLimiter) Allow(context.Context, string, int32, int32) (bool, time.Duration, error) {
	return true, 0, nil
}

func newTestServer(objs ...client.Object) (*Server, *auditSink) {
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	sink := &auditSink{}
	return &Server{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		gw: &gateway.Gateway{
			Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
			Audit:    sink,
			Policies: gateway.CachedPolicyStore{C: c},
			Reader:   c,
			Limiter:  fixedLimiter{},
		},
	}, sink
}

func post(s *Server, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(withSubject(r.Context(), subject{Namespace: "team", ServiceAccount: "mailer"}))
	w := httptest.NewRecorder()
	s.handleSendMessage(w, r)
	return w
}

func TestHandleSendMessage_NoPolicyIs403AndAudited(t *testing.T) {
	s, sink := newTestServer()
	w := post(s, `{"from":"a@team.example","to":["b@x.example"],"subject":"secret subject"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
	var p map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &p)
	if !strings.HasSuffix(p["type"].(string), "no-policy-matched") || p["messageId"] == "" {
		t.Fatalf("unexpected problem %v", p)
	}
	if len(sink.events) != 1 || sink.events[0].Reason != "no_policy_matched" ||
		sink.events[0].MessageID != p["messageId"] {
		t.Fatalf("unexpected audit events %+v", sink.events)
	}
}

func TestHandleSendMessage_InvalidPayloadIsAudited(t *testing.T) {
	s, sink := newTestServer()
	w := post(s, `{"from":"not an address","to":["b@x.example"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
	if len(sink.events) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if ev.Decision != audit.DecisionReject || ev.Reason != "invalid_payload" ||
		ev.Namespace != "team" || ev.ServiceAccount != "mailer" || ev.Transport != gateway.TransportREST {
		t.Fatalf("unexpected audit event %+v", ev)
	}
}

func TestWriteResult_RateLimitedSetsRetryAfter(t *testing.T) {
	w := httptest.NewRecorder()
	writeResult(w, "m", gateway.Result{Status: gateway.StatusRateLimited, RetryAfter: 7 * time.Second, Policy: "p"})
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "7" {
		t.Fatalf("got %d Retry-After=%q", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestWriteResult_UnavailableIs503(t *testing.T) {
	w := httptest.NewRecorder()
	writeResult(w, "m", gateway.Result{Status: gateway.StatusUnavailable, Policy: "p"})
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "unavailable") {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
}

func TestWriteResult_UpstreamTransientVsPermanent(t *testing.T) {
	w := httptest.NewRecorder()
	writeResult(w, "m", gateway.Result{Status: gateway.StatusUpstreamError, Policy: "p", Detail: "relay down"})
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "errors/upstream-error") {
		t.Fatalf("transient failure: got %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	writeResult(w, "m", gateway.Result{Status: gateway.StatusUpstreamError, Permanent: true, Policy: "p", Detail: "550 no such user"})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "errors/upstream-rejected") {
		t.Fatalf("permanent rejection: got %d %s", w.Code, w.Body.String())
	}
}

func TestHandleSendMessage_RejectedPayloadAuditsAddresses(t *testing.T) {
	s, sink := newTestServer()
	w := post(s, `{"from":"a@team.example","to":["b@x.example"],"bcc":["c@x.example"],"headers":{"X-Evil":"a\r\nBcc: victim@x.example"}}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
	ev := sink.events[0]
	if ev.Reason != "invalid_payload" || ev.From != "a@team.example" || len(ev.To) != 2 {
		t.Fatalf("header-injection reject must record sender and recipients, got %+v", ev)
	}
}

func TestHandleSendMessage_DrainingIsAudited(t *testing.T) {
	s, sink := newTestServer()
	s.shutting.Store(true)
	if w := post(s, `{}`); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", w.Code)
	}
	if len(sink.events) != 1 || sink.events[0].Reason != "shutting_down" || sink.events[0].ServiceAccount != "mailer" {
		t.Fatalf("unexpected audit events %+v", sink.events)
	}
}

func TestRouter_TracesOnlyTheMailAPI(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	s, _ := newTestServer()
	s.cacheSynced.Store(true)
	h := s.buildRouter()
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}
	if n := len(exp.GetSpans()); n != 0 {
		t.Fatalf("probes and scrapes must not create spans, got %d", n)
	}
	// Unauthenticated /v1 request: rejected by auth, but still traced.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/messages", nil))
	if spans := exp.GetSpans(); len(spans) != 1 || spans[0].Name != "http.request" {
		t.Fatalf("want one http.request span for /v1, got %+v", spans)
	}
}

func TestHandleSendMessage_OversizedBodyAuditedAsMessageTooLarge(t *testing.T) {
	s, sink := newTestServer()
	big := `{"from":"a@team.example","to":["b@x.example"],"body":{"text":"` + strings.Repeat("x", 33*1024*1024) + `"}}`
	if w := post(s, big); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", w.Code)
	}
	if len(sink.events) != 1 || sink.events[0].Reason != "message_too_large" {
		t.Fatalf("want the same reason as the SMTP path, got %+v", sink.events)
	}
}

func TestHandleSendMessage_AddressSpoofingIsRejected(t *testing.T) {
	long := strings.Repeat("x", maxHeaderValue+1)
	for name, body := range map[string]string{
		"percent hack":        `{"from":"a@team.example","to":["attacker%evil.example@x.example"]}`,
		"bang path":           `{"from":"a@team.example","cc":["evil.example!attacker@x.example"]}`,
		"quoted local part":   `{"from":"a@team.example","bcc":["\"attacker@evil.example\"@x.example"]}`,
		"display name with @": `{"from":"\"attacker@evil.example\" <a@team.example>","to":["b@x.example"]}`,
		"comment with @":      `{"from":"a@team.example(attacker@evil.example)","to":["b@x.example"]}`,
		"encoded-word with @": `{"from":"=?utf-8?B?YXR0YWNrZXJAZXZpbC5leGFtcGxl?= <a@team.example>","to":["b@x.example"]}`,
		"reply-to name":       `{"from":"a@team.example","to":["b@x.example"],"headers":{"Reply-To":"\"x@evil.example\" <b@x.example>"}}`,
		"reply-to routing":    `{"from":"a@team.example","to":["b@x.example"],"headers":{"Reply-To":"attacker%evil.example@x.example"}}`,
		"sender two":          `{"from":"a@team.example","to":["b@x.example"],"headers":{"Sender":"a@team.example, c@team.example"}}`,
		"duplicate header":    `{"from":"a@team.example","to":["b@x.example"],"headers":{"Reply-To":"b@x.example","reply-to":"attacker@evil.example"}}`,
		"resent header":       `{"from":"a@team.example","to":["b@x.example"],"headers":{"Resent-From":"attacker@evil.example"}}`,
		"overlong header":     `{"from":"a@team.example","to":["b@x.example"],"headers":{"X-Data":"` + long + `"}}`,
	} {
		s, sink := newTestServer()
		w := post(s, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d: %s", name, w.Code, w.Body.String())
			continue
		}
		if len(sink.events) != 1 || sink.events[0].Reason != "invalid_payload" {
			t.Errorf("%s: want one invalid_payload audit event, got %+v", name, sink.events)
		}
	}
}

func TestAddressHeaders(t *testing.T) {
	sender, replyTo, err := addressHeaders(map[string]string{
		"sender":   "Billing <noreply@team.example>",
		"Reply-To": "support@team.example, Help Desk <help@team.example>",
		"X-Other":  "attacker@evil.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sender != "noreply@team.example" || len(replyTo) != 2 || replyTo[1] != "help@team.example" {
		t.Fatalf("got sender=%q replyTo=%v", sender, replyTo)
	}
}

func TestEstimateSizeCountsSubjectAndHeaders(t *testing.T) {
	req := requestBody{
		Subject: strings.Repeat("s", 100),
		Headers: map[string]string{"X-Data": strings.Repeat("h", 200)},
		Body:    requestBodyContent{Text: "text"},
	}
	if got, want := estimateSize(req, nil), int64(100+len("X-Data")+200+4); got != want {
		t.Fatalf("estimateSize = %d, want %d", got, want)
	}
}

func TestReadyz_FailsWhileDrainingButRequestsAreServed(t *testing.T) {
	s, _ := newTestServer()
	s.cacheSynced.Store(true)
	w := httptest.NewRecorder()
	s.handleReadyz(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("want ready, got %d", w.Code)
	}
	// Shutdown delay (G-3): readiness fails, mail is still accepted.
	s.draining.Store(true)
	w = httptest.NewRecorder()
	s.handleReadyz(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 while draining, got %d", w.Code)
	}
	if w := post(s, `{}`); w.Code == http.StatusServiceUnavailable {
		t.Fatalf("requests must still be served during the shutdown delay, got %d", w.Code)
	}
}

func TestHandleSendMessage_AllowedRecipients(t *testing.T) {
	pol := &sigv1.MailPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "alerts-only", Namespace: "team"},
		Spec: sigv1.MailPolicySpec{
			Subjects:   []sigv1.PolicySubject{{ServiceAccount: &sigv1.ServiceAccountSubject{Name: "mailer"}}},
			BackendRef: sigv1.BackendRef{Name: "relay", Kind: sigv1.KindClusterMailBackend},
			RecipientRestrictions: &sigv1.RecipientRestrictions{
				AllowedRecipients: []string{"alerts@contoso.com", "*@oncall.contoso.com"},
			},
		},
	}
	s, sink := newTestServer(pol)

	w := post(s, `{"from":"a@team.example","to":["alerts@contoso.com"],"cc":["ceo@contoso.com"]}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "errors/recipient-not-allowed") {
		t.Fatalf("mailbox outside allowedRecipients: want 403 recipient-not-allowed, got %d %s", w.Code, w.Body.String())
	}
	if ev := sink.events[len(sink.events)-1]; ev.Reason != "recipient_not_allowed" || ev.Policy != "alerts-only" {
		t.Fatalf("unexpected audit record %+v", ev)
	}

	// Allowed recipients pass the policy; this test has no backend, so the
	// request stops at backend resolution instead.
	w = post(s, `{"from":"a@team.example","to":["alerts@contoso.com","pager@oncall.contoso.com"]}`)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "errors/backend-not-ready") {
		t.Fatalf("allowed recipients: want to pass the policy, got %d %s", w.Code, w.Body.String())
	}
}

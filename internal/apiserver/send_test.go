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

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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

func (fixedLimiter) Allow(context.Context, string, int32, int32) (bool, time.Duration) {
	return true, 0
}

func newTestServer() (*Server, *auditSink) {
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
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

package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func requestWithLength(n int64) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(""))
	r.ContentLength = n
	return r
}

// Large bodies wait for each other; small ones fit beside them; an
// unknown length takes the whole budget.
func TestBodyBudget(t *testing.T) {
	b := newBodyBudget(100)
	ctx := context.Background()

	release, ok := b.reserve(ctx, requestWithLength(80))
	if !ok {
		t.Fatal("the first large body must fit")
	}
	if small, ok := b.reserve(ctx, requestWithLength(20)); !ok {
		t.Fatal("a small body must fit beside it")
	} else {
		small()
	}
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, ok := b.reserve(short, requestWithLength(80)); ok {
		t.Fatal("a second large body must wait for room")
	}
	if _, ok := b.reserve(short, requestWithLength(-1)); ok {
		t.Fatal("an unknown length must wait for the whole budget")
	}

	got := make(chan bool)
	go func() { _, ok := b.reserve(ctx, requestWithLength(500)); got <- ok }()
	release()
	if !<-got {
		t.Fatal("a body larger than the budget must get the whole budget once it is free")
	}

	if r, ok := newBodyBudget(0).reserve(ctx, requestWithLength(1<<40)); !ok {
		t.Fatal("no budget means no bound")
	} else {
		r()
	}
}

// A request that finds no room is answered 503 with Retry-After and is
// audited, before its body is read.
func TestHandleSendMessage_BodyBudgetExhausted(t *testing.T) {
	s, sink := newTestServer()
	s.bodies = newBodyBudget(10)
	hold, _ := s.bodies.reserve(context.Background(), requestWithLength(10))
	defer hold()

	r := httptest.NewRequest(http.MethodPost, "/v1/messages",
		strings.NewReader(`{"from":"a@team.example","to":["b@x.example"],"body":{"text":"x"}}`))
	r.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(withSubject(r.Context(), subject{Namespace: "team", ServiceAccount: "mailer"}), 50*time.Millisecond)
	defer cancel()
	w := httptest.NewRecorder()
	s.handleSendMessage(w, r.WithContext(ctx))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("want 503 with Retry-After, got %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	if len(sink.events) != 1 || sink.events[0].Reason != "busy" {
		t.Fatalf("want one busy audit event, got %+v", sink.events)
	}
}

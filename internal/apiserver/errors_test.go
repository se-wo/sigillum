package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/se-wo/sigillum/internal/apiserver/auth"
)

// decodeProblem checks that w holds a problem document and returns it.
func decodeProblem(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("want application/problem+json, got %q (%d %q)", ct, w.Code, w.Body.String())
	}
	var p map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("problem body: %v: %q", err, w.Body.String())
	}
	if int(p["status"].(float64)) != w.Code {
		t.Fatalf("status member %v differs from the response status %d", p["status"], w.Code)
	}
	return p
}

// #50: unknown paths and methods answer problem documents, not chi's
// text/plain 404 and empty 405.
func TestRouter_NotFoundAndMethodNotAllowedAreProblems(t *testing.T) {
	cs := k8sfake.NewSimpleClientset()
	cs.PrependReactor("create", "tokenreviews", func(k8stesting.Action) (bool, k8sruntime.Object, error) {
		return true, &authv1.TokenReview{Status: authv1.TokenReviewStatus{
			Authenticated: true,
			User:          authv1.UserInfo{Username: "system:serviceaccount:team:mailer"},
			Audiences:     []string{"sigillum"},
		}}, nil
	})
	authn, err := auth.New(cs, []string{"sigillum"}, 16, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := newTestServer()
	s.authn = authn
	h := s.buildRouter()

	cases := []struct {
		method, path, allow, slug string
		status                    int
	}{
		{http.MethodGet, "/nope", "", "not-found", http.StatusNotFound},
		{http.MethodGet, "/v1/nope", "", "not-found", http.StatusNotFound},
		{http.MethodGet, "/v1/messages", "POST", "method-not-allowed", http.StatusMethodNotAllowed},
		{http.MethodDelete, "/healthz", "GET", "method-not-allowed", http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		r.Header.Set("Authorization", "Bearer tok")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.status {
			t.Fatalf("%s %s: want %d, got %d", c.method, c.path, c.status, w.Code)
		}
		p := decodeProblem(t, w)
		if !strings.HasSuffix(p["type"].(string), "/"+c.slug) {
			t.Errorf("%s %s: want type %s, got %v", c.method, c.path, c.slug, p["type"])
		}
		if got := w.Header().Get("Allow"); got != c.allow {
			t.Errorf("%s %s: want Allow %q, got %q", c.method, c.path, c.allow, got)
		}
	}
}

func TestHandleSendMessage_UnsupportedContentTypeIs415(t *testing.T) {
	const body = `{"from":"a@team.example","to":["b@x.example"],"body":{"text":"x"}}`
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "application/jsonx"} {
		s, sink := newTestServer()
		r := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		r = r.WithContext(withSubject(r.Context(), subject{Namespace: "team", ServiceAccount: "mailer"}))
		w := httptest.NewRecorder()
		s.handleSendMessage(w, r)
		if w.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("Content-Type %q: want 415, got %d: %s", ct, w.Code, w.Body.String())
		}
		if p := decodeProblem(t, w); !strings.HasSuffix(p["type"].(string), "/unsupported-media-type") || p["messageId"] == "" {
			t.Fatalf("Content-Type %q: unexpected problem %v", ct, p)
		}
		if len(sink.events) != 1 || sink.events[0].Reason != "invalid_payload" {
			t.Fatalf("Content-Type %q: want one invalid_payload audit record, got %+v", ct, sink.events)
		}
	}
	// Parameters and case do not matter: this one gets past the check
	// and fails at the policy instead.
	s, _ := newTestServer()
	r := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	r.Header.Set("Content-Type", "Application/JSON; charset=utf-8")
	r = r.WithContext(withSubject(r.Context(), subject{Namespace: "team", ServiceAccount: "mailer"}))
	w := httptest.NewRecorder()
	s.handleSendMessage(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("application/json with charset must be accepted, got %d: %s", w.Code, w.Body.String())
	}
}

// #50: a type error names the request field and what it must hold, not
// the Go type it is decoded into.
func TestHandleSendMessage_TypeErrorsNameTheField(t *testing.T) {
	cases := map[string]string{
		`{"from":"a@x.example","to":"b@x.example"}`:              "`to` must be an array of addresses (strings), not a string",
		`{"from":"a@x.example","to":["b@x.example"],"cc":[1]}`:   "`cc[0]` must be an address (string), not a number",
		`{"from":"a@x.example","to":["b@x.example"],"body":"x"}`: "`body` must be an object with text and/or html, not a string",
		`{"from":"a@x.example","body":{"text":true}}`:            "`body.text` must be a string, not a bool",
		`{"from":"a@x.example","attachments":[{"filename":1}]}`:  "`attachments[0].filename` must be a string, not a number",
		`{"from":"a@x.example","headers":{"X-A":1}}`:             "`headers.X-A` must be a string, not a number",
		`{"from":"a@x.example","headers":[]}`:                    "`headers` must be an object of header names to string values, not an array",
		`["a@x.example"]`:                                        "the payload must be a JSON object",
		`{"from":"a@x.example","headers":{"5":1}}`:               "`headers.5` must be a string, not a number",
	}
	for body, want := range cases {
		s, _ := newTestServer()
		w := post(s, body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", body, w.Code)
		}
		p := decodeProblem(t, w)
		if p["detail"] != want {
			t.Errorf("%s:\n got %q\nwant %q", body, p["detail"], want)
		}
		if strings.Contains(p["detail"].(string), "Go struct") {
			t.Errorf("%s: detail leaks Go internals: %q", body, p["detail"])
		}
	}
}

// Package oauthtest provides a fake OAuth 2.0 token endpoint for the client
// credentials grant, for tests of token sources and of drivers that use
// them.
package oauthtest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// TokenPath is the path of the token endpoint on the server.
const TokenPath = "/token"

// Server is a fake token endpoint served over TLS. It issues tokens
// "token-1", "token-2", ... to the configured client and answers
// invalid_client to anyone else.
type Server struct {
	*httptest.Server
	ClientID     string
	ClientSecret string

	mu       sync.Mutex
	lifetime time.Duration
	failure  *failure
	requests int
	last     url.Values
}

type failure struct {
	status int
	header http.Header
	body   string
}

// New starts a Server for one client; it is closed when the test ends.
// Use s.Client() as the HTTP client, which trusts the server's certificate.
func New(t testing.TB, clientID, clientSecret string) *Server {
	s := &Server{ClientID: clientID, ClientSecret: clientSecret, lifetime: time.Hour}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// TokenURL is the URL of the token endpoint.
func (s *Server) TokenURL() string { return s.URL + TokenPath }

// SetLifetime sets expires_in of the tokens issued from now on.
func (s *Server) SetLifetime(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lifetime = d
}

// Fail answers every request with status, header and body until Recover.
func (s *Server) Fail(status int, header http.Header, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failure = &failure{status: status, header: header, body: body}
}

// Recover ends Fail.
func (s *Server) Recover() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failure = nil
}

// Requests is the number of requests to the token endpoint so far.
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// LastForm is the form of the last token request.
func (s *Server) LastForm() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != TokenPath || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	s.mu.Lock()
	s.requests++
	n, lifetime, fail := s.requests, s.lifetime, s.failure
	s.last = r.PostForm
	s.mu.Unlock()

	if fail != nil {
		for k, v := range fail.header {
			w.Header()[k] = v
		}
		w.WriteHeader(fail.status)
		_, _ = w.Write([]byte(fail.body))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.PostForm.Get("grant_type") != "client_credentials":
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
	case r.PostForm.Get("client_id") != s.ClientID || r.PostForm.Get("client_secret") != s.ClientSecret:
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_client",
			"error_description": "AADSTS7000215: Invalid client secret provided.",
		})
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("token-%d", n),
			"token_type":   "Bearer",
			"expires_in":   int(lifetime / time.Second),
		})
	}
}

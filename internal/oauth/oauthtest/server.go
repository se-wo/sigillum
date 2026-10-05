// Package oauthtest provides a fake OAuth 2.0 token endpoint for the client
// credentials and refresh token grants, for tests of token sources and of
// the components that use them.
package oauthtest

import (
	"crypto/sha256"
	"encoding/base64"
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
// invalid_client to anyone else. With SetRefreshToken it also redeems that
// one refresh token, and answers invalid_grant for any other.
type Server struct {
	*httptest.Server
	ClientID     string
	ClientSecret string

	mu       sync.Mutex
	refresh  string
	rotate   bool
	lifetime time.Duration
	failure  *failure
	requests int
	last     url.Values

	authCode, challenge, redirectURI string
}

// ExpectAuthCode makes the server redeem code once for the authorization
// code grant, if the code_verifier matches challenge (S256) and the
// redirect_uri matches. The answer carries a refresh token "refresh-code-<n>"
// that the server then accepts, rotating.
func (s *Server) ExpectAuthCode(code, challenge, redirectURI string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCode, s.challenge, s.redirectURI = code, challenge, redirectURI
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

// SetRefreshToken makes rt the one refresh token the server accepts. With
// rotate, every redemption replaces it with "refresh-<n>" and returns that,
// as Microsoft does; without, the answer carries no refresh token.
func (s *Server) SetRefreshToken(rt string, rotate bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh, s.rotate = rt, rotate
}

// RefreshToken is the refresh token the server accepts now.
func (s *Server) RefreshToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refresh
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
	grant := r.PostForm.Get("grant_type")
	codeOK := false
	if grant == "authorization_code" {
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		codeOK = s.authCode != "" && r.PostForm.Get("code") == s.authCode &&
			base64.RawURLEncoding.EncodeToString(sum[:]) == s.challenge && r.PostForm.Get("redirect_uri") == s.redirectURI
		if codeOK {
			s.authCode = ""
			s.refresh, s.rotate = fmt.Sprintf("refresh-code-%d", n), true
		}
	}
	refreshOK := grant == "refresh_token" && s.refresh != "" && r.PostForm.Get("refresh_token") == s.refresh
	var rotated string
	if refreshOK && fail == nil && s.rotate {
		rotated = fmt.Sprintf("refresh-%d", n)
		s.refresh = rotated
	}
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
	// A public client (empty ClientSecret) redeems refresh tokens without
	// a secret.
	secretOK := r.PostForm.Get("client_secret") == s.ClientSecret
	switch {
	case grant != "client_credentials" && grant != "refresh_token" && grant != "authorization_code":
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
	case r.PostForm.Get("client_id") != s.ClientID || !secretOK:
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_client",
			"error_description": "AADSTS7000215: Invalid client secret provided.",
		})
	case grant == "authorization_code" && !codeOK:
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	case grant == "refresh_token" && !refreshOK:
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "AADSTS70000: The provided grant has expired due to it being revoked.",
		})
	default:
		answer := map[string]any{
			"access_token": fmt.Sprintf("token-%d", n),
			"token_type":   "Bearer",
			"expires_in":   int(lifetime / time.Second),
		}
		if rotated != "" {
			answer["refresh_token"] = rotated
		}
		if codeOK {
			answer["refresh_token"] = s.RefreshToken()
		}
		_ = json.NewEncoder(w).Encode(answer)
	}
}

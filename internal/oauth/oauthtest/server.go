// Package oauthtest provides a fake OAuth 2.0 token endpoint for the client
// credentials and refresh token grants, for tests of token sources and of
// the components that use them.
package oauthtest

import (
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

// TokenPath is the path of the token endpoint on the server, DevicePath
// that of the device authorization endpoint (RFC 8628).
const (
	TokenPath  = "/token"
	DevicePath = "/devicecode"
)

// Device sign-in states, see SetDevice.
const (
	DevicePending  = "pending"
	DeviceApproved = "approved"
	DeviceDenied   = "denied"
)

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

	devices       int
	deviceState   string
	deviceAccount string
	signIns       map[string]bool // refresh tokens of device sign-ins
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

// DeviceURL is the URL of the device authorization endpoint. Each request
// starts a sign-in with device code "device-<n>" and user code
// "CODE-<n>"; only the latest one can be redeemed.
func (s *Server) DeviceURL() string { return s.URL + DevicePath }

// SetDevice sets the state of the latest device sign-in. Once approved,
// polling returns tokens, an ID token naming account and a refresh token
// the server then accepts too, rotated on every use.
func (s *Server) SetDevice(state, account string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceState, s.deviceAccount = state, account
}

// DeviceStarts is the number of device sign-ins started so far.
func (s *Server) DeviceStarts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.devices
}

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
	if r.URL.Path == DevicePath && r.Method == http.MethodPost {
		s.serveDevice(w, r)
		return
	}
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
	if grant == deviceGrant {
		s.mu.Unlock()
		s.pollDevice(w, r, n)
		return
	}
	rt := r.PostForm.Get("refresh_token")
	signedIn := s.signIns[rt]
	refreshOK := grant == "refresh_token" && rt != "" && (rt == s.refresh || signedIn)
	var rotated string
	if refreshOK && fail == nil && (s.rotate || signedIn) {
		rotated = fmt.Sprintf("refresh-%d", n)
		if signedIn {
			delete(s.signIns, rt)
			s.signIns[rotated] = true
		} else {
			s.refresh = rotated
		}
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
	case grant != "client_credentials" && grant != "refresh_token":
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
	case r.PostForm.Get("client_id") != s.ClientID || !secretOK:
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_client",
			"error_description": "AADSTS7000215: Invalid client secret provided.",
		})
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
		_ = json.NewEncoder(w).Encode(answer)
	}
}

const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

func (s *Server) serveDevice(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	s.mu.Lock()
	s.devices++
	n := s.devices
	s.deviceState, s.deviceAccount = DevicePending, ""
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.PostForm.Get("client_id") != s.ClientID {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device_code":      fmt.Sprintf("device-%d", n),
		"user_code":        fmt.Sprintf("CODE-%d", n),
		"verification_uri": "https://login.example.test/link",
		"expires_in":       900,
		"interval":         5,
	})
}

func (s *Server) pollDevice(w http.ResponseWriter, r *http.Request, n int) {
	s.mu.Lock()
	current := fmt.Sprintf("device-%d", s.devices)
	state, account, lifetime := s.deviceState, s.deviceAccount, s.lifetime
	if r.PostForm.Get("device_code") != current {
		state = "expired"
	}
	refresh := fmt.Sprintf("refresh-device-%d", n)
	if state == DeviceApproved {
		// Like Microsoft, a new sign-in leaves earlier refresh tokens
		// valid; its own rotates on every use.
		if s.signIns == nil {
			s.signIns = map[string]bool{}
		}
		s.signIns[refresh] = true
		s.deviceState = "redeemed"
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	fail := func(code string) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
	}
	switch state {
	case DevicePending:
		fail("authorization_pending")
	case DeviceDenied:
		fail("access_denied")
	case DeviceApproved:
		claims, _ := json.Marshal(map[string]string{"email": account, "preferred_username": account})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  fmt.Sprintf("token-%d", n),
			"token_type":    "Bearer",
			"expires_in":    int(lifetime / time.Second),
			"refresh_token": refresh,
			"id_token":      "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims) + ".sig",
		})
	default:
		fail("expired_token")
	}
}

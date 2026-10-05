package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuthCode runs the authorization code grant (RFC 6749 §4.1) with PKCE
// (RFC 7636) for a native app: the person signs in in a browser on the
// same machine, which the provider redirects to a loopback listener (RFC
// 8252 §7.3). It is for `sigillum oauth login` on a workstation; Google
// offers no other way to a refresh token for Gmail scopes.
type AuthCode struct {
	// AuthURL and TokenURL are the provider's endpoints; both must be
	// https URLs.
	AuthURL  string
	TokenURL string
	ClientID string
	// ClientSecret is sent if set (Google's desktop clients have one; it
	// is not confidential there).
	ClientSecret string
	Scopes       []string
	// Params are added to the authorization request, for example Google's
	// access_type=offline.
	Params     url.Values
	HTTPClient *http.Client
}

// LoginResult is a finished sign-in.
type LoginResult struct {
	Token        Token
	RefreshToken string
}

// Login listens on 127.0.0.1, passes the authorization URL to show (which
// prints it, or opens a browser), waits for the provider's redirect until
// ctx ends, and redeems the code. The refresh token is required.
func (a *AuthCode) Login(ctx context.Context, show func(authURL string)) (LoginResult, error) {
	if u, err := url.Parse(a.AuthURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return LoginResult{}, errors.New("the authorization URL must be an https URL")
	}
	verifier, err := randomString(32)
	if err != nil {
		return LoginResult{}, err
	}
	state, err := randomString(16)
	if err != nil {
		return LoginResult{}, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return LoginResult{}, fmt.Errorf("loopback listener: %w", err)
	}
	redirect := "http://" + ln.Addr().String() + "/callback"

	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {a.ClientID},
		"redirect_uri":          {redirect},
		"scope":                 {strings.Join(a.Scopes, " ")},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	for k, v := range a.Params {
		q[k] = v
	}
	authURL := a.AuthURL + "?" + q.Encode()

	codes := make(chan callback, 1)
	var once sync.Once
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		cb := readCallback(r.URL.Query(), state)
		if errors.Is(cb.err, errStateMismatch) {
			// Not our sign-in (a stale tab, or another site): ignore it.
			http.Error(w, "unexpected sign-in response", http.StatusBadRequest)
			return
		}
		once.Do(func() { codes <- cb })
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if cb.err != nil {
			_, _ = w.Write([]byte("Sign-in failed. You can close this window.\n"))
			return
		}
		_, _ = w.Write([]byte("Signed in. You can close this window and return to the terminal.\n"))
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	show(authURL)
	var cb callback
	select {
	case cb = <-codes:
	case <-ctx.Done():
		return LoginResult{}, fmt.Errorf("no sign-in: %w", ctx.Err())
	}
	if cb.err != nil {
		return LoginResult{}, cb.err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cb.code},
		"redirect_uri":  {redirect},
		"client_id":     {a.ClientID},
		"code_verifier": {verifier},
	}
	if a.ClientSecret != "" {
		form.Set("client_secret", a.ClientSecret)
	}
	tok, refresh, err := post(ctx, a.TokenURL, a.HTTPClient, form, nil)
	if err != nil {
		return LoginResult{}, err
	}
	if refresh == "" {
		return LoginResult{}, &Error{Permanent: true, Description: "the answer has no refresh token; " +
			"the sign-in must grant offline access (offline_access for Microsoft, access_type=offline for Google)"}
	}
	return LoginResult{Token: tok, RefreshToken: refresh}, nil
}

type callback struct {
	code string
	err  error
}

var errStateMismatch = errors.New("state mismatch")

// readCallback checks the redirect's state and reads the code or the
// provider's error, reduced to printable ASCII.
func readCallback(q url.Values, state string) callback {
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
		return callback{err: errStateMismatch}
	}
	if e := q.Get("error"); e != "" {
		return callback{err: &Error{Permanent: true, Code: printable(e, maxCodeLen),
			Description: printable(q.Get("error_description"), maxDescLen)}}
	}
	code := q.Get("code")
	if !isVisibleASCII(code, maxRefreshTokenBytes) {
		return callback{err: &Error{Permanent: true, Description: "the redirect has no usable authorization code"}}
	}
	return callback{code: code}
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MicrosoftAuthURL returns the authorization endpoint of a Microsoft
// tenant, checked like MicrosoftTokenURL.
func MicrosoftAuthURL(tenant string) (string, error) {
	u, err := MicrosoftTokenURL(tenant)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(u, "/token") + "/authorize", nil
}

// Google's OAuth endpoints.
const (
	GoogleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	GoogleTokenURL = "https://oauth2.googleapis.com/token"
)

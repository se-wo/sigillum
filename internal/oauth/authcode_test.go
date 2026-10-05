package oauth_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/se-wo/sigillum/internal/oauth"
	"github.com/se-wo/sigillum/internal/oauth/oauthtest"
)

// browser plays the person: it reads the authorization URL, lets the
// fake provider expect the code, and follows the redirect with query.
func browser(t *testing.T, s *oauthtest.Server, query func(state string) url.Values) func(string) {
	return func(authURL string) {
		u, err := url.Parse(authURL)
		if err != nil {
			t.Error(err)
			return
		}
		q := u.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("client_id") != "client" {
			t.Errorf("authorization request %v", q)
		}
		redirect := q.Get("redirect_uri")
		if !strings.HasPrefix(redirect, "http://127.0.0.1:") {
			t.Errorf("redirect %q is not a loopback address", redirect)
		}
		s.ExpectAuthCode("code-1", q.Get("code_challenge"), redirect)
		go func() {
			resp, err := http.Get(redirect + "?" + query(q.Get("state")).Encode())
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
}

func newAuthCode(s *oauthtest.Server) *oauth.AuthCode {
	return &oauth.AuthCode{AuthURL: "https://login.example.test/authorize", TokenURL: s.TokenURL(), ClientID: "client",
		Scopes: []string{"https://outlook.office.com/SMTP.Send", "offline_access"}, HTTPClient: s.Client()}
}

func TestAuthCode_Login(t *testing.T) {
	s := oauthtest.New(t, "client", "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := newAuthCode(s).Login(ctx, browser(t, s, func(state string) url.Values {
		return url.Values{"code": {"code-1"}, "state": {state}}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.RefreshToken, "refresh-code-") || res.Token.AccessToken == "" {
		t.Fatalf("unexpected result %+v", res)
	}
	// The fake checked the PKCE verifier and the redirect URI.
	if f := s.LastForm(); f.Get("grant_type") != "authorization_code" || f.Get("code_verifier") == "" {
		t.Fatalf("token request %v", f)
	}
}

func TestAuthCode_ProviderError(t *testing.T) {
	s := oauthtest.New(t, "client", "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := newAuthCode(s).Login(ctx, browser(t, s, func(state string) url.Values {
		return url.Values{"error": {"access_denied"}, "error_description": {"The user declined.\r\nInjected"}, "state": {state}}
	}))
	if !oauth.IsPermanent(err) || !strings.Contains(err.Error(), "access_denied") || strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatalf("want a printable access_denied, got %v", err)
	}
}

// A redirect with another state (a stale tab, another site) is ignored;
// the login waits for its own.
func TestAuthCode_WrongStateIsIgnored(t *testing.T) {
	s := oauthtest.New(t, "client", "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := newAuthCode(s).Login(ctx, browser(t, s, func(string) url.Values {
		return url.Values{"code": {"code-1"}, "state": {"forged"}}
	}))
	if err == nil || !strings.Contains(err.Error(), "no sign-in") {
		t.Fatalf("want a timeout without a sign-in, got %v", err)
	}
	if s.Requests() != 0 {
		t.Fatal("a forged redirect must not be redeemed")
	}
}

func TestAuthCode_WrongVerifierIsRefused(t *testing.T) {
	// The code is redeemed, but a wrong verifier makes the fake refuse:
	// the result is a permanent error, never a half sign-in.
	s := oauthtest.New(t, "client", "")
	a := newAuthCode(s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := a.Login(ctx, func(authURL string) {
		u, _ := url.Parse(authURL)
		q := u.Query()
		s.ExpectAuthCode("code-1", "not-the-challenge", q.Get("redirect_uri"))
		go func() {
			resp, err := http.Get(q.Get("redirect_uri") + "?" + url.Values{"code": {"code-1"}, "state": {q.Get("state")}}.Encode())
			if err == nil {
				resp.Body.Close()
			}
		}()
	})
	if !oauth.IsPermanent(err) || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("want invalid_grant for a wrong verifier, got %v", err)
	}
}

func TestMicrosoftAuthURL(t *testing.T) {
	if u, err := oauth.MicrosoftAuthURL("consumers"); err != nil || u != "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize" {
		t.Fatalf("got %q, %v", u, err)
	}
}

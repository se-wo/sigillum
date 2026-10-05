package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/se-wo/sigillum/internal/oauth/oauthtest"
)

const secret = "s3cr3t-value"

func source(s *oauthtest.Server) *ClientCredentials {
	return &ClientCredentials{
		TokenURL:     s.TokenURL(),
		ClientID:     "client",
		ClientSecret: secret,
		Scopes:       []string{"https://graph.microsoft.com/.default", "offline_access"},
		HTTPClient:   s.Client(),
	}
}

func TestClientCredentials_IssuesToken(t *testing.T) {
	s := oauthtest.New(t, "client", secret)
	s.SetLifetime(time.Hour)
	before := time.Now()
	tok, err := source(s).Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "token-1" {
		t.Fatalf("token %q", tok.AccessToken)
	}
	if tok.Expiry.Before(before.Add(time.Hour)) || tok.Expiry.After(time.Now().Add(time.Hour)) {
		t.Fatalf("expiry %v not one hour after the request", tok.Expiry)
	}
	f := s.LastForm()
	if f.Get("grant_type") != "client_credentials" || f.Get("client_id") != "client" || f.Get("client_secret") != secret ||
		f.Get("scope") != "https://graph.microsoft.com/.default offline_access" {
		t.Fatalf("unexpected form %v", f)
	}
	if strings.Contains(fmt.Sprint(tok), "token-1") || strings.Contains(fmt.Sprintf("%#v", tok), "token-1") {
		t.Fatal("printing a token must not show its value")
	}
}

func TestClientCredentials_Failures(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		header     http.Header
		body       string
		permanent  bool
		retryAfter time.Duration
		want       string
	}{
		{name: "throttled", status: 429, header: http.Header{"Retry-After": {"7"}}, retryAfter: 7 * time.Second, want: "HTTP 429"},
		{name: "server error", status: 503, body: `{"error":"temporarily_unavailable"}`, want: "temporarily_unavailable"},
		{name: "retry-after capped", status: 503, header: http.Header{"Retry-After": {"86400"}}, retryAfter: maxRetryAfter},
		{name: "scope", status: 400, body: `{"error":"invalid_scope","error_description":"AADSTS70011: bad scope"}`, permanent: true, want: "invalid_scope: AADSTS70011: bad scope"},
		{name: "not found", status: 404, body: "<html>", permanent: true, want: "HTTP 404"},
		{name: "description with control characters", status: 400, body: `{"error":"x","error_description":"a\r\nb"}`, permanent: true, want: "x: a??b"},
		{name: "not bearer", status: 200, body: `{"access_token":"abc","token_type":"mac","expires_in":3600}`, want: "not Bearer"},
		{name: "token with CRLF", status: 200, body: `{"access_token":"abc\r\nX: y","token_type":"Bearer","expires_in":3600}`, want: "not a valid bearer token"},
		{name: "token with ^A", status: 200, body: `{"access_token":"abc\u0001","token_type":"Bearer"}`, want: "not a valid bearer token"},
		{name: "no token", status: 200, body: `{"token_type":"Bearer","expires_in":3600}`, want: "missing"},
		{name: "not JSON", status: 200, body: `<html>`, want: "malformed"},
		{name: "too large", status: 200, body: strings.Repeat(" ", maxResponseBytes+1), want: "larger than 1 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := oauthtest.New(t, "client", secret)
			s.Fail(tc.status, tc.header, tc.body)
			_, err := source(s).Token(context.Background())
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("want *Error, got %v", err)
			}
			if IsPermanent(err) != tc.permanent || e.RetryAfter != tc.retryAfter {
				t.Fatalf("permanent=%v retryAfter=%v, want %v %v (%v)", IsPermanent(err), e.RetryAfter, tc.permanent, tc.retryAfter, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("error must not contain the secret")
			}
		})
	}
}

func TestClientCredentials_WrongSecretIsPermanent(t *testing.T) {
	s := oauthtest.New(t, "client", "other")
	_, err := source(s).Token(context.Background())
	if !IsPermanent(err) || !strings.Contains(err.Error(), "invalid_client") || strings.Contains(err.Error(), secret) {
		t.Fatalf("want permanent invalid_client without the secret, got %v", err)
	}
}

func TestClientCredentials_Lifetime(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		expiresIn string
		want      time.Duration
	}{
		{`3599`, 3599 * time.Second},
		{`"3599"`, 3599 * time.Second},
		{`null`, DefaultLifetime},
		{`0`, DefaultLifetime},
		{`-5`, DefaultLifetime},
		{`999999999`, maxLifetime},
	} {
		tok, _, err := parseResponse(200, "", []byte(`{"access_token":"a.b-c_d~e+f/g==","token_type":"bearer","expires_in":`+tc.expiresIn+`}`), now)
		if err != nil || tok.Expiry != now.Add(tc.want) {
			t.Errorf("expires_in %s: got %v %v, want %v", tc.expiresIn, tok.Expiry.Sub(now), err, tc.want)
		}
	}
	tok, _, err := parseResponse(200, "", []byte(`{"access_token":"a","token_type":"Bearer"}`), now)
	if err != nil || tok.Expiry != now.Add(DefaultLifetime) {
		t.Errorf("missing expires_in: got %v %v", tok.Expiry.Sub(now), err)
	}
}

func TestClientCredentials_RefusesPlainHTTP(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	for _, u := range []string{srv.URL + "/token", "ftp://example.com/token", "://", ""} {
		_, err := (&ClientCredentials{TokenURL: u, ClientSecret: secret}).Token(context.Background())
		if !IsPermanent(err) {
			t.Errorf("%q: want permanent error, got %v", u, err)
		}
	}
	if hits != 0 {
		t.Fatal("the secret must never be sent over plain HTTP")
	}
}

func TestClientCredentials_DoesNotFollowRedirects(t *testing.T) {
	s := oauthtest.New(t, "client", secret)
	elsewhere := 0
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere++ }))
	defer other.Close()
	s.Fail(http.StatusTemporaryRedirect, http.Header{"Location": {other.URL + "/token"}}, "")
	_, err := source(s).Token(context.Background())
	if !IsPermanent(err) || elsewhere != 0 {
		t.Fatalf("a redirect must fail permanently without sending the secret on (err=%v, forwarded=%d)", err, elsewhere)
	}
}

func TestClientCredentials_TransportErrorIsTransient(t *testing.T) {
	s := oauthtest.New(t, "client", secret)
	src := source(s)
	s.Close()
	_, err := src.Token(context.Background())
	var e *Error
	if !errors.As(err, &e) || e.Permanent || e.Err == nil {
		t.Fatalf("want transient error with cause, got %v", err)
	}
}

func TestMicrosoftTokenURL(t *testing.T) {
	for tenant, want := range map[string]string{
		"72f988bf-86f1-41af-91ab-2d7cd011db47": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token",
		"contoso.onmicrosoft.com":              "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
		"consumers":                            "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
	} {
		if got, err := MicrosoftTokenURL(tenant); err != nil || got != want {
			t.Errorf("%s: got %q %v", tenant, got, err)
		}
	}
	for _, tenant := range []string{"", "a/b", "../common", "evil.example?x=", "a@b", "Contoso.com", "a b"} {
		if _, err := MicrosoftTokenURL(tenant); !IsPermanent(err) {
			t.Errorf("%q: want permanent error, got %v", tenant, err)
		}
	}
}

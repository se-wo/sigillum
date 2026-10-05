package oauth

import (
	"context"
	"strings"
	"testing"

	"github.com/se-wo/sigillum/internal/oauth/oauthtest"
)

func refresher(s *oauthtest.Server) *RefreshToken {
	return &RefreshToken{TokenURL: s.TokenURL(), ClientID: "client", ClientSecret: s.ClientSecret,
		Scopes: []string{"https://outlook.office.com/SMTP.Send", "offline_access"}, HTTPClient: s.Client()}
}

func TestRefreshToken_Rotates(t *testing.T) {
	s := oauthtest.New(t, "client", "")
	s.SetRefreshToken("seed", true)
	r := refresher(s)
	tok, next, err := r.Refresh(context.Background(), "seed")
	if err != nil || tok.AccessToken != "token-1" || next != "refresh-1" {
		t.Fatalf("got %v %q %v", tok, next, err)
	}
	f := s.LastForm()
	if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != "seed" || f.Has("client_secret") ||
		f.Get("scope") != "https://outlook.office.com/SMTP.Send offline_access" {
		t.Fatalf("unexpected form %v", f)
	}
	// The rotated token replaces the old one, which no longer works.
	if _, _, err := r.Refresh(context.Background(), "seed"); !IsPermanent(err) || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("a used refresh token must fail with a permanent invalid_grant, got %v", err)
	}
	if _, next, err = r.Refresh(context.Background(), next); err != nil || next != "refresh-3" {
		t.Fatalf("the rotated token must work: %q %v", next, err)
	}
}

func TestRefreshToken_KeepsTokenWithoutRotation(t *testing.T) {
	s := oauthtest.New(t, "client", "secret")
	s.SetRefreshToken("google-rt", false)
	tok, next, err := refresher(s).Refresh(context.Background(), "google-rt")
	if err != nil || tok.AccessToken == "" || next != "google-rt" {
		t.Fatalf("without a new refresh token the old one stays: %q %v", next, err)
	}
	if s.LastForm().Get("client_secret") != "secret" {
		t.Fatal("a confidential client sends its secret")
	}
}

func TestParseResponse_RefreshToken(t *testing.T) {
	for body, ok := range map[string]bool{
		`{"access_token":"a","token_type":"Bearer","refresh_token":"0.AXoA-_*!$x"}`:                                        true,
		`{"access_token":"a","token_type":"Bearer","refresh_token":"1//0g a"}`:                                             false,
		`{"access_token":"a","token_type":"Bearer","refresh_token":"x\u0001"}`:                                             false,
		`{"access_token":"a","token_type":"Bearer","refresh_token":"` + strings.Repeat("r", maxRefreshTokenBytes+1) + `"}`: false,
	} {
		_, _, err := parseResponse(200, "", []byte(body), t0)
		if (err == nil) != ok {
			t.Errorf("%.80s: err=%v, want ok=%v", body, err, ok)
		}
	}
}

package oauth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/se-wo/sigillum/internal/oauth"
	"github.com/se-wo/sigillum/internal/oauth/oauthtest"
)

func TestParseGoogleServiceAccount(t *testing.T) {
	_, good := oauthtest.ServiceAccountKey(t, "sender@project.iam.gserviceaccount.com", "https://oauth2.googleapis.com/token")
	sa, err := oauth.ParseGoogleServiceAccount(good)
	if err != nil || sa.Email != "sender@project.iam.gserviceaccount.com" || sa.KeyID != "key-1" || sa.Key == nil {
		t.Fatalf("got %+v, %v", sa, err)
	}
	_, elsewhere := oauthtest.ServiceAccountKey(t, "sender@project.iam.gserviceaccount.com", "https://evil.example/token")
	for name, raw := range map[string]string{
		"not JSON":          "{",
		"wrong type":        `{"type":"authorized_user","client_email":"a@b"}`,
		"no email":          `{"type":"service_account","private_key":"x"}`,
		"no key":            `{"type":"service_account","client_email":"a@b"}`,
		"foreign token_uri": string(elsewhere),
	} {
		if _, err := oauth.ParseGoogleServiceAccount([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGoogleServiceAccount_Token(t *testing.T) {
	s := oauthtest.New(t, "", "")
	key, raw := oauthtest.ServiceAccountKey(t, "sender@project.iam.gserviceaccount.com", "")
	s.SetServiceAccount(&key.PublicKey, "sender@project.iam.gserviceaccount.com", "noreply@example.com")
	sa, err := oauth.ParseGoogleServiceAccount(raw)
	if err != nil {
		t.Fatal(err)
	}
	sa.TokenURL, sa.HTTPClient, sa.Scopes = s.TokenURL(), s.Client(), []string{"https://www.googleapis.com/auth/gmail.send"}

	sa.Subject = "noreply@example.com"
	if tok, err := sa.Token(context.Background()); err != nil || tok.AccessToken == "" {
		t.Fatalf("delegated: %v %v", tok, err)
	}
	// A mailbox outside the delegation is a permanent error, as from Google.
	sa.Subject = "ceo@example.com"
	if _, err := sa.Token(context.Background()); !oauth.IsPermanent(err) || !strings.Contains(err.Error(), "unauthorized_client") {
		t.Fatalf("undelegated: want unauthorized_client, got %v", err)
	}
	// The account itself, as the health check asks.
	sa.Subject = ""
	if _, err := sa.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := s.Subjects(); len(got) != 2 || got[0] != "noreply@example.com" || got[1] != "" {
		t.Fatalf("subjects %v", got)
	}

	// Another key is refused.
	_, other := oauthtest.ServiceAccountKey(t, "sender@project.iam.gserviceaccount.com", "")
	sa2, _ := oauth.ParseGoogleServiceAccount(other)
	sa2.TokenURL, sa2.HTTPClient, sa2.Scopes = s.TokenURL(), s.Client(), sa.Scopes
	if _, err := sa2.Token(context.Background()); !oauth.IsPermanent(err) {
		t.Fatalf("wrong key: want a permanent error, got %v", err)
	}
}

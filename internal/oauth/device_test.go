package oauth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/se-wo/sigillum/internal/oauth"
	"github.com/se-wo/sigillum/internal/oauth/oauthtest"
)

func TestDeviceCode_SignIn(t *testing.T) {
	s := oauthtest.New(t, "client", "")
	d := &oauth.DeviceCode{DeviceAuthURL: s.DeviceURL(), TokenURL: s.TokenURL(), ClientID: "client",
		Scopes: []string{"openid", "email", "offline_access", "https://outlook.office.com/SMTP.Send"}, HTTPClient: s.Client()}
	ctx := context.Background()

	auth, err := d.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if auth.UserCode != "CODE-1" || auth.VerificationURI != "https://login.example.test/link" ||
		auth.Interval != 5*time.Second || time.Until(auth.ExpiresAt) < 14*time.Minute {
		t.Fatalf("unexpected authorization %+v", auth)
	}
	if got := s.LastForm(); got != nil && got.Get("scope") != "" {
		// LastForm tracks the token endpoint only.
		t.Fatalf("unexpected token request %v", got)
	}

	if _, err := d.Poll(ctx, auth.DeviceCode); !errors.Is(err, oauth.ErrAuthorizationPending) {
		t.Fatalf("before sign-in: want pending, got %v", err)
	}
	s.SetDevice(oauthtest.DeviceApproved, "me@outlook.com")
	res, err := d.Poll(ctx, auth.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if res.Token.AccessToken == "" || res.RefreshToken != "refresh-device-2" || res.Account != "me@outlook.com" {
		t.Fatalf("unexpected result %+v", res)
	}
	if f := s.LastForm(); f.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || f.Get("device_code") != auth.DeviceCode {
		t.Fatalf("poll form %v", f)
	}
	// The code is single use.
	if _, err := d.Poll(ctx, auth.DeviceCode); !oauth.IsPermanent(err) || !strings.Contains(err.Error(), "expired_token") {
		t.Fatalf("second redemption: want expired_token, got %v", err)
	}
}

func TestDeviceCode_Declined(t *testing.T) {
	s := oauthtest.New(t, "client", "")
	d := &oauth.DeviceCode{DeviceAuthURL: s.DeviceURL(), TokenURL: s.TokenURL(), ClientID: "client", HTTPClient: s.Client()}
	auth, err := d.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.SetDevice(oauthtest.DeviceDenied, "")
	if _, err := d.Poll(context.Background(), auth.DeviceCode); !oauth.IsPermanent(err) || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("want a permanent access_denied, got %v", err)
	}
	// A wrong client gets no code at all.
	d.ClientID = "other"
	if _, err := d.Start(context.Background()); !oauth.IsPermanent(err) {
		t.Fatalf("want a permanent error for an unknown client, got %v", err)
	}
}

func TestMicrosoftDeviceCodeURL(t *testing.T) {
	u, err := oauth.MicrosoftDeviceCodeURL("consumers")
	if err != nil || u != "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode" {
		t.Fatalf("got %q, %v", u, err)
	}
	if _, err := oauth.MicrosoftDeviceCodeURL("x/../y"); err == nil {
		t.Fatal("a tenant with a path must be refused")
	}
}

package oauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RefreshToken redeems the refresh token of a delegated sign-in (RFC 6749
// §6) for an access token. It is not a Source: Microsoft rotates the
// refresh token on every use, so the caller passes the current one and must
// keep the one Refresh returns, or the next refresh fails.
type RefreshToken struct {
	// TokenURL is the token endpoint; it must be an https URL.
	TokenURL string
	ClientID string
	// ClientSecret is empty for public clients (a Microsoft app with public
	// client flows, used by the device code sign-in).
	ClientSecret string
	Scopes       []string
	// HTTPClient sends the request, see ClientCredentials.HTTPClient.
	HTTPClient *http.Client

	now func() time.Time
}

// Refresh returns a new access token and the refresh token to use next
// time: the one the provider sent, or refreshToken if it sent none. A
// revoked or expired refresh token is a permanent *Error (invalid_grant).
func (r *RefreshToken) Refresh(ctx context.Context, refreshToken string) (Token, string, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {r.ClientID},
	}
	if r.ClientSecret != "" {
		form.Set("client_secret", r.ClientSecret)
	}
	if len(r.Scopes) > 0 {
		form.Set("scope", strings.Join(r.Scopes, " "))
	}
	tok, next, err := post(ctx, r.TokenURL, r.HTTPClient, form, r.now)
	if err != nil {
		return Token{}, "", err
	}
	if next == "" {
		next = refreshToken
	}
	return tok, next, nil
}

package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrAuthorizationPending is returned by DeviceCode.Poll while the person
// has not finished signing in; poll again after the interval. ErrSlowDown
// asks for a longer interval as well (RFC 8628 §3.5).
var (
	ErrAuthorizationPending = errors.New("authorization pending")
	ErrSlowDown             = errors.New("polling too fast")
)

const (
	// minPollInterval applies when the provider sends a shorter or no
	// interval; RFC 8628 §3.2 defaults to 5 s.
	minPollInterval = 5 * time.Second
	// maxDeviceCodeLifetime caps expires_in of a device code.
	maxDeviceCodeLifetime = 30 * time.Minute
	maxUserCodeLen        = 64
	maxVerificationURILen = 256
	maxAccountLen         = 320
)

// DeviceCode runs the device authorization grant (RFC 8628) for a public
// client: a person opens the verification URI on any device, enters the
// user code and signs in, while the client polls the token endpoint.
type DeviceCode struct {
	// DeviceAuthURL and TokenURL are the provider's endpoints; both must
	// be https URLs.
	DeviceAuthURL string
	TokenURL      string
	ClientID      string
	// ClientSecret is empty for public clients.
	ClientSecret string
	Scopes       []string
	HTTPClient   *http.Client

	now func() time.Time
}

// DeviceAuthorization is a started sign-in. UserCode and VerificationURI
// are meant to be shown to the person; DeviceCode is the client's secret
// for polling.
type DeviceAuthorization struct {
	DeviceCode      string
	UserCode        string
	VerificationURI string
	ExpiresAt       time.Time
	Interval        time.Duration
}

// DeviceResult is a finished sign-in.
type DeviceResult struct {
	Token        Token
	RefreshToken string
	// Account is the signed-in account from the ID token (the "email"
	// claim, else "preferred_username"), empty if the answer had none.
	Account string
}

// Start requests a device code and user code.
func (d *DeviceCode) Start(ctx context.Context) (DeviceAuthorization, error) {
	form := url.Values{"client_id": {d.ClientID}, "scope": {strings.Join(d.Scopes, " ")}}
	if d.ClientSecret != "" {
		form.Set("client_secret", d.ClientSecret)
	}
	r, err := exchange(ctx, d.DeviceAuthURL, d.HTTPClient, form, d.now)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	return parseDeviceAuthorization(r.status, r.retryAfter, r.body, r.start)
}

// Poll asks the token endpoint whether the person has signed in. It
// returns ErrAuthorizationPending or ErrSlowDown until then; a declined or
// expired sign-in is a permanent *Error (access_denied, expired_token).
func (d *DeviceCode) Poll(ctx context.Context, deviceCode string) (DeviceResult, error) {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {d.ClientID},
		"device_code": {deviceCode},
	}
	if d.ClientSecret != "" {
		form.Set("client_secret", d.ClientSecret)
	}
	r, err := exchange(ctx, d.TokenURL, d.HTTPClient, form, d.now)
	if err != nil {
		return DeviceResult{}, err
	}
	tok, refresh, err := parseResponse(r.status, r.retryAfter, r.body, r.start)
	var e *Error
	if errors.As(err, &e) {
		switch e.Code {
		case "authorization_pending":
			return DeviceResult{}, ErrAuthorizationPending
		case "slow_down":
			return DeviceResult{}, ErrSlowDown
		}
	}
	if err != nil {
		return DeviceResult{}, err
	}
	if refresh == "" {
		return DeviceResult{}, &Error{Permanent: true, Description: "the answer has no refresh token; the sign-in must grant offline_access"}
	}
	return DeviceResult{Token: tok, RefreshToken: refresh, Account: accountOf(r.body)}, nil
}

// parseDeviceAuthorization reads a device authorization answer (RFC 8628
// §3.2). The user code and verification URI end up in a status condition,
// so they must be short printable ASCII, and the URI an https URL.
func parseDeviceAuthorization(status int, retryAfter string, body []byte, now time.Time) (DeviceAuthorization, error) {
	if status != http.StatusOK {
		// The same error format as the token endpoint.
		_, _, err := parseResponse(status, retryAfter, body, now)
		return DeviceAuthorization{}, err
	}
	var r struct {
		DeviceCode      string    `json:"device_code"`
		UserCode        string    `json:"user_code"`
		VerificationURI string    `json:"verification_uri"`
		ExpiresIn       expiresIn `json:"expires_in"`
		Interval        expiresIn `json:"interval"`
	}
	if len(body) > maxResponseBytes || json.Unmarshal(body, &r) != nil {
		return DeviceAuthorization{}, &Error{Status: status, Description: "malformed device authorization response"}
	}
	u, err := url.Parse(r.VerificationURI)
	switch {
	case !isVisibleASCII(r.DeviceCode, maxRefreshTokenBytes):
		return DeviceAuthorization{}, &Error{Status: status, Description: "device_code is missing or not printable ASCII"}
	case !isVisibleASCII(r.UserCode, maxUserCodeLen):
		return DeviceAuthorization{}, &Error{Status: status, Description: "user_code is missing, too long or not printable ASCII"}
	case !isVisibleASCII(r.VerificationURI, maxVerificationURILen) || err != nil || u.Scheme != "https" || u.Host == "":
		return DeviceAuthorization{}, &Error{Status: status, Description: "verification_uri is not an https URL"}
	}
	lifetime := min(time.Duration(max(r.ExpiresIn, 0))*time.Second, maxDeviceCodeLifetime)
	if lifetime <= 0 {
		lifetime = 15 * time.Minute
	}
	interval := min(max(time.Duration(max(r.Interval, 0))*time.Second, minPollInterval), time.Minute)
	return DeviceAuthorization{DeviceCode: r.DeviceCode, UserCode: r.UserCode, VerificationURI: r.VerificationURI,
		ExpiresAt: now.Add(lifetime), Interval: interval}, nil
}

// accountOf reads the signed-in account from the id_token of a token
// answer. The ID token came straight from the token endpoint over TLS, so
// its claims are taken without checking the signature (OpenID Connect Core
// §3.1.3.7). It returns "" if there is no usable account.
func accountOf(body []byte) string {
	var r struct {
		IDToken string `json:"id_token"`
	}
	if json.Unmarshal(body, &r) != nil {
		return ""
	}
	parts := strings.Split(r.IDToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var c struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return ""
	}
	account := c.Email
	if account == "" {
		account = c.PreferredUsername
	}
	if !isVisibleASCII(account, maxAccountLen) {
		return ""
	}
	return account
}

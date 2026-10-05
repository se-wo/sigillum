package oauth

import (
	"strings"
	"testing"
	"time"
)

// FuzzParseResponse checks that a token endpoint answer either yields a
// usable bearer token with a bounded expiry, or an error whose provider
// text is safe to log.
func FuzzParseResponse(f *testing.F) {
	f.Add(200, "", []byte(`{"access_token":"eyJ0.eyJ1.sig","token_type":"Bearer","expires_in":3599}`))
	f.Add(200, "", []byte(`{"access_token":"ya29.a0Af","token_type":"bearer","expires_in":"3599"}`))
	f.Add(200, "", []byte(`{"access_token":"a\r\nb","token_type":"Bearer"}`))
	f.Add(400, "", []byte(`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`))
	f.Add(429, "120", []byte(``))
	f.Add(503, "Wed, 21 Oct 2026 07:28:00 GMT", []byte(`{"error":"temporarily_unavailable"}`))
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, status int, retryAfter string, body []byte) {
		tok, refresh, err := parseResponse(status, retryAfter, body, now)
		if err == nil {
			if status != 200 || !isB64Token(tok.AccessToken) || strings.ContainsAny(tok.AccessToken, "\x00\x01\r\n ") {
				t.Fatalf("accepted %q with status %d", tok.AccessToken, status)
			}
			if refresh != "" && !isVisibleASCII(refresh, maxRefreshTokenBytes) {
				t.Fatalf("accepted refresh token %q", refresh)
			}
			if !tok.Expiry.After(now) || tok.Expiry.After(now.Add(maxLifetime)) {
				t.Fatalf("expiry %v out of bounds", tok.Expiry.Sub(now))
			}
			return
		}
		e, ok := err.(*Error)
		if !ok {
			t.Fatalf("want *Error, got %T", err)
		}
		for _, s := range []string{e.Code, e.Description} {
			if len(s) > maxDescLen+3 {
				t.Fatalf("provider text not shortened: %d bytes", len(s))
			}
			for _, r := range s {
				if r < 0x20 || r >= 0x7f {
					t.Fatalf("unprintable %q in %q", r, s)
				}
			}
		}
		if e.RetryAfter < 0 || e.RetryAfter > maxRetryAfter {
			t.Fatalf("retry-after %v out of bounds", e.RetryAfter)
		}
		if (status == 429 || status >= 500) && e.Permanent {
			t.Fatalf("status %d must not be permanent", status)
		}
	})
}

// FuzzParseDeviceAuthorization checks that what a device authorization
// answer yields is safe to show in a status condition: short printable
// ASCII and an https verification URI, with bounded timings.
func FuzzParseDeviceAuthorization(f *testing.F) {
	f.Add(200, []byte(`{"device_code":"DAQABAAEAAAD","user_code":"ABCD1234","verification_uri":"https://www.microsoft.com/link","expires_in":900,"interval":5}`))
	f.Add(200, []byte(`{"device_code":"x","user_code":"A\r\nB","verification_uri":"javascript:alert(1)","expires_in":"99999999"}`))
	f.Add(400, []byte(`{"error":"invalid_client"}`))
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, status int, body []byte) {
		a, err := parseDeviceAuthorization(status, "", body, now)
		if err != nil {
			return
		}
		for _, s := range []string{a.DeviceCode, a.UserCode, a.VerificationURI} {
			if !isVisibleASCII(s, maxRefreshTokenBytes) {
				t.Fatalf("accepted %q", s)
			}
		}
		if len(a.UserCode) > maxUserCodeLen || !strings.HasPrefix(a.VerificationURI, "https://") {
			t.Fatalf("accepted user code %q, URI %q", a.UserCode, a.VerificationURI)
		}
		if !a.ExpiresAt.After(now) || a.ExpiresAt.After(now.Add(maxDeviceCodeLifetime)) ||
			a.Interval < minPollInterval || a.Interval > time.Minute {
			t.Fatalf("timings out of bounds: %+v", a)
		}
	})
}

// FuzzAccountOf checks that the account read from an ID token is printable
// ASCII of bounded length, or empty.
func FuzzAccountOf(f *testing.F) {
	f.Add([]byte(`{"id_token":"eyJhbGciOiJub25lIn0.eyJlbWFpbCI6Im1lQG91dGxvb2suY29tIn0.sig"}`))
	f.Add([]byte(`{"id_token":"a.b.c"}`))
	f.Add([]byte(`{"id_token":"eyJhbGciOiJub25lIn0.eyJlbWFpbCI6Im1lXHJcbkBvdXRsb29rLmNvbSJ9.sig"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if a := accountOf(body); a != "" && !isVisibleASCII(a, maxAccountLen) {
			t.Fatalf("accepted account %q", a)
		}
	})
}

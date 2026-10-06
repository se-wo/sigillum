package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GoogleServiceAccount is a Source for the JWT bearer grant (RFC 7523) of
// a Google service account: the source signs an assertion with the
// account's private key and redeems it for an access token. With Subject
// set, the token acts as that user (domain-wide delegation in Google
// Workspace); without, as the service account itself.
type GoogleServiceAccount struct {
	// Email and Key come from the service account's JSON key, see
	// ParseGoogleServiceAccount.
	Email string
	Key   *rsa.PrivateKey
	// KeyID is the key's ID; Google uses it to pick the public key.
	KeyID   string
	Scopes  []string
	Subject string
	// TokenURL is Google's token endpoint unless a test sets another https URL.
	TokenURL   string
	HTTPClient *http.Client

	now func() time.Time
}

const (
	// assertionLifetime is the longest Google accepts.
	assertionLifetime = time.Hour
	// googleTokenEndpoint receives service account assertions.
	googleTokenEndpoint = "https://oauth2.googleapis.com/token"
	maxEmailLen         = 320
)

// ParseGoogleServiceAccount reads the JSON key file of a service account
// (type "service_account"). Its token_uri must be Google's token endpoint:
// the signed assertion is sent there, and a key file is no place to
// redirect it.
func ParseGoogleServiceAccount(keyJSON []byte) (*GoogleServiceAccount, error) {
	var f struct {
		Type         string `json:"type"`
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		PrivateKeyID string `json:"private_key_id"`
		TokenURI     string `json:"token_uri"`
	}
	if err := json.Unmarshal(keyJSON, &f); err != nil {
		return nil, errors.New("the service account key is not valid JSON")
	}
	switch {
	case f.Type != "service_account":
		return nil, errors.New(`the key file is not of type "service_account"`)
	case !isVisibleASCII(f.ClientEmail, maxEmailLen) || !strings.Contains(f.ClientEmail, "@"):
		return nil, errors.New("the key file has no valid client_email")
	case f.TokenURI != "" && f.TokenURI != googleTokenEndpoint:
		return nil, errors.New("the key file's token_uri is not " + googleTokenEndpoint)
	}
	block, _ := pem.Decode([]byte(f.PrivateKey))
	if block == nil {
		return nil, errors.New("the key file has no PEM private_key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the private_key is not a PKCS #8 key")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the private_key is not an RSA key")
	}
	keyID := f.PrivateKeyID
	if !isVisibleASCII(keyID, maxCodeLen) {
		keyID = ""
	}
	return &GoogleServiceAccount{Email: f.ClientEmail, Key: key, KeyID: keyID}, nil
}

// Token implements Source.
func (s *GoogleServiceAccount) Token(ctx context.Context) (Token, error) {
	tokenURL := s.TokenURL
	if tokenURL == "" {
		tokenURL = googleTokenEndpoint
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	assertion, err := s.assertion(tokenURL, now())
	if err != nil {
		return Token{}, &Error{Permanent: true, Description: "sign the assertion: " + err.Error()}
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	tok, _, err := post(ctx, tokenURL, s.HTTPClient, form, s.now)
	return tok, err
}

// assertion builds and signs the JWT (RS256) that asks for a token.
func (s *GoogleServiceAccount) assertion(aud string, now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if s.KeyID != "" {
		header["kid"] = s.KeyID
	}
	claims := map[string]any{
		"iss":   s.Email,
		"scope": strings.Join(s.Scopes, " "),
		"aud":   aud,
		"iat":   now.Unix(),
		"exp":   now.Add(assertionLifetime).Unix(),
	}
	if s.Subject != "" {
		claims["sub"] = s.Subject
	}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

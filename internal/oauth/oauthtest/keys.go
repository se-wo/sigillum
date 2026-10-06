package oauthtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
)

// ServiceAccountKey returns a new RSA key and a Google service account
// JSON key file for it, with token_uri set as given ("" leaves it out).
func ServiceAccountKey(t testing.TB, email, tokenURI string) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f := map[string]string{
		"type":           "service_account",
		"client_email":   email,
		"private_key_id": "key-1",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	}
	if tokenURI != "" {
		f["token_uri"] = tokenURI
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return key, raw
}

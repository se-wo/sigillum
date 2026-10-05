package graph

import (
	"bytes"
	"errors"
	"net/mail"
	"strings"
	"testing"
)

// FuzzPrepare checks the envelope rule: whatever prepare accepts, Graph
// delivers to exactly the envelope recipients, because To and Cc name only
// envelope recipients and Bcc adds the rest.
func FuzzPrepare(f *testing.F) {
	f.Add([]byte("From: a@contoso.com\r\nTo: b@example.com\r\n\r\nx\r\n"), "b@example.com,c@example.com")
	f.Add([]byte("From: a@contoso.com\r\nTo: \"x, y\" <b@example.com>, c@example.com\r\nCc: =?utf-8?q?D?= <d@example.com>\r\n\r\nx"), "D@example.com,c@example.com,b@example.com")
	f.Add([]byte("From: a@contoso.com\r\nTo: undisclosed-recipients:;\r\n\r\nx"), "b@example.com")
	f.Add([]byte("From: a@contoso.com\r\nTo: b@example.com\r\nBcc: c@example.com\r\n\r\nx"), "b@example.com,c@example.com")
	f.Fuzz(func(t *testing.T, raw []byte, envelopeList string) {
		envelope := strings.Split(envelopeList, ",")
		out, from, err := prepare(raw, envelope)
		if err != nil {
			return
		}
		if !bytes.HasSuffix(out, raw) {
			t.Fatal("the original message must follow unchanged")
		}
		m, err := mail.ReadMessage(bytes.NewReader(out))
		if err != nil {
			t.Fatalf("prepared message does not parse: %v", err)
		}
		fromList, err := m.Header.AddressList("From")
		if err != nil || len(fromList) != 1 || fromList[0].Address != from {
			t.Fatalf("From %q does not match the header: %v %v", from, fromList, err)
		}
		inEnvelope := map[string]bool{}
		for _, r := range envelope {
			inEnvelope[strings.ToLower(r)] = true
		}
		delivered := map[string]bool{}
		for _, field := range []string{"To", "Cc", "Bcc"} {
			list, err := m.Header.AddressList(field)
			if errors.Is(err, mail.ErrHeaderNotPresent) {
				continue
			}
			if err != nil {
				t.Fatalf("%s does not parse after prepare: %v", field, err)
			}
			for _, a := range list {
				key := strings.ToLower(a.Address)
				if !inEnvelope[key] {
					t.Fatalf("%s delivers to %q outside the envelope %v", field, a.Address, envelope)
				}
				delivered[key] = true
			}
		}
		for r := range inEnvelope {
			if !delivered[r] {
				t.Fatalf("envelope recipient %q is not delivered", r)
			}
		}
	})
}

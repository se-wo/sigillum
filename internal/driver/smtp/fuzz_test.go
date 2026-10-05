package smtp

import (
	"bytes"
	"net/mail"
	"strings"
	"testing"

	"github.com/se-wo/sigillum/internal/driver"
)

// Fuzz targets for message assembly, which turns REST request fields into
// the RFC 5322 text relayed upstream. Seeds run with every `go test`;
// `make fuzz` explores further (see CONTRIBUTING.md).

func FuzzAssembleMessage(f *testing.F) {
	f.Add("Alerts", "hello", "X-Custom", "value", "text body", "", "report.pdf", "application/pdf", []byte("%PDF"))
	f.Add("", "", "", "", "", "<p>html</p>", "", "", []byte(nil))
	f.Add("Jörg \"J\" <x>", "Grüße =?utf-8?q?x?=", "Bcc", "b@x", "a\r\nb", "c\nd", `a"b\c.txt`, "", []byte{0, 1, 2})
	f.Add("n", "s", "X-Inject", "v\r\nBcc: evil@x", "t", "h", "f", "text/plain\r\nX: y", []byte("x"))
	f.Add("n", "s", "Bad Key:", "v", "t", "", "", "", []byte(nil))
	f.Fuzz(func(t *testing.T, name, subject, hk, hv, text, html, filename, ct string, content []byte) {
		msg := &driver.Message{
			From:    driver.Address{Name: name, Address: "from@example.com"},
			To:      []driver.Address{{Name: name, Address: "to@example.com"}},
			Subject: subject,
			Headers: map[string]string{hk: hv},
			Body:    driver.Body{Text: text, HTML: html},
		}
		if filename != "" || ct != "" || len(content) > 0 {
			msg.Attachments = []driver.Attachment{{Filename: filename, ContentType: ct, Content: content}}
		}
		raw, _, err := AssembleMessage(msg, "example.com")
		if err != nil {
			return
		}
		// Caller-controlled fields must never break out of their header:
		// the result parses, keeps the managed headers single and adds no
		// recipients.
		m, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("assembled message does not parse: %v\n%q", err, raw)
		}
		for _, k := range []string{"From", "To", "Subject", "Content-Type", "Mime-Version", "Message-Id"} {
			if len(m.Header[k]) > 1 {
				t.Fatalf("assembled message has %d %s headers:\n%q", len(m.Header[k]), k, raw)
			}
		}
		if len(m.Header["Bcc"]) > 0 || len(m.Header["Cc"]) > 0 {
			t.Fatalf("assembled message gained recipients:\n%q", raw)
		}
		from, err := m.Header.AddressList("From")
		if err != nil || len(from) != 1 || from[0].Address != "from@example.com" {
			t.Fatalf("From header = %v, %v:\n%q", from, err, raw)
		}
		to, err := m.Header.AddressList("To")
		if err != nil || len(to) != 1 || to[0].Address != "to@example.com" {
			t.Fatalf("To header = %v, %v:\n%q", to, err, raw)
		}
	})
}

func FuzzWriteQuotedPrintable(f *testing.F) {
	for _, s := range []string{"ascii body", "Grüße", strings.Repeat("a=", 60), "line\r\nbreak\n", "\x00\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var b bytes.Buffer
		writeQuotedPrintable(&b, s)
		// RFC 2045 §6.7: encoded lines are at most 76 characters, and the
		// output is 7-bit with CRLF line breaks only.
		for _, line := range strings.Split(b.String(), crlf) {
			if len(line) > 76 {
				t.Fatalf("line of %d characters for %q: %q", len(line), s, line)
			}
			for i := 0; i < len(line); i++ {
				if c := line[i]; c == '\r' || c == '\n' || c > 126 || (c < 32 && c != '\t') {
					t.Fatalf("byte %#x in encoded output for %q: %q", c, s, line)
				}
			}
		}
	})
}

// FuzzDescribeXOAUTH2Error checks that whatever the relay sends as its
// XOAUTH2 error challenge ends up in the error message as printable ASCII
// only, so it cannot break a log line or the SMTP reply to the client.
func FuzzDescribeXOAUTH2Error(f *testing.F) {
	f.Add([]byte(`{"status":"401","schemes":"bearer","scope":"https://outlook.office.com/SMTP.Send"}`))
	f.Add([]byte(`{"status":"401\r\n550 x","scope":"\u0000ä"}`))
	f.Add([]byte(`{"status":400}`))
	f.Fuzz(func(t *testing.T, challenge []byte) {
		s := describeXOAUTH2Error(challenge)
		for i := 0; i < len(s); i++ {
			if s[i] < 0x20 || s[i] > 0x7e {
				t.Fatalf("non-printable byte %#x in %q", s[i], s)
			}
		}
		if len(s) > 300 {
			t.Fatalf("description of %d bytes", len(s))
		}
	})
}

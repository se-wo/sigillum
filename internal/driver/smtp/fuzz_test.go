package smtp

import (
	"bytes"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"

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
		// In the top-level header block, no line may exceed the RFC 5322
		// §2.1.1 998-octet limit, however long the caller's subject, display
		// name or header value is.
		head := string(raw)
		if i := strings.Index(head, crlf+crlf); i >= 0 {
			head = head[:i]
		}
		for _, line := range strings.Split(head, crlf) {
			if len(line) > 998 {
				t.Fatalf("header line of %d octets exceeds 998:\n%q", len(line), line)
			}
		}
		// No RFC 2047 encoded-word that Sigillum writes may exceed 75
		// characters. Custom header values are written as the caller sent
		// them (docs/SPEC.md §4.4.1), so only the fields Sigillum encodes are
		// checked; net/mail has unfolded them.
		for _, k := range []string{"From", "To", "Subject"} {
			if w := longestEncodedWord(m.Header.Get(k)); w > 75 {
				t.Fatalf("encoded-word of %d characters exceeds 75 in %s:\n%q", w, k, raw)
			}
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

// FuzzAssembleRelated checks the structure built for inline parts (#80):
// a valid content ID ends up as exactly one Content-ID header next to the
// HTML in multipart/related, and an invalid one is refused, never written.
func FuzzAssembleRelated(f *testing.F) {
	f.Add("text", `<img src="cid:logo@x">`, "inline", "logo@x", true)
	f.Add("", "<p>x</p>", "INLINE", "a.b@c.d", false)
	f.Add("t", "", "inline", "logo@x", true)
	f.Add("t", "h", "attachment", "logo@x", false)
	f.Add("t", "h", "inline", "logo@x>\r\nBcc: evil@x", true)
	f.Add("t", "h", "inline", "<logo@x>", true)
	f.Fuzz(func(t *testing.T, text, html, disposition, cid string, withPDF bool) {
		atts := []driver.Attachment{{Filename: "logo.png", ContentType: "image/png", Disposition: disposition,
			ContentID: cid, Content: []byte("png")}}
		if withPDF {
			atts = append(atts, driver.Attachment{Filename: "a.pdf", ContentType: "application/pdf", Content: []byte("%PDF")})
		}
		raw, _, err := AssembleMessage(&driver.Message{From: driver.Address{Address: "from@example.com"},
			To: []driver.Address{{Address: "to@example.com"}}, Body: driver.Body{Text: text, HTML: html}, Attachments: atts}, "")
		valid := cid == "" || driver.ValidateContentID(cid) == nil
		if err != nil {
			if valid {
				t.Fatalf("valid input refused: %v", err)
			}
			return
		}
		if !valid {
			t.Fatalf("invalid content ID %q accepted:\n%q", cid, raw)
		}
		m, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("assembled message does not parse: %v\n%q", err, raw)
		}
		if len(m.Header["Bcc"]) > 0 {
			t.Fatalf("assembled message gained recipients:\n%q", raw)
		}
		tree, err := mimeTree(m.Header.Get("Content-Type"), "", m.Body)
		if err != nil {
			t.Fatalf("MIME structure does not parse: %v\n%q", err, raw)
		}
		if cid != "" && strings.Count(tree, "<"+cid+">") != 1 {
			t.Fatalf("content ID %q must appear once, got %s", cid, tree)
		}
		related := cid != "" && strings.TrimSpace(html) != "" && strings.EqualFold(disposition, "inline")
		if got := strings.Contains(tree, "related(text/html,image/png<"+cid+">)"); got != related {
			t.Fatalf("multipart/related = %v, want %v: %s", got, related, tree)
		}
	})
}

// FuzzRetryHint checks that a relay's reply text yields a delay only for
// 421 and 451, never a negative one, and only when it names a number.
func FuzzRetryHint(f *testing.F) {
	f.Add(451, "4.7.0 Try again in 30 seconds")
	f.Add(421, "retry after 5 min")
	f.Add(451, "Server busy. Please try again later")
	f.Add(550, "retry in 10 seconds")
	f.Add(451, "retry in 999999 minutes")
	f.Fuzz(func(t *testing.T, code int, msg string) {
		d := retryHint(deliveryError{&textproto.Error{Code: code, Msg: msg}})
		if d < 0 || d > 999999*time.Minute {
			t.Fatalf("%d %q: delay %v out of range", code, msg, d)
		}
		if d > 0 && code != 421 && code != 451 {
			t.Fatalf("%d %q: only 421 and 451 carry a delay, got %v", code, msg, d)
		}
		if d > 0 && !strings.ContainsAny(msg, "0123456789") {
			t.Fatalf("%d %q: delay %v without a number", code, msg, d)
		}
		if capped := driver.RetryAfter(driver.WithRetryAfter(driver.ErrUpstreamTransient, d)); capped > driver.MaxRetryAfter {
			t.Fatalf("WithRetryAfter(%v) = %v, above the cap", d, capped)
		}
	})
}

package apiserver

import (
	"bytes"
	"net/http"
	"net/textproto"
	"strings"
	"testing"

	"github.com/se-wo/sigillum/internal/policy"
)

// Fuzz targets for REST request parsing. Seeds run with every `go test`;
// `make fuzz` explores further (see CONTRIBUTING.md).

func FuzzParseMultipartMessage(f *testing.F) {
	const boundary = "b"
	f.Add(boundary, "--b\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\n"+
		`{"from":"a@x","to":["b@x"],"subject":"s","body":{"text":"t"}}`+
		"\r\n--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"r.pdf\"\r\n"+
		"Content-Type: application/pdf\r\n\r\n%PDF\r\n--b--\r\n")
	f.Add(boundary, "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a\r\nb\"\r\n\r\nx\r\n--b--\r\n")
	f.Add(boundary, "--b\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\n{\r\n--b--\r\n")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, boundary, body string) {
		const maxBytes = 1 << 16
		r, err := http.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
		if err != nil {
			return
		}
		r.Header.Set("Content-Type", "multipart/form-data; boundary=\""+boundary+"\"")
		_, atts, err := parseMultipartMessage(r, maxBytes)
		if err != nil {
			return
		}
		var total int
		for _, a := range atts {
			total += len(a.Content)
			if validateAttachmentMeta(requestAttachment{Filename: a.Filename, ContentType: a.ContentType, Disposition: a.Disposition}) != nil {
				t.Fatalf("attachment metadata with CR, LF or NUL accepted: %+v", a)
			}
		}
		if total > maxBytes {
			t.Fatalf("attachments of %d bytes accepted with a limit of %d", total, maxBytes)
		}
	})
}

func FuzzRequestHeaders(f *testing.F) {
	f.Add("X-Custom", "value", "Reply-To", "r@x.example, q@x.example")
	f.Add("Sender", "s@x.example", "reply-to", `"attacker@evil" <r@x.example>`)
	f.Add("x-a", "1", "X-A", "2")
	f.Add("Resent-From", "a@x", "Sender", "=?utf-8?q?a=40b?= <s@x>")
	f.Add("Bad\r\nKey", "v", "Sender", "a%b@x")
	f.Fuzz(func(t *testing.T, k1, v1, k2, v2 string) {
		h := map[string]string{k1: v1, k2: v2}
		if validateRequestHeaders(h) != nil {
			return
		}
		for k, v := range h {
			if strings.ContainsAny(k+v, "\r\n\x00") || len(k)+len(": ")+len(v) > maxHeaderLine ||
				strings.HasPrefix(textproto.CanonicalMIMEHeaderKey(k), "Resent-") {
				t.Fatalf("validateRequestHeaders accepted %q: %q", k, v)
			}
		}
		sender, replyTo, err := addressHeaders(h)
		if err != nil {
			return
		}
		for _, a := range append([]string{sender}, replyTo...) {
			if a == "" {
				continue
			}
			if err := policy.ValidateMailbox(a); err != nil {
				t.Fatalf("addressHeaders(%q) returned %q: %v", h, a, err)
			}
			if bytes.ContainsAny([]byte(a), "\r\n") {
				t.Fatalf("addressHeaders(%q) returned %q", h, a)
			}
		}
	})
}

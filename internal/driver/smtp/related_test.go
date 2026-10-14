package smtp

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"

	"github.com/se-wo/sigillum/internal/driver"
)

// mimeTree renders the MIME structure of an entity, e.g.
// "mixed(alternative(text/plain,related(text/html,image/png<logo@x>)),application/pdf)",
// with each leaf's Content-ID in angle brackets.
func mimeTree(contentType, contentID string, body io.Reader) (string, error) {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(mt, "multipart/") {
		_, _ = io.Copy(io.Discard, body)
		return mt + contentID, nil
	}
	var parts []string
	mr := multipart.NewReader(body, params["boundary"])
	for {
		p, err := mr.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		sub, err := mimeTree(p.Header.Get("Content-Type"), p.Header.Get("Content-ID"), p)
		if err != nil {
			return "", err
		}
		parts = append(parts, sub)
	}
	return strings.TrimPrefix(mt, "multipart/") + "(" + strings.Join(parts, ",") + ")", nil
}

func assembledTree(t *testing.T, msg *driver.Message) (string, []byte) {
	t.Helper()
	raw, _, err := AssembleMessage(msg, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	tree, err := mimeTree(m.Header.Get("Content-Type"), "", m.Body)
	if err != nil {
		t.Fatalf("%v:\n%s", err, raw)
	}
	return tree, raw
}

// #80: inline parts with a content ID go into multipart/related with the
// HTML that references them.
func TestAssemble_InlineImagesAreRelatedToTheHTML(t *testing.T) {
	logo := driver.Attachment{Filename: "logo.png", ContentType: "image/png", Disposition: "inline",
		ContentID: "logo@example.com", Content: []byte("\x89PNG")}
	chart := logo
	chart.Filename, chart.ContentID = "chart.png", "chart.1@example.com"
	pdf := driver.Attachment{Filename: "invoice.pdf", ContentType: "application/pdf", Content: []byte("%PDF")}
	noCID := driver.Attachment{Filename: "sig.png", ContentType: "image/png", Disposition: "inline", Content: []byte("x")}
	html := `<img src="cid:logo@example.com">`

	for name, tc := range map[string]struct {
		body driver.Body
		atts []driver.Attachment
		want string
	}{
		"text, html, inline, attachment": {driver.Body{Text: "t", HTML: html}, []driver.Attachment{logo, pdf, chart},
			"mixed(alternative(text/plain,related(text/html,image/png<logo@example.com>,image/png<chart.1@example.com>)),application/pdf)"},
		"text, html, inline": {driver.Body{Text: "t", HTML: html}, []driver.Attachment{logo},
			"alternative(text/plain,related(text/html,image/png<logo@example.com>))"},
		"html, inline": {driver.Body{HTML: html}, []driver.Attachment{logo},
			"related(text/html,image/png<logo@example.com>)"},
		"html, inline, attachment": {driver.Body{HTML: html}, []driver.Attachment{pdf, logo},
			"mixed(alternative(related(text/html,image/png<logo@example.com>)),application/pdf)"},
		// Without HTML nothing can reference the part: it stays an
		// ordinary part, its Content-ID kept.
		"text, inline": {driver.Body{Text: "t"}, []driver.Attachment{logo},
			"mixed(alternative(text/plain),image/png<logo@example.com>)"},
		// Inline without a content ID: unchanged from before.
		"html, inline without cid": {driver.Body{HTML: html}, []driver.Attachment{noCID},
			"mixed(alternative(text/html),image/png)"},
	} {
		t.Run(name, func(t *testing.T) {
			got, raw := assembledTree(t, &driver.Message{From: driver.Address{Address: "from@example.com"},
				To: []driver.Address{{Address: "to@example.com"}}, Body: tc.body, Attachments: tc.atts})
			if got != tc.want {
				t.Fatalf("got  %s\nwant %s\n%s", got, tc.want, raw)
			}
			if strings.Contains(got, "related(") && !strings.Contains(string(raw), `multipart/related; type="text/html"`) {
				t.Fatalf("multipart/related must name its root type (RFC 2387):\n%s", raw)
			}
		})
	}
}

func TestAssemble_RejectsInvalidContentID(t *testing.T) {
	for _, cid := range []string{"logo", "<logo@x>", "lo go@x", "logo@x\r\nBcc: evil@x", "a@b@c", ".a@b", "a@b.", "a..b@c"} {
		_, _, err := AssembleMessage(&driver.Message{From: driver.Address{Address: "from@example.com"},
			To: []driver.Address{{Address: "to@example.com"}}, Body: driver.Body{HTML: "<p>x</p>"},
			Attachments: []driver.Attachment{{Filename: "a.png", Disposition: "inline", ContentID: cid, Content: []byte("x")}}}, "")
		if err == nil {
			t.Errorf("content ID %q must be rejected", cid)
		}
	}
}

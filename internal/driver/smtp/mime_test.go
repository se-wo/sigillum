package smtp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"

	"github.com/se-wo/sigillum/internal/driver"
)

func parseMessage(t *testing.T, raw []byte) (*mail.Message, string) {
	t.Helper()
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}
	return m, m.Header.Get("Content-Type")
}

func TestAssemble_TextOnly(t *testing.T) {
	msg := &driver.Message{
		From:    driver.Address{Address: "from@example.com"},
		To:      []driver.Address{{Address: "to@example.com"}},
		Subject: "hello",
		Body:    driver.Body{Text: "ascii body"},
	}
	raw, id, err := AssembleMessage(msg, "sigillum")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "<") {
		t.Fatalf("expected message-id, got %q", id)
	}
	m, ct := parseMessage(t, raw)
	if !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("want text/plain, got %s", ct)
	}
	body := readAll(t, m)
	if !strings.Contains(body, "ascii body") {
		t.Fatalf("body missing: %q", body)
	}
	if m.Header.Get("From") != "from@example.com" {
		t.Fatalf("from header wrong: %q", m.Header.Get("From"))
	}
}

func TestAssemble_HTMLOnly(t *testing.T) {
	msg := &driver.Message{
		From: driver.Address{Address: "from@example.com"},
		To:   []driver.Address{{Address: "to@example.com"}},
		Body: driver.Body{HTML: "<p>hi</p>"},
	}
	raw, _, err := AssembleMessage(msg, "")
	if err != nil {
		t.Fatal(err)
	}
	_, ct := parseMessage(t, raw)
	if !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("want text/html, got %s", ct)
	}
}

func TestAssemble_Alternative(t *testing.T) {
	msg := &driver.Message{
		From: driver.Address{Address: "from@example.com"},
		To:   []driver.Address{{Address: "to@example.com"}},
		Body: driver.Body{Text: "plain", HTML: "<p>html</p>"},
	}
	raw, _, err := AssembleMessage(msg, "")
	if err != nil {
		t.Fatal(err)
	}
	m, ct := parseMessage(t, raw)
	mt, params, _ := mime.ParseMediaType(ct)
	if mt != "multipart/alternative" {
		t.Fatalf("want alternative, got %s", mt)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	parts := readParts(t, mr)
	if len(parts) != 2 {
		t.Fatalf("want 2 parts, got %d", len(parts))
	}
	if !strings.HasPrefix(parts[0].header, "text/plain") {
		t.Fatalf("first part want text/plain, got %s", parts[0].header)
	}
	if !strings.HasPrefix(parts[1].header, "text/html") {
		t.Fatalf("second part want text/html, got %s", parts[1].header)
	}
}

func TestAssemble_MixedWithAttachment(t *testing.T) {
	att := []byte("hello pdf bytes")
	msg := &driver.Message{
		From: driver.Address{Address: "from@example.com"},
		To:   []driver.Address{{Address: "to@example.com"}},
		Body: driver.Body{Text: "see attached"},
		Attachments: []driver.Attachment{{
			Filename:    "x.pdf",
			ContentType: "application/pdf",
			Content:     att,
		}},
	}
	raw, _, err := AssembleMessage(msg, "")
	if err != nil {
		t.Fatal(err)
	}
	m, ct := parseMessage(t, raw)
	mt, params, _ := mime.ParseMediaType(ct)
	if mt != "multipart/mixed" {
		t.Fatalf("want mixed, got %s", mt)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	parts := readParts(t, mr)
	if len(parts) != 2 {
		t.Fatalf("want 2 parts (body + attachment), got %d", len(parts))
	}
	// Find the attachment part.
	var attPart partOut
	for _, p := range parts {
		if strings.Contains(p.header, "application/pdf") {
			attPart = p
		}
	}
	if attPart.header == "" {
		t.Fatal("attachment part not found")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.ReplaceAll(string(attPart.body), "\r", ""), "\n", ""))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if !bytes.Equal(decoded, att) {
		t.Fatalf("attachment round-trip failed:\nwant=%q\ngot=%q", att, decoded)
	}
}

func TestAssemble_RejectsNoRecipients(t *testing.T) {
	_, _, err := AssembleMessage(&driver.Message{From: driver.Address{Address: "x@y"}}, "")
	if err == nil {
		t.Fatal("expected error for missing recipients")
	}
}

func TestAssemble_RejectsMissingFrom(t *testing.T) {
	_, _, err := AssembleMessage(&driver.Message{To: []driver.Address{{Address: "to@x"}}}, "")
	if err == nil {
		t.Fatal("expected error for missing from")
	}
}

func TestAssemble_ReservedHeaderIgnored(t *testing.T) {
	msg := &driver.Message{
		From:    driver.Address{Address: "a@b"},
		To:      []driver.Address{{Address: "c@d"}},
		Subject: "real",
		Body:    driver.Body{Text: "x"},
		Headers: map[string]string{"Subject": "evil-override"},
	}
	raw, _, err := AssembleMessage(msg, "")
	if err != nil {
		t.Fatal(err)
	}
	m, _ := parseMessage(t, raw)
	if got := m.Header.Get("Subject"); !strings.Contains(got, "real") {
		t.Fatalf("subject was overridden by reserved header: %q", got)
	}
}

func TestAssemble_RejectsHeaderValueCRLF(t *testing.T) {
	msg := &driver.Message{
		From:    driver.Address{Address: "a@b"},
		To:      []driver.Address{{Address: "c@d"}},
		Body:    driver.Body{Text: "x"},
		Headers: map[string]string{"X-Corr": "ok\r\nBcc: evil@x"},
	}
	_, _, err := AssembleMessage(msg, "")
	if err == nil {
		t.Fatal("expected error for CRLF in header value")
	}
}

func TestAssemble_RejectsHeaderKeyCRLF(t *testing.T) {
	msg := &driver.Message{
		From:    driver.Address{Address: "a@b"},
		To:      []driver.Address{{Address: "c@d"}},
		Body:    driver.Body{Text: "x"},
		Headers: map[string]string{"X-Bad\r\nKey": "val"},
	}
	_, _, err := AssembleMessage(msg, "")
	if err == nil {
		t.Fatal("expected error for CRLF in header key")
	}
}

func TestAssemble_RejectsAttachmentFilenameCRLF(t *testing.T) {
	msg := &driver.Message{
		From: driver.Address{Address: "a@b"},
		To:   []driver.Address{{Address: "c@d"}},
		Body: driver.Body{Text: "x"},
		Attachments: []driver.Attachment{{
			Filename:    "evil\r\nBcc: x@y",
			ContentType: "text/plain",
			Content:     []byte("data"),
		}},
	}
	_, _, err := AssembleMessage(msg, "")
	if err == nil {
		t.Fatal("expected error for CRLF in attachment filename")
	}
}

func TestAssemble_EscapesQuotesInFilename(t *testing.T) {
	msg := &driver.Message{
		From: driver.Address{Address: "a@b"},
		To:   []driver.Address{{Address: "c@d"}},
		Body: driver.Body{Text: "x"},
		Attachments: []driver.Attachment{{
			Filename:    `file"name.txt`,
			ContentType: "text/plain",
			Content:     []byte("data"),
		}},
	}
	raw, _, err := AssembleMessage(msg, "")
	if err != nil {
		t.Fatal(err)
	}
	// The double-quote in the filename must be escaped in the wire bytes.
	if strings.Contains(string(raw), `filename="file"name`) {
		t.Fatal("unescaped double-quote found in Content-Disposition filename")
	}
}

// longestEncodedWord returns the length of the longest RFC 2047 encoded-word
// (=?...?=) in raw, or 0 if there is none.
func longestEncodedWord(raw string) int {
	longest := 0
	for {
		i := strings.Index(raw, "=?")
		if i < 0 {
			break
		}
		j := strings.Index(raw[i+2:], "?=")
		if j < 0 {
			break
		}
		w := j + 4 // "=?" + inner + "?="
		if w > longest {
			longest = w
		}
		raw = raw[i+2+j+2:]
	}
	return longest
}

func assertLineLimits(t *testing.T, raw []byte) {
	t.Helper()
	// RFC 5322 §2.1.1: every line in the top-level header block is at most
	// 998 octets.
	head := string(raw)
	if i := strings.Index(head, crlf+crlf); i >= 0 {
		head = head[:i]
	}
	for _, line := range strings.Split(head, crlf) {
		if len(line) > 998 {
			t.Fatalf("line of %d octets exceeds the 998 limit: %q", len(line), line)
		}
	}
}

func TestAssemble_FoldsLongSubject(t *testing.T) {
	for _, subject := range []string{
		"folding " + strings.TrimSpace(strings.Repeat("alpha ", 300)), // long ASCII
		"folding " + strings.TrimSpace(strings.Repeat("Grüße ", 300)), // long UTF-8
	} {
		msg := &driver.Message{
			From:    driver.Address{Address: "from@example.com"},
			To:      []driver.Address{{Address: "to@example.com"}},
			Subject: subject,
			Body:    driver.Body{Text: "x"},
		}
		raw, _, err := AssembleMessage(msg, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		assertLineLimits(t, raw)
		if w := longestEncodedWord(string(raw)); w > 75 {
			t.Fatalf("encoded-word of %d characters exceeds the 75 limit", w)
		}
		m, _ := parseMessage(t, raw)
		got, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
		if err != nil {
			t.Fatalf("decode subject: %v", err)
		}
		// Folding and encoding must not change the words of the subject.
		if strings.Join(strings.Fields(got), " ") != strings.Join(strings.Fields(subject), " ") {
			t.Fatalf("subject round-trip changed the text:\nwant %q\ngot  %q", subject, got)
		}
	}
}

func TestAssemble_FoldsLongRecipientList(t *testing.T) {
	var to []driver.Address
	for i := 0; i < 40; i++ {
		to = append(to, driver.Address{Name: "Team Member Number", Address: fmt.Sprintf("user%02d@example.com", i)})
	}
	raw, _, err := AssembleMessage(&driver.Message{
		From: driver.Address{Address: "from@example.com"},
		To:   to,
		Body: driver.Body{Text: "x"},
	}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	assertLineLimits(t, raw)
	m, _ := parseMessage(t, raw)
	list, err := m.Header.AddressList("To")
	if err != nil || len(list) != len(to) {
		t.Fatalf("To list = %d addresses, %v; want %d", len(list), err, len(to))
	}
}

// attachmentPart walks the assembled multipart/mixed message and returns the
// header of the first part whose Content-Disposition is an attachment.
func attachmentPart(t *testing.T, raw []byte) textproto.MIMEHeader {
	t.Helper()
	m, ct := parseMessage(t, raw)
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("top-level content-type %q: %v", ct, err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		if strings.HasPrefix(p.Header.Get("Content-Disposition"), "attachment") ||
			strings.HasPrefix(p.Header.Get("Content-Disposition"), "inline") {
			return p.Header
		}
	}
	t.Fatal("attachment part not found")
	return nil
}

func TestAssemble_AttachmentUnicodeFilename(t *testing.T) {
	name := "Rëchnung 2026 €.pdf"
	raw, _, err := AssembleMessage(&driver.Message{
		From:        driver.Address{Address: "a@b"},
		To:          []driver.Address{{Address: "c@d"}},
		Body:        driver.Body{Text: "x"},
		Attachments: []driver.Attachment{{Filename: name, ContentType: "application/pdf", Content: []byte("%PDF")}},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	h := attachmentPart(t, raw)
	// mime.ParseMediaType decodes the RFC 2231 filename*= back to the original.
	_, params, err := mime.ParseMediaType(h.Get("Content-Disposition"))
	if err != nil {
		t.Fatalf("parse content-disposition %q: %v", h.Get("Content-Disposition"), err)
	}
	if params["filename"] != name {
		t.Fatalf("filename round-trip: want %q, got %q (header %q)", name, params["filename"], h.Get("Content-Disposition"))
	}
	// A plain ASCII fallback is present for old clients, and no raw UTF-8 byte
	// leaks into the header.
	if !strings.Contains(h.Get("Content-Disposition"), `filename="R`) {
		t.Fatalf("no ASCII filename fallback: %q", h.Get("Content-Disposition"))
	}
}

func TestAssemble_AttachmentContentTypeParamsStripped(t *testing.T) {
	raw, _, err := AssembleMessage(&driver.Message{
		From:        driver.Address{Address: "a@b"},
		To:          []driver.Address{{Address: "c@d"}},
		Body:        driver.Body{Text: "x"},
		Attachments: []driver.Attachment{{Filename: "a.txt", ContentType: `text/plain; name="evil.exe"; charset=utf-8`, Content: []byte("x")}},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	h := attachmentPart(t, raw)
	mt, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse content-type %q: %v", h.Get("Content-Type"), err)
	}
	if mt != "text/plain" {
		t.Fatalf("media type: want text/plain, got %q", mt)
	}
	if _, ok := params["name"]; ok {
		t.Fatalf("caller name parameter leaked into Content-Type: %q", h.Get("Content-Type"))
	}
	if params["charset"] != "utf-8" {
		t.Fatalf("charset dropped for text/*: %q", h.Get("Content-Type"))
	}
	_, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	if dparams["filename"] != "a.txt" {
		t.Fatalf("disposition filename: want a.txt, got %q", dparams["filename"])
	}
}

func TestAssemble_AttachmentBadContentTypeRejected(t *testing.T) {
	_, _, err := AssembleMessage(&driver.Message{
		From:        driver.Address{Address: "a@b"},
		To:          []driver.Address{{Address: "c@d"}},
		Body:        driver.Body{Text: "x"},
		Attachments: []driver.Attachment{{Filename: "a.txt", ContentType: "not a media type", Content: []byte("x")}},
	}, "")
	if err == nil {
		t.Fatal("expected error for an unparseable contentType")
	}
}

type partOut struct {
	header string
	body   []byte
}

func readParts(t *testing.T, mr *multipart.Reader) []partOut {
	t.Helper()
	var out []partOut
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(p)
		out = append(out, partOut{header: p.Header.Get("Content-Type"), body: buf.Bytes()})
	}
	return out
}

func readAll(t *testing.T, m *mail.Message) string {
	t.Helper()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(m.Body); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestAssemble_DisplayNamesStayInsideTheirAddress(t *testing.T) {
	for _, name := range []string{
		`x@evil.example, y`,
		`Jörg "J" <x>`,
		`Alerts (ops)`,
		`Grüße`,
		`Grüße \ "x" <y>`,
		"tab\tand\x01control\\",
		`plain`,
	} {
		raw, _, err := AssembleMessage(&driver.Message{
			From: driver.Address{Name: name, Address: "from@example.com"},
			To:   []driver.Address{{Name: name, Address: "to@example.com"}},
		}, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		m, _ := parseMessage(t, raw)
		for k, want := range map[string]string{"From": "from@example.com", "To": "to@example.com"} {
			list, err := m.Header.AddressList(k)
			if err != nil || len(list) != 1 || list[0].Address != want || list[0].Name != name {
				t.Errorf("name %q: %s = %v, %v; header %q", name, k, list, err, m.Header.Get(k))
			}
		}
	}
}

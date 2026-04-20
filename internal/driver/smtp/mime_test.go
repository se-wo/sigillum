package smtp

import (
	"bytes"
	"encoding/base64"
	"mime"
	"mime/multipart"
	"net/mail"
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

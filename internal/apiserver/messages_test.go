package apiserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"testing"

	"github.com/se-wo/sigillum/internal/driver"
)

type testAttachment struct {
	name    string
	ct      string
	content []byte
}

func TestValidateAttachmentMeta(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    requestAttachment
		ok   bool
	}{
		{"plain", requestAttachment{Filename: "report.pdf", ContentType: "application/pdf"}, true},
		{"unicode filename ok", requestAttachment{Filename: "Rëchnung €.pdf"}, true},
		{"no contentType ok", requestAttachment{Filename: "a.txt"}, true},
		{"CRLF filename", requestAttachment{Filename: "a\r\nb.txt"}, false},
		{"NUL filename", requestAttachment{Filename: "a\x00b"}, false},
		{"RLO spoof", requestAttachment{Filename: "invoice‮fdp.exe"}, false},
		{"RLI spoof", requestAttachment{Filename: "a⁧b.exe"}, false},
		{"LRM", requestAttachment{Filename: "a‎b"}, false},
		{"bad contentType", requestAttachment{Filename: "a", ContentType: "not a media type"}, false},
		{"contentType with params ok", requestAttachment{Filename: "a", ContentType: `text/plain; charset=utf-8`}, true},
	} {
		err := validateAttachmentMeta(tc.a)
		if (err == nil) != tc.ok {
			t.Errorf("%s: validateAttachmentMeta = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestParseMultipartMessage_NoAttachments(t *testing.T) {
	body, ct := buildMultipartBody(t, map[string]interface{}{
		"from":    "sender@example.com",
		"to":      []string{"rcpt@example.com"},
		"subject": "Hello",
		"body":    map[string]string{"text": "world"},
	}, nil)

	r, _ := http.NewRequest(http.MethodPost, "/v1/messages", body)
	r.Header.Set("Content-Type", ct)

	req, atts, err := parseMultipartMessage(r, 32*1024*1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.From != "sender@example.com" {
		t.Errorf("from: got %q", req.From)
	}
	if len(req.To) != 1 || req.To[0] != "rcpt@example.com" {
		t.Errorf("to: got %v", req.To)
	}
	if req.Body.Text != "world" {
		t.Errorf("body.text: got %q", req.Body.Text)
	}
	if len(atts) != 0 {
		t.Errorf("expected 0 attachments, got %d", len(atts))
	}
}

func TestParseMultipartMessage_WithAttachments(t *testing.T) {
	att := testAttachment{name: "invoice.pdf", ct: "application/pdf", content: []byte("%PDF fake")}

	body, ct := buildMultipartBody(t, map[string]interface{}{
		"from": "a@b.com",
		"to":   []string{"c@d.com"},
	}, []testAttachment{att})

	r, _ := http.NewRequest(http.MethodPost, "/v1/messages", body)
	r.Header.Set("Content-Type", ct)

	req, atts, err := parseMultipartMessage(r, 32*1024*1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.From != "a@b.com" {
		t.Errorf("from: got %q", req.From)
	}
	if len(atts) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(atts))
	}
	if atts[0].Filename != "invoice.pdf" {
		t.Errorf("filename: got %q", atts[0].Filename)
	}
	if atts[0].ContentType != "application/pdf" {
		t.Errorf("content-type: got %q", atts[0].ContentType)
	}
	if string(atts[0].Content) != "%PDF fake" {
		t.Errorf("content: got %q", atts[0].Content)
	}
}

func TestParseMultipartMessage_SizeLimitExceeded(t *testing.T) {
	body, ct := buildMultipartBody(t, map[string]interface{}{
		"from": "a@b.com",
		"to":   []string{"c@d.com"},
	}, nil)

	r, _ := http.NewRequest(http.MethodPost, "/v1/messages", body)
	r.Header.Set("Content-Type", ct)

	// Set limit to 1 byte — should fail.
	_, _, err := parseMultipartMessage(r, 1)
	if err == nil {
		t.Fatal("expected error for oversized body")
	}
}

func TestParseMultipartMessage_BadJSON(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("data", "not-valid-json")
	w.Close()

	r, _ := http.NewRequest(http.MethodPost, "/v1/messages", &buf)
	r.Header.Set("Content-Type", w.FormDataContentType())

	_, _, err := parseMultipartMessage(r, 32*1024*1024)
	if err == nil {
		t.Fatal("expected error for bad JSON in data part")
	}
}

func TestParseMultipartMessage_UnknownFieldInData(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("data", `{"from":"a@x.example","to":["b@x.example"],"text":"hi"}`)
	w.Close()

	r, _ := http.NewRequest(http.MethodPost, "/v1/messages", &buf)
	r.Header.Set("Content-Type", w.FormDataContentType())

	_, _, err := parseMultipartMessage(r, 32*1024*1024)
	if err == nil || !strings.Contains(err.Error(), "did you mean body.text?") {
		t.Fatalf("want an unknown-field error with a hint, got %v", err)
	}
}

// A misplaced message field sent as a plain form field is refused rather
// than mailed as a file named after it; any other plain form field is
// still an attachment.
func TestParseMultipartMessage_FormFields(t *testing.T) {
	parse := func(fields ...string) ([]driver.Attachment, error) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		_ = w.WriteField("data", `{"from":"a@x.example","to":["b@x.example"]}`)
		for i := 0; i+1 < len(fields); i += 2 {
			_ = w.WriteField(fields[i], fields[i+1])
		}
		w.Close()
		r, _ := http.NewRequest(http.MethodPost, "/v1/messages", &buf)
		r.Header.Set("Content-Type", w.FormDataContentType())
		_, atts, err := parseMultipartMessage(r, 32*1024*1024)
		return atts, err
	}
	if _, err := parse("text", "Hello"); err == nil || !strings.Contains(err.Error(), "did you mean body.text in the data part?") {
		t.Fatalf("text field: want a hint, got %v", err)
	}
	if _, err := parse("Subject", "Hi"); err == nil || !strings.Contains(err.Error(), "belongs in the data part") {
		t.Fatalf("subject field: want a refusal, got %v", err)
	}
	if _, err := parse("data", `{}`); err == nil || !strings.Contains(err.Error(), "more than one data part") {
		t.Fatalf("second data part: want a refusal, got %v", err)
	}
	atts, err := parse("report", "content")
	if err != nil || len(atts) != 1 || atts[0].Filename != "report" || string(atts[0].Content) != "content" {
		t.Fatalf("plain field: want one attachment, got %+v, %v", atts, err)
	}
}

// Base64 attachments in the data part are sent along with the file parts.
func TestParseMultipartMessage_AttachmentsInData(t *testing.T) {
	body, ct := buildMultipartBody(t, map[string]any{
		"from": "a@x.example", "to": []string{"b@x.example"}, "body": map[string]string{"text": "see attached"},
		"attachments": []map[string]string{{"filename": "inv.pdf", "contentBase64": "JVBERg=="}},
	}, []testAttachment{{name: "r.txt", ct: "text/plain", content: []byte("x")}})
	r, _ := http.NewRequest(http.MethodPost, "/v1/messages", body)
	r.Header.Set("Content-Type", ct)
	_, atts, err := parseMultipartMessage(r, 32*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 2 || atts[0].Filename != "inv.pdf" || string(atts[0].Content) != "%PDF" || atts[1].Filename != "r.txt" {
		t.Fatalf("want inv.pdf from data and r.txt, got %+v", atts)
	}

	body, ct = buildMultipartBody(t, map[string]any{
		"from": "a@x.example", "to": []string{"b@x.example"},
		"attachments": []map[string]string{{"filename": "a\r\nb", "contentBase64": "eA=="}},
	}, nil)
	r, _ = http.NewRequest(http.MethodPost, "/v1/messages", body)
	r.Header.Set("Content-Type", ct)
	if _, _, err := parseMultipartMessage(r, 32*1024*1024); err == nil {
		t.Fatal("want a CRLF filename in the data part refused")
	}
}

func TestParseMultipartMessage_MissingDataPart(t *testing.T) {
	// A multipart body with no "data" part should return an empty requestBody,
	// not an error — the address-parsing step will catch the empty from/to.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="attachment"; filename="file.txt"`)
	h.Set("Content-Type", "text/plain")
	pw, _ := mw.CreatePart(h)
	fmt.Fprint(pw, "hello")
	mw.Close()

	r, _ := http.NewRequest(http.MethodPost, "/v1/messages", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())

	req, atts, err := parseMultipartMessage(r, 32*1024*1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.From != "" {
		t.Errorf("expected empty from, got %q", req.From)
	}
	if len(atts) != 1 {
		t.Errorf("expected 1 attachment, got %d", len(atts))
	}
}

// buildMultipartBody writes a multipart/form-data body with a JSON data part
// and optional binary attachments.
func buildMultipartBody(t *testing.T, meta interface{}, attachments []testAttachment) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := w.WriteField("data", string(metaJSON)); err != nil {
		t.Fatalf("write data field: %v", err)
	}

	for _, att := range attachments {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="attachment"; filename=%q`, att.name))
		h.Set("Content-Type", att.ct)
		pw, err := w.CreatePart(h)
		if err != nil {
			t.Fatalf("create part: %v", err)
		}
		if _, err := pw.Write(att.content); err != nil {
			t.Fatalf("write part: %v", err)
		}
	}
	w.Close()
	return &buf, w.FormDataContentType()
}

package apiserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"testing"
)

type testAttachment struct {
	name    string
	ct      string
	content []byte
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

package apiserver

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"testing"

	"github.com/se-wo/sigillum/internal/driver"
)

type filePart struct {
	name, filename, contentID string
}

// multipartWithFiles builds a request with a data part and file parts,
// each optionally carrying a Content-ID part header.
func multipartWithFiles(t *testing.T, data map[string]any, files ...filePart) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	dw, _ := mw.CreateFormField("data")
	if err := json.NewEncoder(dw).Encode(data); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="`+f.name+`"; filename="`+f.filename+`"`)
		h.Set("Content-Type", "image/png")
		if f.contentID != "" {
			h.Set("Content-ID", f.contentID)
		}
		pw, _ := mw.CreatePart(h)
		_, _ = pw.Write([]byte("png"))
	}
	_ = mw.Close()
	r, _ := http.NewRequest(http.MethodPost, "/v1/messages", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

// #80: a file part gets its content ID from contentIds in the data part
// or from a Content-ID part header, and is then sent inline.
func TestParseMultipartMessage_ContentIDs(t *testing.T) {
	base := func(ids map[string]string) map[string]any {
		return map[string]any{"from": "a@x.example", "to": []string{"b@x.example"},
			"body": map[string]string{"html": `<img src="cid:logo@x.example">`}, "contentIds": ids}
	}
	r := multipartWithFiles(t, base(map[string]string{"logo": "logo@x.example"}),
		filePart{name: "logo", filename: "logo.png"},
		filePart{name: "chart", filename: "chart.png", contentID: "<chart@x.example>"},
		filePart{name: "report", filename: "report.pdf"})
	_, atts, err := parseMultipartMessage(r, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	want := []driver.Attachment{
		{Filename: "logo.png", Disposition: "inline", ContentID: "logo@x.example"},
		{Filename: "chart.png", Disposition: "inline", ContentID: "chart@x.example"},
		{Filename: "report.pdf"},
	}
	if len(atts) != len(want) {
		t.Fatalf("got %+v", atts)
	}
	for i, w := range want {
		if a := atts[i]; a.Filename != w.Filename || a.Disposition != w.Disposition || a.ContentID != w.ContentID {
			t.Errorf("attachment %d: got %+v, want %+v", i, a, w)
		}
	}

	for name, tc := range map[string]struct {
		ids   map[string]string
		files []filePart
		want  string
	}{
		"unknown part":    {map[string]string{"nope": "a@x"}, []filePart{{name: "logo", filename: "l.png"}}, `no file part is named "nope"`},
		"ambiguous part":  {map[string]string{"img": "a@x"}, []filePart{{name: "img", filename: "1.png"}, {name: "img", filename: "2.png"}}, "more than one"},
		"header and data": {map[string]string{"logo": "a@x"}, []filePart{{name: "logo", filename: "l.png", contentID: "<b@x>"}}, "already has a Content-ID"},
		"invalid in data": {map[string]string{"logo": "logo"}, []filePart{{name: "logo", filename: "l.png"}}, "id-left@id-right"},
		"invalid header":  {nil, []filePart{{name: "logo", filename: "l.png", contentID: "<a b@x>"}}, "id-left@id-right"},
	} {
		r := multipartWithFiles(t, base(tc.ids), tc.files...)
		if _, _, err := parseMultipartMessage(r, 1<<20); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want an error with %q, got %v", name, tc.want, err)
		}
	}
}

func TestHandleSendMessage_ContentIDRules(t *testing.T) {
	const png = `"contentBase64":"cG5n"`
	for name, tc := range map[string]struct {
		body, want string
	}{
		"duplicate": {`{"from":"a@team.example","to":["b@x.example"],"body":{"html":"<p>x</p>"},"attachments":[` +
			`{"filename":"a.png","disposition":"inline","contentId":"logo@x",` + png + `},` +
			`{"filename":"b.png","disposition":"inline","contentId":"LOGO@x",` + png + `}]}`, "used by more than one attachment"},
		"not inline": {`{"from":"a@team.example","to":["b@x.example"],"body":{"html":"<p>x</p>"},"attachments":[` +
			`{"filename":"a.png","contentId":"logo@x",` + png + `}]}`, `needs disposition \"inline\"`},
		"contentIds in JSON": {`{"from":"a@team.example","to":["b@x.example"],"body":{"html":"<p>x</p>"},"contentIds":{"a":"b@x"}}`,
			"set contentId on the attachment"},
	} {
		s, sink := newTestServer()
		w := post(s, tc.body)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s: want 400 with %q, got %d %s", name, tc.want, w.Code, w.Body.String())
		}
		if len(sink.events) != 1 || sink.events[0].Reason != "invalid_payload" {
			t.Errorf("%s: want one invalid_payload audit record, got %+v", name, sink.events)
		}
	}
	// A valid one passes the payload checks and reaches the policy.
	s, _ := newTestServer()
	w := post(s, `{"from":"a@team.example","to":["b@x.example"],"body":{"html":"<img src=\"cid:logo@x\">"},"attachments":[`+
		`{"filename":"a.png","disposition":"inline","contentId":"logo@x",`+png+`}]}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want the payload accepted (403 no policy), got %d %s", w.Code, w.Body.String())
	}
}

func TestDecodeAttachments_KeepsContentID(t *testing.T) {
	atts, err := decodeAttachments([]requestAttachment{{Filename: "a.png", Disposition: "inline", ContentID: "logo@x", ContentBase64: "cG5n"}})
	if err != nil || len(atts) != 1 || atts[0].ContentID != "logo@x" || atts[0].Disposition != "inline" {
		t.Fatalf("got %+v, %v", atts, err)
	}
}

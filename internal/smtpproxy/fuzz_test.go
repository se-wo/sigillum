package smtpproxy

import (
	"bytes"
	"net/mail"
	"testing"

	"github.com/se-wo/sigillum/internal/policy"
)

// Fuzz targets for the parts of the SMTP proxy that read the raw DATA of
// untrusted clients. Seeds run with every `go test`; `make fuzz` explores
// further (see CONTRIBUTING.md).

var messageSeeds = []string{
	"From: a@x.example\r\nTo: b@x.example\r\nSubject: s\r\n\r\nbody\r\n",
	"From: a@x\r\nBcc: hidden@x,\r\n\tother@x\r\nTo: b@x\r\n\r\nBcc: in body stays\r\n",
	"bcc: h@x\r\nResent-BCC: r@x\r\nSubject: s\r\n\r\nbody",
	"From: a@x\nBcc: h@x\n\nbody",
	"From: \"attacker@evil\" <a@x.example>\r\n\r\n",
	"From: a@x.example\r\nSender: s@x.example\r\nReply-To: r@x.example, q@x.example\r\n\r\n",
	"From: a@x.example\r\nFrom: b@x.example\r\n\r\n",
	"Content-Transfer-Encoding: quoted-printable\r\n\r\nh=C3=A9",
	"Content-Transfer-Encoding: base64\r\n\r\naGVsbG8gd29ybGQh",
	"Content-Type: multipart/mixed; boundary=o\r\n\r\n" +
		"--o\r\nContent-Type: multipart/alternative; boundary=i\r\n\r\n" +
		"--i\r\nContent-Type: text/plain\r\n\r\nab\r\n--i--\r\n" +
		"--o\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--o--\r\n",
	"no header end",
}

func FuzzStripBcc(f *testing.F) {
	for _, s := range messageSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		in := bytes.Clone(raw)
		out := stripBcc(raw)
		end := headerEnd(in)
		if end < 0 {
			if !bytes.Equal(out, in) {
				t.Fatalf("stripBcc changed a message without header end: %q -> %q", in, out)
			}
			return
		}
		if !bytes.HasSuffix(out, in[end:]) {
			t.Fatalf("stripBcc changed the body: %q -> %q", in, out)
		}
		if len(out) > len(in) {
			t.Fatalf("stripBcc grew the message: %q -> %q", in, out)
		}
		// Re-parsing the stripped header must find no blind copies.
		hdr := out[:len(out)-(len(in)-end)]
		for _, line := range bytes.SplitAfter(hdr, []byte("\n")) {
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && isBccField(line) {
				t.Fatalf("stripBcc left %q in %q", line, out)
			}
		}
		if again := stripBcc(bytes.Clone(out)); !bytes.Equal(again, out) {
			t.Fatalf("stripBcc is not idempotent: %q -> %q", out, again)
		}
	})
}

func FuzzContentSize(f *testing.F) {
	for _, s := range messageSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		msg, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			return
		}
		// Encoded content can shrink the measured size, never grow it, and
		// never push it below zero.
		if n := contentSize(msg, len(raw)); n < 0 || n > int64(len(raw)) {
			t.Fatalf("contentSize = %d for %d raw bytes: %q", n, len(raw), raw)
		}
	})
}

func FuzzParseMessage(f *testing.F) {
	for _, s := range messageSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		msg, hdr, err := parseMessage(raw)
		if err != nil {
			return
		}
		if msg == nil || hdr.from == "" {
			t.Fatalf("parseMessage(%q) accepted without a From address", raw)
		}
		for _, k := range []string{"From", "Sender", "Reply-To"} {
			if len(msg.Header[k]) > 1 {
				t.Fatalf("parseMessage(%q) accepted duplicate %s", raw, k)
			}
		}
		// Every address the policy is later asked about must be a mailbox
		// it can judge by its domain.
		for _, a := range append([]string{hdr.from, hdr.sender}, hdr.replyTo...) {
			if a == "" {
				continue
			}
			if err := policy.ValidateMailbox(a); err != nil {
				t.Fatalf("parseMessage(%q) returned %q: %v", raw, a, err)
			}
		}
	})
}

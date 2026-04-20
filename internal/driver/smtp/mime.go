package smtp

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"sort"
	"strings"
	"time"

	"github.com/se-wo/sigillum/internal/driver"
)

const crlf = "\r\n"

// formatAddress produces an RFC-5322 address with optional display name.
func formatAddress(a driver.Address) string {
	if a.Name == "" {
		return a.Address
	}
	return mime.QEncoding.Encode("utf-8", a.Name) + " <" + a.Address + ">"
}

func formatAddressList(addrs []driver.Address) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = formatAddress(a)
	}
	return strings.Join(parts, ", ")
}

func extractAddrs(addrs []driver.Address) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.Address
	}
	return out
}

// generateBoundary returns a random multipart boundary token.
func generateBoundary() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "sigillum-" + base64.RawURLEncoding.EncodeToString(b[:])
}

// generateMessageID returns an RFC-5322 Message-ID using a random local-part.
func generateMessageID(domain string) string {
	if domain == "" {
		domain = "sigillum.local"
	}
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "<" + base64.RawURLEncoding.EncodeToString(b[:]) + "@" + domain + ">"
}

// AssembleMessage serializes msg into RFC-5322 text suitable for SMTP DATA.
//
// Structure decisions:
//   - If both text and html are present we emit multipart/alternative.
//   - If attachments are present we wrap the body in multipart/mixed.
//   - Headers sort deterministically so tests can compare bytes.
func AssembleMessage(msg *driver.Message, heloDomain string) ([]byte, string, error) {
	if msg == nil {
		return nil, "", fmt.Errorf("nil message")
	}
	if msg.From.Address == "" {
		return nil, "", fmt.Errorf("from address required")
	}
	if len(msg.To)+len(msg.Cc)+len(msg.Bcc) == 0 {
		return nil, "", fmt.Errorf("at least one recipient required")
	}

	hdr := textproto.MIMEHeader{}
	hdr.Set("Date", time.Now().UTC().Format(time.RFC1123Z))
	messageID := msg.MessageID
	if messageID == "" {
		messageID = generateMessageID(heloDomain)
	}
	hdr.Set("Message-ID", messageID)
	hdr.Set("From", formatAddress(msg.From))
	if len(msg.To) > 0 {
		hdr.Set("To", formatAddressList(msg.To))
	}
	if len(msg.Cc) > 0 {
		hdr.Set("Cc", formatAddressList(msg.Cc))
	}
	if msg.Subject != "" {
		hdr.Set("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	}
	hdr.Set("MIME-Version", "1.0")

	for k, v := range msg.Headers {
		// Don't allow callers to overwrite headers we manage.
		if isReservedHeader(k) {
			continue
		}
		if err := validateHeaderKey(k); err != nil {
			return nil, messageID, err
		}
		if containsInjectionChars(v) {
			return nil, messageID, fmt.Errorf("header %q value contains CR, LF, or NUL", k)
		}
		hdr.Set(k, v)
	}

	var body bytes.Buffer

	hasText := strings.TrimSpace(msg.Body.Text) != ""
	hasHTML := strings.TrimSpace(msg.Body.HTML) != ""
	hasAtt := len(msg.Attachments) > 0

	switch {
	case !hasAtt && !hasText && !hasHTML:
		hdr.Set("Content-Type", "text/plain; charset=utf-8")
		hdr.Set("Content-Transfer-Encoding", "7bit")
		body.WriteString("")

	case !hasAtt:
		writeAlternative(&hdr, &body, msg.Body)

	default:
		mw := multipart.NewWriter(&body)
		boundary := generateBoundary()
		_ = mw.SetBoundary(boundary)
		hdr.Set("Content-Type", "multipart/mixed; boundary=\""+boundary+"\"")

		// Body part (alternative) goes first.
		if hasText || hasHTML {
			altBuf, altHeader := buildAlternative(msg.Body)
			part, err := mw.CreatePart(altHeader)
			if err != nil {
				return nil, messageID, err
			}
			if _, err := part.Write(altBuf); err != nil {
				return nil, messageID, err
			}
		}

		for _, a := range msg.Attachments {
			if err := writeAttachment(mw, a); err != nil {
				return nil, messageID, err
			}
		}
		if err := mw.Close(); err != nil {
			return nil, messageID, err
		}
	}

	var out bytes.Buffer
	keys := make([]string, 0, len(hdr))
	for k := range hdr {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range hdr[k] {
			out.WriteString(k)
			out.WriteString(": ")
			out.WriteString(v)
			out.WriteString(crlf)
		}
	}
	out.WriteString(crlf)
	out.Write(body.Bytes())
	return out.Bytes(), messageID, nil
}

func writeAlternative(hdr *textproto.MIMEHeader, body *bytes.Buffer, b driver.Body) {
	hasText := strings.TrimSpace(b.Text) != ""
	hasHTML := strings.TrimSpace(b.HTML) != ""

	switch {
	case hasText && hasHTML:
		raw, partHeader := buildAlternative(b)
		for k, vs := range partHeader {
			for _, v := range vs {
				hdr.Set(k, v)
			}
		}
		body.Write(raw)
	case hasHTML:
		hdr.Set("Content-Type", "text/html; charset=utf-8")
		hdr.Set("Content-Transfer-Encoding", "quoted-printable")
		writeQuotedPrintable(body, b.HTML)
	default:
		hdr.Set("Content-Type", "text/plain; charset=utf-8")
		hdr.Set("Content-Transfer-Encoding", "quoted-printable")
		writeQuotedPrintable(body, b.Text)
	}
}

func buildAlternative(b driver.Body) ([]byte, textproto.MIMEHeader) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	boundary := generateBoundary()
	_ = mw.SetBoundary(boundary)
	if strings.TrimSpace(b.Text) != "" {
		ph := textproto.MIMEHeader{}
		ph.Set("Content-Type", "text/plain; charset=utf-8")
		ph.Set("Content-Transfer-Encoding", "quoted-printable")
		w, _ := mw.CreatePart(ph)
		writeQuotedPrintable(w, b.Text)
	}
	if strings.TrimSpace(b.HTML) != "" {
		ph := textproto.MIMEHeader{}
		ph.Set("Content-Type", "text/html; charset=utf-8")
		ph.Set("Content-Transfer-Encoding", "quoted-printable")
		w, _ := mw.CreatePart(ph)
		writeQuotedPrintable(w, b.HTML)
	}
	_ = mw.Close()
	return buf.Bytes(), textproto.MIMEHeader{
		"Content-Type": []string{"multipart/alternative; boundary=\"" + boundary + "\""},
	}
}

func writeAttachment(mw *multipart.Writer, a driver.Attachment) error {
	ph := textproto.MIMEHeader{}
	ct := a.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	if containsInjectionChars(ct) {
		return fmt.Errorf("attachment contentType contains CR, LF, or NUL")
	}
	ph.Set("Content-Type", ct)
	disp := a.Disposition
	if disp == "" {
		disp = "attachment"
	}
	if containsInjectionChars(disp) {
		return fmt.Errorf("attachment disposition contains CR, LF, or NUL")
	}
	if a.Filename != "" {
		if containsInjectionChars(a.Filename) {
			return fmt.Errorf("attachment filename contains CR, LF, or NUL")
		}
		// Escape backslash and double-quote per RFC 2183 before quoting.
		safeName := strings.ReplaceAll(strings.ReplaceAll(a.Filename, `\`, `\\`), `"`, `\"`)
		ph.Set("Content-Disposition", fmt.Sprintf(`%s; filename="%s"`, disp, safeName))
	} else {
		ph.Set("Content-Disposition", disp)
	}
	ph.Set("Content-Transfer-Encoding", "base64")
	w, err := mw.CreatePart(ph)
	if err != nil {
		return err
	}
	enc := base64.NewEncoder(base64.StdEncoding, lineBreakWriter{w: w, every: 76})
	if _, err := enc.Write(a.Content); err != nil {
		return err
	}
	return enc.Close()
}

// lineBreakWriter wraps base64 output at the 76-column RFC limit.
type lineBreakWriter struct {
	w     io.Writer
	every int
	col   int
}

func (l lineBreakWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		room := l.every - l.col
		if room <= 0 {
			if _, err := l.w.Write([]byte(crlf)); err != nil {
				return written, err
			}
			l.col = 0
			room = l.every
		}
		n := len(p)
		if n > room {
			n = room
		}
		nn, err := l.w.Write(p[:n])
		written += nn
		l.col += nn
		if err != nil {
			return written, err
		}
		p = p[n:]
	}
	return written, nil
}

// writeQuotedPrintable is a minimal QP encoder good enough for the
// transactional bodies Sigillum will see — long-line wrapping at 76 chars,
// '=' escape for byte values outside printable ASCII or for trailing whitespace.
func writeQuotedPrintable(w io.Writer, s string) {
	const max = 76
	col := 0
	flush := func(b []byte) {
		_, _ = w.Write(b)
		col += len(b)
	}
	soft := func() {
		_, _ = w.Write([]byte("=" + crlf))
		col = 0
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' {
			_, _ = w.Write([]byte(crlf))
			col = 0
			continue
		}
		if c == '\r' {
			continue
		}
		var encoded []byte
		if c == '=' || c < 32 || c > 126 {
			encoded = []byte(fmt.Sprintf("=%02X", c))
		} else {
			encoded = []byte{c}
		}
		if col+len(encoded) > max-1 {
			soft()
		}
		flush(encoded)
	}
}

func isReservedHeader(k string) bool {
	switch strings.ToLower(k) {
	case "from", "to", "cc", "bcc", "subject", "date", "message-id",
		"mime-version", "content-type", "content-transfer-encoding":
		return true
	}
	return false
}

// containsInjectionChars reports whether s contains characters that allow
// SMTP/MIME header injection: CR, LF, or NUL.
func containsInjectionChars(s string) bool {
	return strings.ContainsAny(s, "\r\n\x00")
}

// validateHeaderKey returns an error if k is not a valid RFC-5322 field-name
// token: visible ASCII (33–126) excluding colon.
func validateHeaderKey(k string) error {
	if k == "" {
		return fmt.Errorf("header key must not be empty")
	}
	for _, c := range k {
		if c < 33 || c > 126 || c == ':' {
			return fmt.Errorf("header key %q contains invalid character", k)
		}
	}
	return nil
}

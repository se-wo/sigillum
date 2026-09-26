package smtpproxy

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
)

// maxMIMEDepth bounds multipart nesting so a crafted message cannot recurse
// without limit.
const maxMIMEDepth = 16

// contentSize measures a message for maxSizeBytes: the raw size minus only
// the transfer-encoding overhead of base64 and quoted-printable leaf parts.
// An 8 MiB PDF therefore counts as roughly 8 MiB, not as its ~11 MiB base64
// form, which keeps SMTP in line with the REST path. Every other byte that
// is relayed (headers, MIME boundaries, preamble, epilogue) is counted, so
// none of them can be used to smuggle data past the limit.
//
// Any parse or decode error returns rawLen unchanged: malformed MIME can
// never shrink the measured size.
func contentSize(msg *mail.Message, rawLen int) int64 {
	savings, ok := encodingSavings(textproto.MIMEHeader(msg.Header), msg.Body, 0)
	if !ok || savings < 0 || savings > int64(rawLen) {
		return int64(rawLen)
	}
	return int64(rawLen) - savings
}

// encodingSavings returns how many bytes the transfer encodings of all leaf
// parts under h/body add on top of their decoded content.
func encodingSavings(h textproto.MIMEHeader, body io.Reader, depth int) (int64, bool) {
	if depth > maxMIMEDepth {
		return 0, false
	}
	mediaType, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err == nil && strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return 0, false
		}
		mr := multipart.NewReader(body, boundary)
		var total int64
		for {
			p, err := mr.NextRawPart() // raw: we decode transfer encodings ourselves
			if err == io.EOF {
				return total, true
			}
			if err != nil {
				return 0, false
			}
			n, ok := encodingSavings(p.Header, p, depth+1)
			if !ok {
				return 0, false
			}
			total += n
		}
	}

	enc := &countingReader{r: body}
	var r io.Reader = enc
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, enc) // skips CR/LF
	case "quoted-printable":
		r = quotedprintable.NewReader(enc)
	}
	decoded, err := io.Copy(io.Discard, r)
	if err != nil {
		return 0, false
	}
	return enc.n - decoded, true
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

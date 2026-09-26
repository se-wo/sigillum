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

// contentSize measures a message the way the REST path measures a request
// for maxSizeBytes: decoded bytes of every leaf body part (text, HTML,
// attachments), without headers, MIME framing or transfer-encoding
// overhead. An 8 MiB PDF therefore counts as 8 MiB on both transports,
// not as its ~11 MiB base64 form.
//
// Any parse or decode error makes it fall back to rawLen, which is always
// the larger number, so malformed MIME can never shrink the measured size.
// Bytes outside leaf parts (headers, boundaries, preamble) are not
// counted; the raw message as a whole is still capped by --max-message-bytes.
func contentSize(msg *mail.Message, rawLen int) int64 {
	n, ok := partSize(textproto.MIMEHeader(msg.Header), msg.Body, 0)
	if !ok {
		return int64(rawLen)
	}
	return n
}

func partSize(h textproto.MIMEHeader, body io.Reader, depth int) (int64, bool) {
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
			n, ok := partSize(p.Header, p, depth+1)
			if !ok {
				return 0, false
			}
			total += n
		}
	}

	var r io.Reader = body
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, body) // skips CR/LF
	case "quoted-printable":
		r = quotedprintable.NewReader(body)
	}
	n, err := io.Copy(io.Discard, r)
	if err != nil {
		return 0, false
	}
	return n, true
}

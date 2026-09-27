package smtpproxy

import (
	"bytes"
	"strings"
)

// stripBcc removes Bcc and Resent-Bcc header fields (with their folded
// continuation lines) from the header section of raw, in place, and returns
// the shortened slice. The body is not touched, so signatures over it stay
// valid; DKIM never signs Bcc.
//
// A submission server must not disclose blind-copy recipients to the other
// recipients (RFC 5322 §3.6.3). Legacy clients in the style of
// "sendmail -t" put Bcc into the message and rely on the MSA to remove it.
func stripBcc(raw []byte) []byte {
	end := headerEnd(raw)
	if end < 0 {
		return raw
	}
	out := raw[:0]
	skipping := false
	for i := 0; i < end; {
		j := bytes.IndexByte(raw[i:end], '\n')
		next := end
		if j >= 0 {
			next = i + j + 1
		}
		line := raw[i:next]
		continuation := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
		if !continuation {
			skipping = isBccField(line)
		}
		if !skipping {
			out = append(out, line...) // never overtakes i, so in-place is safe
		}
		i = next
	}
	out = append(out, raw[end:]...)
	return out
}

// headerEnd returns the offset of the blank line that ends the header
// section (the blank line itself belongs to the body side), or -1.
//
// Like net/textproto, it takes the first line that is empty after removing
// its CRLF or LF ending, so it also finds a blank first line (an empty header,
// as left behind when every field was a Bcc) and CRLF and LF lines mixed.
func headerEnd(raw []byte) int {
	for i := 0; i < len(raw); {
		j := bytes.IndexByte(raw[i:], '\n')
		if j < 0 {
			break
		}
		if line := raw[i : i+j]; len(line) == 0 || (len(line) == 1 && line[0] == '\r') {
			return i
		}
		i += j + 1
	}
	return -1
}

func isBccField(line []byte) bool {
	colon := bytes.IndexByte(line, ':')
	if colon < 0 {
		return false
	}
	name := strings.TrimSpace(string(line[:colon]))
	return strings.EqualFold(name, "Bcc") || strings.EqualFold(name, "Resent-Bcc")
}

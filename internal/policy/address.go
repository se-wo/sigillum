package policy

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"strings"
)

// ValidatePlainAddress checks that s parses as a single plain address,
// without display name or comments and equal to its parsed form, whose
// local part has no routing semantics (ValidateMailbox). SMTP paths and
// allowedRecipients entries use it, so both agree on what counts as a
// plain address.
func ValidatePlainAddress(s string) error {
	a, err := mail.ParseAddress(s)
	if err != nil {
		return err
	}
	if a.Name != "" || a.Address != s {
		return fmt.Errorf("%q is not a plain address", s)
	}
	return ValidateMailbox(a.Address)
}

// ValidateMailbox checks a parsed addr-spec (mail.Address.Address) for local
// parts that carry routing semantics of their own. Recipient restrictions
// compare only the domain after the last '@', so a local part such as
// "user%evil.example", "evil.example!user" or the dequoted form of
// "\"user@evil.example\"" would pass them while an upstream MTA that honours
// the percent hack, bang paths or nested '@' routes the message elsewhere.
//
// The local part must be a dot-atom made of RFC 5322 atext without '%' and
// '!'. Non-ASCII bytes (SMTPUTF8 local parts) carry no routing semantics and
// are accepted.
//
// The domain must be an ASCII host name (ValidateDomain): recipient
// restrictions compare it as a string, while an MTA routes the DNS name a
// Unicode spelling maps to, or the IP of a domain literal.
func ValidateMailbox(addr string) error {
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return fmt.Errorf("%q is not a plain mailbox address", addr)
	}
	if err := ValidateDomain(addr[at+1:]); err != nil {
		return fmt.Errorf("%q: %w", addr, err)
	}
	local := addr[:at]
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return fmt.Errorf("%q: local part must be a dot-atom", addr)
	}
	for i := 0; i < len(local); i++ {
		if !localPartByte(local[i]) {
			return fmt.Errorf("%q: character %q is not allowed in the local part", addr, local[i])
		}
	}
	return nil
}

// ValidateDomain accepts an ASCII host name: dot-separated labels of
// letters, digits and '-', not starting or ending with '-', at most 63
// bytes each. An internationalized domain is accepted in its A-label form
// (xn--...). Refused are U-labels and other Unicode spellings, which IDNA
// maps onto a different ASCII name than the one policies compare ("evïl"
// is xn--evl-yla; a fullwidth "ｃ" or the ideographic full stop map to "c"
// and "."), invisible characters, and domain literals ("[10.0.0.1]"), which
// route to an address without any domain to check.
func ValidateDomain(d string) error {
	if len(d) == 0 || len(d) > 253 {
		return errors.New("domain must be 1 to 253 characters")
	}
	for _, label := range strings.Split(d, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("domain %q: labels must be 1 to 63 characters", d)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("domain %q: labels must not start or end with '-'", d)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return fmt.Errorf("domain %q must be an ASCII host name; write an internationalized domain in its xn-- form", d)
			}
		}
	}
	return nil
}

func localPartByte(c byte) bool {
	switch {
	case c >= 0x80:
		return true
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	// RFC 5322 atext specials plus '.', minus '%' and '!'.
	return strings.IndexByte("#$&'*+-/=?^_`{|}~.", c) >= 0
}

// errNameContainsAt is returned by ValidateAddressHeader.
var errNameContainsAt = errors.New("display names and comments must not contain '@'")

// ValidateAddressHeader checks the raw value of an address header (From,
// Sender, Reply-To) that holds n addresses. Only the addr-specs are checked
// against the policy, while mail clients show the display name, so a name,
// comment or encoded-word such as "attacker@evil.example" <noreply@...> would
// present an arbitrary address as the sender. The value is therefore
// rejected when it contains more '@' (or look-alikes of it) than it has
// addresses, after decoding RFC 2047 encoded-words.
func ValidateAddressHeader(raw string, n int) error {
	decoded, err := wordDecoder.DecodeHeader(raw)
	if err != nil {
		return fmt.Errorf("cannot decode header: %v", err)
	}
	ats := strings.Count(decoded, "@")
	for _, lookalike := range []string{"\uFF20", "\uFE6B"} { // fullwidth / small commercial at
		ats += strings.Count(decoded, lookalike)
	}
	if ats > n {
		return errNameContainsAt
	}
	return nil
}

// wordDecoder decodes encoded-words of any ASCII-compatible charset: '@' is
// 0x40 in all of them, so passing the bytes through is enough to count it,
// and a charset Go does not know cannot hide one from the check. Charsets in
// which '@' is not the byte 0x40 are refused, as is any header using them.
var wordDecoder = &mime.WordDecoder{
	CharsetReader: func(charset string, r io.Reader) (io.Reader, error) {
		cs := strings.ToLower(charset)
		for _, p := range []string{"utf-7", "utf7", "utf-16", "utf16", "utf-32", "utf32", "ucs", "unicode"} {
			if strings.HasPrefix(cs, p) {
				return nil, fmt.Errorf("charset %q is not accepted in address headers", charset)
			}
		}
		return r, nil
	},
}

package policy

import (
	"strings"
	"testing"
)

// Fuzz targets for the address checks that stand between caller input and
// the recipient/sender policy. Seeds run with every `go test`; `make fuzz`
// explores further (see CONTRIBUTING.md).

func FuzzValidatePlainAddress(f *testing.F) {
	for _, s := range []string{
		"alerts@contoso.com",
		"first.last+tag@contoso.com",
		"jörg@contoso.com",
		"attacker%evil.com@contoso.com",
		"evil.com!attacker@contoso.com",
		`"attacker@evil.com"@contoso.com`,
		"Name <a@contoso.com>",
		"a@contoso.com (comment)",
		"<a@contoso.com>",
		"a@[127.0.0.1]",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidatePlainAddress(s) != nil {
			return
		}
		// An accepted path is relayed as is, so it must also pass the
		// mailbox check on its own and carry no routing syntax the domain
		// comparison would miss.
		if err := ValidateMailbox(s); err != nil {
			t.Fatalf("ValidatePlainAddress(%q) accepted, ValidateMailbox: %v", s, err)
		}
		local := s[:strings.LastIndexByte(s, '@')]
		if strings.ContainsAny(local, "%!@\"\\ <>()") {
			t.Fatalf("ValidatePlainAddress(%q) accepted a local part with routing syntax", s)
		}
	})
}

func FuzzValidateAddressHeader(f *testing.F) {
	for _, s := range []string{
		"noreply@contoso.com",
		`"Alerts" <noreply@contoso.com>`,
		`"attacker@evil.example" <noreply@contoso.com>`,
		"=?utf-8?q?attacker=40evil.example?= <noreply@contoso.com>",
		"=?utf-7?q?x?= <noreply@contoso.com>",
		"=?iso-8859-1?b?YXR0YWNrZXJAZXZpbA==?= <a@b>",
		"a@b, c@d",
		"Full＠width <a@b>",
	} {
		f.Add(s, 1)
	}
	f.Fuzz(func(t *testing.T, raw string, n int) {
		if n < 0 || n > 64 {
			return
		}
		if ValidateAddressHeader(raw, n) != nil {
			return
		}
		// A value accepted for n addresses is accepted for more.
		if err := ValidateAddressHeader(raw, n+1); err != nil {
			t.Fatalf("ValidateAddressHeader(%q) accepted for %d, not %d: %v", raw, n, n+1, err)
		}
		// With no '@' to spare, one more address whose display name holds
		// '@' must be caught.
		tight := 0
		for ValidateAddressHeader(raw, tight) != nil {
			tight++
		}
		if v := raw + `, "x@evil.example" <a@b>`; ValidateAddressHeader(v, tight+1) == nil {
			t.Fatalf("ValidateAddressHeader(%q, %d) = nil", v, tight+1)
		}
	})
}

func FuzzAddressMatches(f *testing.F) {
	for _, s := range [][2]string{
		{"alerts@contoso.com", "alerts@contoso.com"},
		{"Alerts@Contoso.com", "*@contoso.com"},
		{"a/b@contoso.com", "a*@contoso.com"},
		{"a@evil.com", "*@contoso.com"},
		{"a@contoso.com", "[a-"},
		{"a@contoso.com", "?@contoso.com"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, addr, pattern string) {
		got := AddressMatches(addr, pattern)
		if got != AddressMatches(strings.ToLower(addr), pattern) {
			t.Fatalf("AddressMatches(%q, %q) depends on case", addr, pattern)
		}
		if got && !strings.ContainsAny(pattern, "*?[") &&
			strings.ToLower(strings.TrimSpace(addr)) != strings.ToLower(strings.TrimSpace(pattern)) {
			t.Fatalf("AddressMatches(%q, %q) matched without a glob", addr, pattern)
		}
	})
}

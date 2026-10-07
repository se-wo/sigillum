package policy

import (
	"strings"
	"testing"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

func TestValidateMailbox(t *testing.T) {
	for addr, ok := range map[string]bool{
		"alerts@contoso.com":            true,
		"first.last+tag@contoso.com":    true,
		"o'brien@contoso.com":           true,
		"jörg@contoso.com":              true,
		"attacker%evil.com@contoso.com": false, // percent hack
		"evil.com!attacker@contoso.com": false, // bang path
		"attacker@evil.com@contoso.com": false, // dequoted "attacker@evil.com"@contoso.com
		"a b@contoso.com":               false, // dequoted "a b"@contoso.com
		`a"b@contoso.com`:               false,
		`a\b@contoso.com`:               false,
		".a@contoso.com":                false,
		"a.@contoso.com":                false,
		"a..b@contoso.com":              false,
		"@contoso.com":                  false,
		"alerts@":                       false,
		"alerts":                        false,
	} {
		if err := ValidateMailbox(addr); (err == nil) != ok {
			t.Errorf("ValidateMailbox(%q) = %v, want ok=%v", addr, err, ok)
		}
	}
}

func TestValidateAddressHeader(t *testing.T) {
	for _, tc := range []struct {
		raw string
		n   int
		ok  bool
	}{
		{"noreply@contoso.com", 1, true},
		{"Billing <noreply@contoso.com>", 1, true},
		{"=?utf-8?q?J=C3=B6rg?= <noreply@contoso.com>", 1, true},
		{"a@contoso.com, b@contoso.com", 2, true},
		{"noreply@contoso.com(attacker@evil.com)", 1, false},
		{`"attacker@evil.com" <noreply@contoso.com>`, 1, false},
		{"=?utf-8?B?YXR0YWNrZXJAZXZpbC5jb20=?= <noreply@contoso.com>", 1, false},
		{"=?iso-8859-15?q?attacker=40evil.com?= <noreply@contoso.com>", 1, false},
		{"=?utf-7?q?attacker+AEA-evil.com?= <noreply@contoso.com>", 1, false},
		{"attacker＠evil.com <noreply@contoso.com>", 1, false},
		{`"Billing" <noreply@contoso.com> (attacker@evil.com)`, 1, false},
	} {
		if err := ValidateAddressHeader(tc.raw, tc.n); (err == nil) != tc.ok {
			t.Errorf("ValidateAddressHeader(%q, %d) = %v, want ok=%v", tc.raw, tc.n, err, tc.ok)
		}
	}
}

func TestEvaluate_RoutingLocalPartsAreDenied(t *testing.T) {
	p := policy("p", "ns", 0, "sa", "noreply@contoso.com")
	p.Spec.RecipientRestrictions = &sigv1.RecipientRestrictions{AllowedDomains: []string{"contoso.com"}}
	for _, rcpt := range []string{
		"attacker%evil.com@contoso.com",
		"evil.com!attacker@contoso.com",
		"attacker@evil.com@contoso.com",
	} {
		got := Evaluate(&p, MessageView{From: "noreply@contoso.com", Recipients: []string{rcpt}})
		if got.Allowed || got.DenyReason != DenyRecipientBlocked {
			t.Errorf("recipient %q: want recipient_not_allowed, got %+v", rcpt, got)
		}
	}
	// Also without recipientRestrictions: the local part alone is enough.
	p.Spec.RecipientRestrictions = nil
	got := Evaluate(&p, MessageView{From: "noreply@contoso.com", Recipients: []string{"attacker%evil.com@contoso.com"}})
	if got.Allowed {
		t.Fatalf("routing local part must be denied without recipientRestrictions, got %+v", got)
	}
}

func TestEvaluate_SenderAndReplyTo(t *testing.T) {
	p := policy("p", "ns", 0, "sa", "noreply@contoso.com")
	p.Spec.RecipientRestrictions = &sigv1.RecipientRestrictions{AllowedDomains: []string{"contoso.com"}}
	base := MessageView{From: "noreply@contoso.com", Recipients: []string{"alerts@contoso.com"}}

	for _, tc := range []struct {
		name   string
		mutate func(*MessageView)
		want   DenyReason
	}{
		{"plain", func(*MessageView) {}, ""},
		{"sender allowed", func(m *MessageView) { m.Sender = "noreply@contoso.com" }, ""},
		{"sender foreign", func(m *MessageView) { m.Sender = "attacker@evil.com" }, DenySenderNotAllowed},
		{"reply-to internal", func(m *MessageView) { m.ReplyTo = []string{"support@contoso.com"} }, ""},
		{"reply-to external", func(m *MessageView) { m.ReplyTo = []string{"support@contoso.com", "attacker@evil.com"} }, DenyRecipientBlocked},
		{"reply-to routing", func(m *MessageView) { m.ReplyTo = []string{"attacker%evil.com@contoso.com"} }, DenyRecipientBlocked},
	} {
		m := base
		tc.mutate(&m)
		got := Evaluate(&p, m)
		if tc.want == "" && !got.Allowed || tc.want != "" && got.DenyReason != tc.want {
			t.Errorf("%s: want %q, got %+v", tc.name, tc.want, got)
		}
	}
}

// ValidatePlainAddress is shared by SMTP paths and the MailPolicy webhook.
func TestValidatePlainAddress(t *testing.T) {
	for _, ok := range []string{"alerts@example.com", "team/a@oncall.example.com"} {
		if err := ValidatePlainAddress(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"Alerts <alerts@example.com>", "alerts@example.com (ops)", "user%evil.example@example.com", "not an address"} {
		if err := ValidatePlainAddress(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Spellings of a domain that a string comparison against blockedDomains
// misses while an MTA routes them to the blocked name, or to an address
// without any domain, are refused.
func TestValidateMailbox_DomainSpellings(t *testing.T) {
	for addr, ok := range map[string]bool{
		"u@xn--evl-yla.example":        true, // A-label: what policies compare
		"u@COMPETITOR.example":         true, // case is folded by the comparison
		"u@localhost":                  true,
		"u@a-b.example":                true,
		"u@evïl.example":               false, // U-label of xn--evl-yla.example
		"u@ｃompetitor.example":         false, // fullwidth c maps to c
		"u@competitor。example":         false, // ideographic full stop maps to '.'
		"u@competitor.example​":        false, // zero-width space
		"u@[10.0.0.1]":                 false, // domain literal
		"u@[IPv6:::1]":                 false,
		"u@-competitor.example":        false,
		"u@competitor..example":        false,
		"u@competitor_example.com":     false,
		"u@" + strings.Repeat("a", 64): false,
	} {
		if err := ValidateMailbox(addr); (err == nil) != ok {
			t.Errorf("ValidateMailbox(%q) = %v, want ok=%v", addr, err, ok)
		}
	}
}

// The policy engine refuses such recipients too, so a transport that
// forgets the parse-time check cannot reopen the bypass.
func TestEvaluate_UnicodeDomainCannotBypassBlockedDomains(t *testing.T) {
	p := &sigv1.MailPolicy{Spec: sigv1.MailPolicySpec{RecipientRestrictions: &sigv1.RecipientRestrictions{
		BlockedDomains: []string{"xn--evl-yla.example", "competitor.example"},
	}}}
	for _, r := range []string{"u@evïl.example", "u@ｃompetitor.example", "u@[192.0.2.1]", "u@xn--evl-yla.example", "u@Competitor.Example"} {
		if d := Evaluate(p, MessageView{From: "a@team.example", Recipients: []string{r}}); d.Allowed {
			t.Errorf("recipient %q must be refused", r)
		}
	}
	if d := Evaluate(p, MessageView{From: "a@team.example", Recipients: []string{"u@partner.example"}}); !d.Allowed {
		t.Fatalf("an ordinary recipient must pass, got %+v", d)
	}
}

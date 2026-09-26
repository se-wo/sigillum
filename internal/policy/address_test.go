package policy

import (
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

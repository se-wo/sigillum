package v1alpha1

import (
	"encoding/json"
	"strings"
	"testing"
)

// An empty allowedSenders denies every sender, an omitted one allows all:
// the difference must survive a JSON round trip through the Go type.
func TestBackendSpec_AllowedSendersRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want string
	}{
		{"omitted", nil, `"allowedSenders":null`},
		{"empty", []string{}, `"allowedSenders":[]`},
		{"listed", []string{"me@example.com"}, `"allowedSenders":["me@example.com"]`},
	} {
		raw, err := json.Marshal(BackendSpec{Type: BackendSMTP, AllowedSenders: tc.in})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), tc.want) {
			t.Fatalf("%s: %s does not contain %s", tc.name, raw, tc.want)
		}
		var out BackendSpec
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		if (out.AllowedSenders == nil) != (tc.in == nil) || len(out.AllowedSenders) != len(tc.in) {
			t.Fatalf("%s: got %#v, want %#v", tc.name, out.AllowedSenders, tc.in)
		}
		if cp := out.DeepCopy(); (cp.AllowedSenders == nil) != (tc.in == nil) {
			t.Fatalf("%s: DeepCopy lost the difference: %#v", tc.name, cp.AllowedSenders)
		}
	}
}

func TestEffectiveAllowedSenders(t *testing.T) {
	xoauth2 := func(senders []string) *BackendSpec {
		return &BackendSpec{Type: BackendSMTP, AllowedSenders: senders, SMTP: &SMTPBackendSpec{
			AuthType: SMTPAuthXOAUTH2, OAuth: &SMTPOAuthSpec{Mailbox: "me@outlook.com"}}}
	}
	if got := xoauth2(nil).EffectiveAllowedSenders(); len(got) != 1 || got[0] != "me@outlook.com" {
		t.Fatalf("an XOAUTH2 backend without allowedSenders sends only as its mailbox, got %v", got)
	}
	if got := xoauth2([]string{"alias@outlook.com"}).EffectiveAllowedSenders(); len(got) != 1 || got[0] != "alias@outlook.com" {
		t.Fatalf("an explicit list wins, got %v", got)
	}
	if got := xoauth2([]string{}).EffectiveAllowedSenders(); got == nil || len(got) != 0 {
		t.Fatalf("an empty list still denies every sender, got %#v", got)
	}
	glob := xoauth2(nil)
	glob.SMTP.OAuth.Mailbox = "*@outlook.com"
	if got := glob.EffectiveAllowedSenders(); got == nil || len(got) != 0 {
		t.Fatalf("a mailbox that is a pattern must deny, not widen, got %#v", got)
	}
	plain := &BackendSpec{Type: BackendSMTP, SMTP: &SMTPBackendSpec{AuthType: SMTPAuthPlain}}
	if got := plain.EffectiveAllowedSenders(); got != nil {
		t.Fatalf("other backends without the list have no bound, got %v", got)
	}
}

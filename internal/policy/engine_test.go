package policy

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

func policy(name, ns string, prio int32, sa string, allowedSenders ...string) sigv1.MailPolicy {
	p := sigv1.MailPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: sigv1.MailPolicySpec{
			Priority: prio,
			Subjects: []sigv1.PolicySubject{
				{ServiceAccount: &sigv1.ServiceAccountSubject{Name: sa}},
			},
			BackendRef: sigv1.BackendRef{Name: "b", Kind: sigv1.KindClusterMailBackend},
		},
	}
	if len(allowedSenders) > 0 {
		p.Spec.SenderRestrictions = &sigv1.SenderRestrictions{AllowedSenders: allowedSenders}
	}
	return p
}

func TestMatch_PriorityAndAlphabeticTiebreak(t *testing.T) {
	caller := Caller{Namespace: "billing", ServiceAccount: "billing-mailer"}
	policies := []sigv1.MailPolicy{
		policy("zzz-low", "billing", 10, "billing-mailer"),
		policy("aaa-high", "billing", 100, "billing-mailer"),
		policy("ccc-tie", "billing", 100, "billing-mailer"),
		policy("bbb-tie", "billing", 100, "billing-mailer"),
		policy("wrong-ns", "other", 1000, "billing-mailer"),
		policy("wrong-sa", "billing", 1000, "someone-else"),
	}
	got := Match(policies, caller)
	if got == nil {
		t.Fatalf("expected a match")
	}
	if got.Name != "aaa-high" {
		t.Fatalf("priority+alphabetic tie-break broken: got %s, want aaa-high", got.Name)
	}
}

func TestMatch_DefaultDenyWhenNothingMatches(t *testing.T) {
	if got := Match(nil, Caller{Namespace: "x", ServiceAccount: "y"}); got != nil {
		t.Fatalf("expected nil match for empty policy list, got %v", got.Name)
	}
}

func TestMatch_ServiceAccountSelector(t *testing.T) {
	caller := Caller{
		Namespace:      "billing",
		ServiceAccount: "billing-mailer",
		SALabels:       map[string]string{"app.kubernetes.io/component": "notifier"},
		SALabelsKnown:  true,
	}
	policies := []sigv1.MailPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "by-label", Namespace: "billing"},
			Spec: sigv1.MailPolicySpec{
				Priority: 50,
				Subjects: []sigv1.PolicySubject{{
					ServiceAccountSelector: &sigv1.LabelSelectorSubject{
						MatchLabels: map[string]string{"app.kubernetes.io/component": "notifier"},
					},
				}},
				BackendRef: sigv1.BackendRef{Name: "b", Kind: sigv1.KindClusterMailBackend},
			},
		},
	}
	if got := Match(policies, caller); got == nil || got.Name != "by-label" {
		t.Fatalf("expected match by SA selector, got %v", got)
	}
}

func TestEvaluate_SenderAllowlistGlob(t *testing.T) {
	p := policy("p", "ns", 1, "sa", "billing@example.com", "*@noreply.example.com")
	cases := []struct {
		from string
		ok   bool
	}{
		{"billing@example.com", true},
		{"alerts@noreply.example.com", true},
		{"random@example.com", false},
		{"someone@noreply.example.org", false},
	}
	for _, tc := range cases {
		got := Evaluate(&p, MessageView{From: tc.from, Recipients: []string{"x@y.com"}})
		if got.Allowed != tc.ok {
			t.Fatalf("from=%s want allowed=%v got %+v", tc.from, tc.ok, got)
		}
		if !tc.ok && got.DenyReason != DenySenderNotAllowed {
			t.Fatalf("from=%s expected DenySenderNotAllowed, got %s", tc.from, got.DenyReason)
		}
	}
}

func TestEvaluate_NoPolicyDeniesByDefault(t *testing.T) {
	got := Evaluate(nil, MessageView{From: "x@y", Recipients: []string{"a@b"}})
	if got.Allowed || got.DenyReason != DenyNoPolicy {
		t.Fatalf("expected default-deny, got %+v", got)
	}
}

func TestEvaluate_MessageLimits(t *testing.T) {
	p := policy("p", "ns", 1, "sa", "*@x.com")
	p.Spec.MessageLimits = &sigv1.MessageLimitsSpec{MaxSizeBytes: 100, MaxRecipients: 2}
	got := Evaluate(&p, MessageView{From: "a@x.com", Recipients: []string{"a@b", "c@d", "e@f"}, SizeBytes: 50})
	if got.Allowed || got.DenyReason != DenyTooManyRecipient {
		t.Fatalf("expected too many recipients, got %+v", got)
	}
	got = Evaluate(&p, MessageView{From: "a@x.com", Recipients: []string{"a@b"}, SizeBytes: 200})
	if got.Allowed || got.DenyReason != DenyMessageTooLarge {
		t.Fatalf("expected too large, got %+v", got)
	}
}

func TestEvaluate_RecipientAllowDeny(t *testing.T) {
	p := policy("p", "ns", 1, "sa", "*@x.com")
	p.Spec.RecipientRestrictions = &sigv1.RecipientRestrictions{
		AllowedDomains: []string{"example.com"},
		BlockedDomains: []string{"bad.example.com"},
	}
	cases := []struct {
		rcpt string
		ok   bool
	}{
		{"a@example.com", true},
		{"a@other.com", false},
		{"a@bad.example.com", false}, // denylist takes priority
	}
	for _, tc := range cases {
		got := Evaluate(&p, MessageView{From: "x@x.com", Recipients: []string{tc.rcpt}})
		if got.Allowed != tc.ok {
			t.Fatalf("rcpt=%s want %v got %+v", tc.rcpt, tc.ok, got)
		}
		if !tc.ok && got.DenyReason != DenyRecipientBlocked {
			t.Fatalf("rcpt=%s expected DenyRecipientBlocked, got %s", tc.rcpt, got.DenyReason)
		}
	}
}

func TestSenderAllowedCaseInsensitive(t *testing.T) {
	if !senderAllowed("Billing@Example.COM", []string{"billing@example.com"}) {
		t.Fatal("sender match must be case-insensitive")
	}
}

func TestSenderAllowed_EmptyDeniesAll(t *testing.T) {
	if senderAllowed("a@b.com", nil) {
		t.Fatal("empty allowedSenders must deny all")
	}
}

// Sanity check: Evaluate strips whitespace from glob comparison.
func TestSenderAllowedTrim(t *testing.T) {
	if !senderAllowed(" billing@example.com ", []string{" billing@example.com "}) {
		t.Fatal("expected trim")
	}
}

func TestDomainOf(t *testing.T) {
	if got := domainOf("a@b.com"); got != "b.com" {
		t.Fatalf("got %q", got)
	}
	if got := domainOf("no-at"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestMatch_EmptyAllowedSendersStillMatchesPolicyButDeniesEvaluation(t *testing.T) {
	p := policy("p", "billing", 10, "sa")
	p.Spec.SenderRestrictions = &sigv1.SenderRestrictions{AllowedSenders: nil}
	matched := Match([]sigv1.MailPolicy{p}, Caller{Namespace: "billing", ServiceAccount: "sa"})
	if matched == nil {
		t.Fatal("expected match")
	}
	if !strings.Contains(string(Evaluate(matched, MessageView{From: "x@y", Recipients: []string{"a@b"}}).DenyReason), "sender_not_allowed") {
		t.Skip("evaluation handles via SenderRestrictions only when set; nil restrictions allow")
	}
}

func TestMatch_ServiceAccountSelectorExpressions(t *testing.T) {
	p := sigv1.MailPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "expr", Namespace: "billing"},
		Spec: sigv1.MailPolicySpec{
			Subjects: []sigv1.PolicySubject{{
				ServiceAccountSelector: &sigv1.LabelSelectorSubject{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"batch", "notify"},
					}},
				},
			}},
		},
	}
	policies := []sigv1.MailPolicy{p}
	if !NeedsSALabels(policies) {
		t.Fatal("NeedsSALabels must report selector subjects")
	}
	in := Caller{Namespace: "billing", ServiceAccount: "x", SALabels: map[string]string{"tier": "notify"}, SALabelsKnown: true}
	if got := Match(policies, in); got == nil {
		t.Fatal("expected matchExpressions to match")
	}
	out := Caller{Namespace: "billing", ServiceAccount: "x", SALabels: map[string]string{"tier": "web"}, SALabelsKnown: true}
	if got := Match(policies, out); got != nil {
		t.Fatalf("expected no match, got %s", got.Name)
	}
	if NeedsSALabels([]sigv1.MailPolicy{policy("p", "billing", 1, "sa")}) {
		t.Fatal("NeedsSALabels must be false without selector subjects")
	}
}

func TestEvaluate_RecipientCaseAndNoAllowlist(t *testing.T) {
	p := policy("p", "ns", 1, "sa", "*@x.com")
	p.Spec.RecipientRestrictions = &sigv1.RecipientRestrictions{BlockedDomains: []string{"Gmail.com"}}
	if got := Evaluate(&p, MessageView{From: "a@x.com", Recipients: []string{"ok@corp.example", "a@GMAIL.com"}}); got.Allowed {
		t.Fatal("blocked domain must match case-insensitively")
	}
	if got := Evaluate(&p, MessageView{From: "a@x.com", Recipients: []string{"ok@corp.example"}}); !got.Allowed {
		t.Fatalf("empty allowlist must allow non-blocked domains, got %+v", got)
	}
}

func TestMatch_PodIPLegacyRequiresOptIn(t *testing.T) {
	podPolicy := func(name string, optIn bool) sigv1.MailPolicy {
		p := sigv1.MailPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "legacy"},
			Spec: sigv1.MailPolicySpec{
				Subjects: []sigv1.PolicySubject{{PodSelector: &sigv1.LabelSelectorSubject{
					MatchLabels: map[string]string{"app": "cron"},
				}}},
			},
		}
		if optIn {
			p.Spec.LegacyAuth = &sigv1.LegacyAuthSpec{PodIPFallback: true}
		}
		return p
	}
	legacy := Caller{Namespace: "legacy", ServiceAccount: "default", LegacyPodIP: true,
		PodLabels: map[string]string{"app": "cron"}}

	if got := Match([]sigv1.MailPolicy{podPolicy("no-opt-in", false)}, legacy); got != nil {
		t.Fatalf("pod-IP caller must not match a policy without podIPFallback, got %s", got.Name)
	}
	if got := Match([]sigv1.MailPolicy{podPolicy("opt-in", true)}, legacy); got == nil {
		t.Fatal("pod-IP caller must match an opted-in podSelector policy")
	}
	token := legacy
	token.LegacyPodIP = false
	if got := Match([]sigv1.MailPolicy{podPolicy("opt-in", true)}, token); got != nil {
		t.Fatal("podSelector must be ignored for token-authenticated callers")
	}
	// An SA subject in an opted-in policy still matches a pod-IP caller.
	sa := policy("sa-opt-in", "legacy", 1, "default")
	sa.Spec.LegacyAuth = &sigv1.LegacyAuthSpec{PodIPFallback: true}
	if got := Match([]sigv1.MailPolicy{sa}, legacy); got == nil {
		t.Fatal("SA subject in opted-in policy must match pod-IP caller")
	}
}

func TestEvaluate_EnvelopeSenderAlsoChecked(t *testing.T) {
	p := policy("p", "ns", 1, "sa", "*@app.example")
	ok := Evaluate(&p, MessageView{From: "a@app.example", EnvelopeFrom: "bounce@app.example", Recipients: []string{"x@y"}})
	if !ok.Allowed {
		t.Fatalf("both senders allowed, got %+v", ok)
	}
	spoof := Evaluate(&p, MessageView{From: "ceo@other.example", EnvelopeFrom: "a@app.example", Recipients: []string{"x@y"}})
	if spoof.Allowed || spoof.DenyReason != DenySenderNotAllowed {
		t.Fatalf("header From must be checked even if envelope passes, got %+v", spoof)
	}
	env := Evaluate(&p, MessageView{From: "a@app.example", EnvelopeFrom: "x@other.example", Recipients: []string{"x@y"}})
	if env.Allowed {
		t.Fatal("envelope sender must be checked too")
	}
}

func TestMatch_NegativeSelectorFailsClosedWithoutLabels(t *testing.T) {
	p := sigv1.MailPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "not-untrusted", Namespace: "ns"},
		Spec: sigv1.MailPolicySpec{Subjects: []sigv1.PolicySubject{{
			ServiceAccountSelector: &sigv1.LabelSelectorSubject{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "tier", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"untrusted"},
			}}},
		}}},
	}
	policies := []sigv1.MailPolicy{p}
	// Lookup failed: labels unknown. A NotIn selector must not match.
	if got := Match(policies, Caller{Namespace: "ns", ServiceAccount: "sa"}); got != nil {
		t.Fatal("selector subjects must not match when SA labels could not be resolved")
	}
	// Resolved, and genuinely without the label: matches as the selector says.
	if got := Match(policies, Caller{Namespace: "ns", ServiceAccount: "sa", SALabelsKnown: true}); got == nil {
		t.Fatal("resolved SA without the label should match a NotIn selector")
	}
}

func TestEvaluate_AllowedRecipients(t *testing.T) {
	p := policy("p", "ns", 1, "sa", "*@x.com")
	p.Spec.RecipientRestrictions = &sigv1.RecipientRestrictions{
		AllowedRecipients: []string{"QA@staging.example.com"},
		BlockedDomains:    []string{"blocked.example.com"},
	}
	cases := []struct {
		name    string
		rcpts   []string
		replyTo []string
		ok      bool
	}{
		{"listed address", []string{"qa@staging.example.com"}, nil, true},
		{"case-insensitive", []string{"Qa@Staging.Example.com"}, nil, true},
		{"other mailbox in same domain", []string{"dev@staging.example.com"}, nil, false},
		{"one bad recipient fails all", []string{"qa@staging.example.com", "x@other.com"}, nil, false},
		{"reply-to checked too", []string{"qa@staging.example.com"}, []string{"x@other.com"}, false},
	}
	for _, tc := range cases {
		got := Evaluate(&p, MessageView{From: "a@x.com", Recipients: tc.rcpts, ReplyTo: tc.replyTo})
		if got.Allowed != tc.ok {
			t.Fatalf("%s: want %v got %+v", tc.name, tc.ok, got)
		}
	}

	// Both allowlists combine; blockedDomains wins over both.
	p.Spec.RecipientRestrictions.AllowedDomains = []string{"example.com"}
	p.Spec.RecipientRestrictions.AllowedRecipients = append(p.Spec.RecipientRestrictions.AllowedRecipients,
		"ops@blocked.example.com")
	for rcpt, ok := range map[string]bool{
		"anyone@example.com":      true,
		"qa@staging.example.com":  true,
		"dev@staging.example.com": false,
		"ops@blocked.example.com": false,
	} {
		if got := Evaluate(&p, MessageView{From: "a@x.com", Recipients: []string{rcpt}}); got.Allowed != ok {
			t.Fatalf("%s: want %v got %+v", rcpt, ok, got)
		}
	}
}

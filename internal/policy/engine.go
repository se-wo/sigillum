// Package policy holds the policy-evaluation logic used on the api-server hot
// path. It is intentionally agnostic of the api-server transport layer so it
// can be unit-tested against pure inputs.
package policy

import (
	"path/filepath"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

// Caller carries the authenticated identity for one inbound request.
type Caller struct {
	Namespace      string
	ServiceAccount string
	// SALabels are the labels of the caller's ServiceAccount, resolved by the
	// transport layer. Only needed when a candidate policy uses a
	// serviceAccountSelector (see NeedsSALabels).
	SALabels map[string]string
	// SALabelsKnown reports that SALabels were actually resolved. Without it
	// serviceAccountSelector subjects never match: a selector made only of
	// negative operators (NotIn, DoesNotExist) matches an empty label set,
	// so treating "lookup failed" as "no labels" would fail open.
	SALabelsKnown bool
	// LegacyPodIP is set when the caller was identified by pod-IP lookup on
	// the SMTP path (US-3.5). Only policies with legacyAuth.podIPFallback
	// accept such callers, and only then are podSelector subjects consulted.
	LegacyPodIP bool
	// PodLabels are the labels of the source pod (LegacyPodIP only).
	PodLabels map[string]string
}

// NeedsSALabels reports whether any of the policies carries a
// serviceAccountSelector subject, i.e. whether the transport layer has to
// resolve the caller's ServiceAccount labels before calling Match.
func NeedsSALabels(policies []sigv1.MailPolicy) bool {
	for _, p := range policies {
		for _, s := range p.Spec.Subjects {
			if s.ServiceAccountSelector != nil {
				return true
			}
		}
	}
	return false
}

// MessageView is the subset of the inbound payload the engine needs to decide.
type MessageView struct {
	From string
	// EnvelopeFrom is the SMTP MAIL FROM address, when it differs from the
	// header From. Both must satisfy senderRestrictions, otherwise a client
	// could pass the check with one and spoof the other.
	EnvelopeFrom string
	// Sender is the Sender header address, if any. It names the mailbox
	// that submitted the message and is shown by mail clients ("on behalf
	// of"), so it must satisfy senderRestrictions like From.
	Sender     string
	Recipients []string // To + Cc + Bcc
	// ReplyTo holds the Reply-To addresses. Replies go there, so they must
	// satisfy recipientRestrictions like the recipients themselves.
	ReplyTo   []string
	SizeBytes int64
}

// DenyReason is the slug used both for metrics labels and for problem types.
type DenyReason string

const (
	DenyNoPolicy         DenyReason = "no_policy_matched"
	DenySenderNotAllowed DenyReason = "sender_not_allowed"
	DenyRecipientBlocked DenyReason = "recipient_not_allowed"
	DenyMessageTooLarge  DenyReason = "message_too_large"
	DenyTooManyRecipient DenyReason = "too_many_recipients"
)

// Decision is the result of evaluating a request against a set of policies.
type Decision struct {
	Allowed    bool
	Policy     *sigv1.MailPolicy
	DenyReason DenyReason
	DenyDetail string
}

// Match returns the highest-priority MailPolicy in the same namespace as the
// caller. Match precedence within a single policy follows US-3.2:
//
//	explicit ServiceAccount > ServiceAccountSelector > PodSelector
//
// Tie-break across policies follows US-2.6 — higher priority wins, then
// alphabetical name. Pod-selector subjects only apply to pod-IP legacy
// callers, and those only match policies that opt in via legacyAuth.
func Match(policies []sigv1.MailPolicy, caller Caller) *sigv1.MailPolicy {
	candidates := make([]sigv1.MailPolicy, 0, len(policies))
	for _, p := range policies {
		if p.Namespace != caller.Namespace {
			continue
		}
		if caller.LegacyPodIP && (p.Spec.LegacyAuth == nil || !p.Spec.LegacyAuth.PodIPFallback) {
			continue
		}
		if !subjectMatches(p, caller) {
			continue
		}
		candidates = append(candidates, p)
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Spec.Priority != candidates[j].Spec.Priority {
			return candidates[i].Spec.Priority > candidates[j].Spec.Priority
		}
		return candidates[i].Name < candidates[j].Name
	})
	winner := candidates[0]
	return &winner
}

func subjectMatches(p sigv1.MailPolicy, caller Caller) bool {
	for _, s := range p.Spec.Subjects {
		if s.ServiceAccount != nil && s.ServiceAccount.Name == caller.ServiceAccount {
			return true
		}
		if s.ServiceAccountSelector != nil && caller.SALabelsKnown && selectorMatches(s.ServiceAccountSelector, caller.SALabels) {
			return true
		}
		if s.PodSelector != nil && caller.LegacyPodIP && selectorMatches(s.PodSelector, caller.PodLabels) {
			return true
		}
	}
	return false
}

// selectorMatches evaluates matchLabels and matchExpressions. An empty
// selector never matches — a policy must not accidentally bind every SA.
func selectorMatches(sel *sigv1.LabelSelectorSubject, have map[string]string) bool {
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
		return false
	}
	ls, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
		MatchLabels:      sel.MatchLabels,
		MatchExpressions: sel.MatchExpressions,
	})
	if err != nil {
		return false
	}
	return ls.Matches(labels.Set(have))
}

// Evaluate decides accept/deny for one message against one already-matched
// policy. The transport layer is responsible for matching the policy first.
func Evaluate(p *sigv1.MailPolicy, msg MessageView) Decision {
	if p == nil {
		return Decision{DenyReason: DenyNoPolicy, DenyDetail: "no policy matched the calling subject"}
	}

	if p.Spec.MessageLimits != nil {
		if p.Spec.MessageLimits.MaxSizeBytes > 0 && msg.SizeBytes > p.Spec.MessageLimits.MaxSizeBytes {
			return Decision{Policy: p, DenyReason: DenyMessageTooLarge,
				DenyDetail: "message exceeds policy maxSizeBytes"}
		}
		if p.Spec.MessageLimits.MaxRecipients > 0 && int32(len(msg.Recipients)) > p.Spec.MessageLimits.MaxRecipients {
			return Decision{Policy: p, DenyReason: DenyTooManyRecipient,
				DenyDetail: "message exceeds policy maxRecipients"}
		}
	}
	if p.Spec.SenderRestrictions != nil {
		senders := []string{msg.From}
		if msg.EnvelopeFrom != "" {
			senders = append(senders, msg.EnvelopeFrom)
		}
		if msg.Sender != "" {
			senders = append(senders, msg.Sender)
		}
		for _, from := range senders {
			if !senderAllowed(from, p.Spec.SenderRestrictions.AllowedSenders) {
				return Decision{Policy: p, DenyReason: DenySenderNotAllowed,
					DenyDetail: "sender '" + from + "' not in allowedSenders"}
			}
		}
	}
	// Transports reject routing local parts at parse time already; checking
	// again here keeps the policy safe should a new transport forget to.
	for _, r := range msg.Recipients {
		if ValidateMailbox(r) != nil || !recipientAllowed(r, p.Spec.RecipientRestrictions) {
			return Decision{Policy: p, DenyReason: DenyRecipientBlocked,
				DenyDetail: "recipient '" + r + "' not allowed by policy"}
		}
	}
	for _, r := range msg.ReplyTo {
		if ValidateMailbox(r) != nil || !recipientAllowed(r, p.Spec.RecipientRestrictions) {
			return Decision{Policy: p, DenyReason: DenyRecipientBlocked,
				DenyDetail: "reply-to '" + r + "' not allowed by policy"}
		}
	}
	return Decision{Allowed: true, Policy: p}
}

// senderAllowed handles exact-match and `*@suffix` glob patterns. An empty
// allow-list denies all (per spec defaults — explicit allow is required).
func senderAllowed(from string, allowed []string) bool {
	for _, pattern := range allowed {
		if AddressMatches(from, pattern) {
			return true
		}
	}
	return false
}

// AddressMatches reports whether addr matches an allowedSenders or
// allowedRecipients entry: case-insensitively, exactly or, if the entry
// contains *, ? or [, as a filepath.Match glob over the whole address.
// A glob's * also matches '@', so entries must anchor on the domain
// ("*@example.com"); the webhook enforces that for allowedRecipients.
func AddressMatches(addr, pattern string) bool {
	a := strings.ToLower(strings.TrimSpace(addr))
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == a {
		return true
	}
	if strings.ContainsAny(p, "*?[") {
		ok, _ := filepath.Match(p, a)
		return ok
	}
	return false
}

// recipientAllowed applies recipientRestrictions; nil allows every
// recipient. blockedDomains always wins. Otherwise a recipient passes if its
// domain is in allowedDomains or the address matches an allowedRecipients
// entry (exact or glob, as allowedSenders); with
// both allowlists empty every domain that is not blocked passes.
func recipientAllowed(addr string, r *sigv1.RecipientRestrictions) bool {
	if r == nil {
		return true
	}
	domain := domainOf(addr)
	for _, d := range r.BlockedDomains {
		if strings.EqualFold(d, domain) {
			return false
		}
	}
	if len(r.AllowedDomains) == 0 && len(r.AllowedRecipients) == 0 {
		return true
	}
	for _, d := range r.AllowedDomains {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	for _, p := range r.AllowedRecipients {
		if AddressMatches(addr, p) {
			return true
		}
	}
	return false
}

func domainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

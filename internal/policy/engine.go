// Package policy holds the policy-evaluation logic used on the api-server hot
// path. It is intentionally agnostic of the api-server transport layer so it
// can be unit-tested against pure inputs.
package policy

import (
	"path/filepath"
	"sort"
	"strings"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

// Caller carries the authenticated identity for one inbound request.
type Caller struct {
	Namespace      string
	ServiceAccount string
	// SALabels is empty unless the engine resolves the SA labels — for v1 we
	// only consult ServiceAccount / ServiceAccountSelector via SA name +
	// labels supplied by the caller-side resolver.
	SALabels map[string]string
}

// MessageView is the subset of the inbound payload the engine needs to decide.
type MessageView struct {
	From       string
	Recipients []string // To + Cc + Bcc
	SizeBytes  int64
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
// alphabetical name. Pod-selector subjects are skipped (they only matter for
// the future SMTP path); the api-server path matches by SA only.
func Match(policies []sigv1.MailPolicy, caller Caller) *sigv1.MailPolicy {
	candidates := make([]sigv1.MailPolicy, 0, len(policies))
	for _, p := range policies {
		if p.Namespace != caller.Namespace {
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
		if s.ServiceAccountSelector != nil && labelsMatch(s.ServiceAccountSelector.MatchLabels, caller.SALabels) {
			return true
		}
		// PodSelector is intentionally ignored on the REST path (SMTP-only).
	}
	return false
}

func labelsMatch(want, have map[string]string) bool {
	if len(want) == 0 {
		return false
	}
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
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
		if !senderAllowed(msg.From, p.Spec.SenderRestrictions.AllowedSenders) {
			return Decision{Policy: p, DenyReason: DenySenderNotAllowed,
				DenyDetail: "sender '" + msg.From + "' not in allowedSenders"}
		}
	}
	if p.Spec.RecipientRestrictions != nil {
		for _, r := range msg.Recipients {
			if !recipientAllowed(r, p.Spec.RecipientRestrictions) {
				return Decision{Policy: p, DenyReason: DenyRecipientBlocked,
					DenyDetail: "recipient '" + r + "' not allowed by policy"}
			}
		}
	}
	return Decision{Allowed: true, Policy: p}
}

// senderAllowed handles exact-match and `*@suffix` glob patterns. An empty
// allow-list denies all (per spec defaults — explicit allow is required).
func senderAllowed(from string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	from = strings.ToLower(strings.TrimSpace(from))
	for _, pattern := range allowed {
		p := strings.ToLower(strings.TrimSpace(pattern))
		if p == from {
			return true
		}
		if strings.ContainsAny(p, "*?[") {
			if ok, _ := filepath.Match(p, from); ok {
				return true
			}
		}
	}
	return false
}

func recipientAllowed(addr string, r *sigv1.RecipientRestrictions) bool {
	domain := domainOf(addr)
	for _, d := range r.BlockedDomains {
		if strings.EqualFold(d, domain) {
			return false
		}
	}
	if len(r.AllowedDomains) == 0 {
		return true
	}
	for _, d := range r.AllowedDomains {
		if strings.EqualFold(d, domain) {
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

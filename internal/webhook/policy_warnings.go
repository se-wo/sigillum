package webhook

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/policy"
)

// backendWarnings compares a policy with the backend it references (#49).
// Lookup failures add nothing: the controller reports a missing backend in
// the policy's Ready condition.
func (v *MailPolicyValidator) backendWarnings(ctx context.Context, mp *sigv1.MailPolicy) admission.Warnings {
	if v.Reader == nil || mp.Spec.SenderRestrictions == nil || mp.Spec.BackendRef.Name == "" {
		return nil
	}
	var (
		backend client.Object
		spec    *sigv1.BackendSpec
		key     = types.NamespacedName{Name: mp.Spec.BackendRef.Name}
		kind    = sigv1.KindClusterMailBackend
	)
	switch mp.Spec.BackendRef.Kind {
	case sigv1.KindClusterMailBackend, "":
		cmb := &sigv1.ClusterMailBackend{}
		backend, spec = cmb, &cmb.Spec
	case sigv1.KindMailBackend:
		mb := &sigv1.MailBackend{}
		backend, spec, key.Namespace, kind = mb, &mb.Spec, mp.Namespace, sigv1.KindMailBackend
	default:
		return nil
	}
	if err := v.Reader.Get(ctx, key, backend); err != nil || spec.AllowedSenders == nil {
		return nil
	}
	var never []string
	for _, e := range mp.Spec.SenderRestrictions.AllowedSenders {
		if e != "" && senderNeverAllowed(e, spec.AllowedSenders) {
			never = append(never, e)
		}
	}
	if len(never) == 0 {
		return nil
	}
	return admission.Warnings{fmt.Sprintf("spec.senderRestrictions.allowedSenders: %s %s allows none of %q: "+
		"sends from these addresses fail with sender-not-allowed", kind, key.Name, never)}
}

// senderNeverAllowed reports whether no address matching the policy entry
// e can match any entry of the backend's list. It only says so when
// certain; for two globs on the same domain it assumes they overlap.
func senderNeverAllowed(e string, backend []string) bool {
	glob := strings.ContainsAny(e, "*?[")
	if glob && addressEntryError(e) != "" {
		return false // "*" or a glob not anchored on a domain: cannot tell
	}
	for _, b := range backend {
		switch {
		case !glob:
			// A plain address: the backend's matcher decides.
			if policy.AddressMatches(e, b) {
				return false
			}
		case !strings.ContainsAny(b, "*?["):
			// A plain backend address allows only itself.
			if policy.AddressMatches(b, e) {
				return false
			}
		case addressEntryError(b) != "":
			return false
		default:
			// Both are <local glob>@<bare domain>: every address of e ends
			// in "@" + its domain, so with different domains they are
			// disjoint. On the same domain assume they overlap.
			if strings.EqualFold(domainPart(e), domainPart(b)) {
				return false
			}
		}
	}
	return true
}

func domainPart(e string) string {
	_, d, _ := strings.Cut(e, "@")
	return strings.TrimSpace(d)
}

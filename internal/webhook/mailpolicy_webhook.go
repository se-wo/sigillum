package webhook

import (
	"context"
	"path/filepath"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/policy"
)

// +kubebuilder:webhook:path=/validate-sigillum-dev-v1alpha1-mailpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=sigillum.dev,resources=mailpolicies,verbs=create;update,versions=v1alpha1,name=vmailpolicy.sigillum.dev,admissionReviewVersions=v1

// MailPolicyValidator enforces the structural rules listed in the plan:
// at least one subject, a non-empty backendRef, and a recognised backend kind.
type MailPolicyValidator struct{}

// SetupMailPolicyWebhook wires the validator into the manager.
func SetupMailPolicyWebhook(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &sigv1.MailPolicy{}).
		WithValidator(&MailPolicyValidator{}).
		Complete()
}

var _ admission.Validator[*sigv1.MailPolicy] = &MailPolicyValidator{}

func (v *MailPolicyValidator) ValidateCreate(_ context.Context, obj *sigv1.MailPolicy) (admission.Warnings, error) {
	return v.validate(obj)
}

func (v *MailPolicyValidator) ValidateUpdate(_ context.Context, _, newObj *sigv1.MailPolicy) (admission.Warnings, error) {
	return v.validate(newObj)
}

func (v *MailPolicyValidator) ValidateDelete(_ context.Context, _ *sigv1.MailPolicy) (admission.Warnings, error) {
	return nil, nil
}

func (v *MailPolicyValidator) validate(mp *sigv1.MailPolicy) (admission.Warnings, error) {
	gk := schema.GroupKind{Group: sigv1.GroupVersion.Group, Kind: "MailPolicy"}

	var allErrs field.ErrorList
	specPath := field.NewPath("spec")

	if len(mp.Spec.Subjects) == 0 {
		allErrs = append(allErrs, field.Required(specPath.Child("subjects"), "at least one subject is required"))
	}
	for i, s := range mp.Spec.Subjects {
		sPath := specPath.Child("subjects").Index(i)
		set := 0
		if s.ServiceAccount != nil {
			set++
			if s.ServiceAccount.Name == "" {
				allErrs = append(allErrs, field.Required(sPath.Child("serviceAccount").Child("name"), "name is required"))
			}
		}
		if s.ServiceAccountSelector != nil {
			set++
			allErrs = append(allErrs, validateSelector(sPath.Child("serviceAccountSelector"), s.ServiceAccountSelector)...)
		}
		if s.PodSelector != nil {
			set++
			allErrs = append(allErrs, validateSelector(sPath.Child("podSelector"), s.PodSelector)...)
		}
		if set == 0 {
			allErrs = append(allErrs, field.Required(sPath, "subject must specify exactly one matcher"))
		}
		if set > 1 {
			allErrs = append(allErrs, field.Forbidden(sPath, "subject must specify exactly one matcher"))
		}
	}

	if mp.Spec.BackendRef.Name == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("backendRef").Child("name"), "name is required"))
	}
	switch mp.Spec.BackendRef.Kind {
	case "", sigv1.KindClusterMailBackend, sigv1.KindMailBackend:
	default:
		allErrs = append(allErrs, field.NotSupported(specPath.Child("backendRef").Child("kind"),
			mp.Spec.BackendRef.Kind, []string{string(sigv1.KindClusterMailBackend), string(sigv1.KindMailBackend)}))
	}

	if mp.Spec.SenderRestrictions != nil {
		for i, s := range mp.Spec.SenderRestrictions.AllowedSenders {
			if s == "" {
				allErrs = append(allErrs, field.Required(specPath.Child("senderRestrictions").Child("allowedSenders").Index(i),
					"allowed sender must be non-empty"))
			}
		}
	}

	if rr := mp.Spec.RecipientRestrictions; rr != nil {
		rPath := specPath.Child("recipientRestrictions")
		allErrs = append(allErrs, validateDomains(rPath.Child("allowedDomains"), rr.AllowedDomains)...)
		allErrs = append(allErrs, validateDomains(rPath.Child("blockedDomains"), rr.BlockedDomains)...)
		allErrs = append(allErrs, validateRecipients(rPath.Child("allowedRecipients"), rr.AllowedRecipients)...)
	}

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(gk, mp.Name, allErrs)
}

func validateSelector(p *field.Path, sel *sigv1.LabelSelectorSubject) field.ErrorList {
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
		return field.ErrorList{field.Required(p, "must specify matchLabels or matchExpressions")}
	}
	if _, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
		MatchLabels:      sel.MatchLabels,
		MatchExpressions: sel.MatchExpressions,
	}); err != nil {
		return field.ErrorList{field.Invalid(p, sel, err.Error())}
	}
	return nil
}

// validateRecipients accepts plain addresses whose local part has no
// routing semantics, and globs whose domain part is a bare domain
// ("*@oncall.example.com"). A glob's * also matches '@', so an unanchored
// domain would widen the list far beyond its intent; "*", "*@*" and bare
// domains are refused (whole domains belong in allowedDomains).
func validateRecipients(p *field.Path, entries []string) field.ErrorList {
	var errs field.ErrorList
	for i, e := range entries {
		if msg := recipientEntryError(e); msg != "" {
			errs = append(errs, field.Invalid(p.Index(i), e, msg))
		}
	}
	return errs
}

func recipientEntryError(e string) string {
	msg := addressEntryError(e)
	if msg == errWildcardDomain {
		msg += "; list whole domains in allowedDomains"
	}
	return msg
}

const errWildcardDomain = "the domain of a pattern must not contain wildcards"

// addressEntryError validates an allowlist entry that bounds addresses
// (allowedRecipients, a backend's allowedSenders): a plain address, or a
// glob of the form <local-part pattern>@<bare domain>. It returns "" for a
// valid entry.
func addressEntryError(e string) string {
	if !strings.ContainsAny(e, "*?[") {
		if err := policy.ValidatePlainAddress(e); err != nil {
			return err.Error() + " (must be a plain address such as alerts@example.com)"
		}
		return ""
	}
	local, domain, ok := strings.Cut(e, "@")
	switch {
	case !ok || strings.Contains(domain, "@"):
		return "a pattern must have the form <local-part pattern>@<domain>, e.g. *@oncall.example.com"
	case strings.ContainsAny(domain, "*?["):
		return errWildcardDomain
	case len(validation.IsDNS1123Subdomain(strings.ToLower(domain))) > 0:
		return "the domain of a pattern must be a bare domain"
	case local == "":
		return "the local part of a pattern must not be empty"
	case strings.ContainsAny(local, "%!\"<>() ,;:"):
		return "the local part of a pattern must not contain routing or quoting characters"
	}
	if _, err := filepath.Match(e, ""); err != nil {
		return "invalid glob pattern: " + err.Error()
	}
	return ""
}

// validateDomains accepts bare DNS names only. Recipient matching is an exact
// domain comparison, so an address or a glob here would silently never match.
func validateDomains(p *field.Path, domains []string) field.ErrorList {
	var errs field.ErrorList
	for i, d := range domains {
		if strings.ContainsAny(d, "@*?[") {
			errs = append(errs, field.Invalid(p.Index(i), d, "must be a bare domain (no '@' or wildcards)"))
			continue
		}
		for _, msg := range validation.IsDNS1123Subdomain(strings.ToLower(d)) {
			errs = append(errs, field.Invalid(p.Index(i), d, msg))
		}
	}
	return errs
}

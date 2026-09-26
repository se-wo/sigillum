package webhook

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/credential"
)

// +kubebuilder:webhook:path=/validate-sigillum-dev-v1alpha1-mailcredential,mutating=false,failurePolicy=fail,sideEffects=None,groups=sigillum.dev,resources=mailcredentials,verbs=create;update,versions=v1alpha1,name=vmailcredential.sigillum.dev,admissionReviewVersions=v1

// MailCredentialValidator validates MailCredential (US-3.7, SPEC §4.3.4).
type MailCredentialValidator struct {
	Exclusions credential.Exclusions
	// GeneratedEnabled is false when generated mode is switched off
	// (bring-your-own-hash only).
	GeneratedEnabled bool
}

// SetupMailCredentialWebhook wires the validator into the manager.
func SetupMailCredentialWebhook(mgr ctrl.Manager, v *MailCredentialValidator) error {
	return ctrl.NewWebhookManagedBy(mgr, &sigv1.MailCredential{}).
		WithValidator(v).
		Complete()
}

var _ admission.Validator[*sigv1.MailCredential] = &MailCredentialValidator{}

func (v *MailCredentialValidator) ValidateCreate(_ context.Context, obj *sigv1.MailCredential) (admission.Warnings, error) {
	return v.validate(obj)
}

func (v *MailCredentialValidator) ValidateUpdate(_ context.Context, _, newObj *sigv1.MailCredential) (admission.Warnings, error) {
	return v.validate(newObj)
}

func (v *MailCredentialValidator) ValidateDelete(_ context.Context, _ *sigv1.MailCredential) (admission.Warnings, error) {
	return nil, nil
}

func (v *MailCredentialValidator) validate(mc *sigv1.MailCredential) (admission.Warnings, error) {
	gk := schema.GroupKind{Group: sigv1.GroupVersion.Group, Kind: "MailCredential"}
	spec := field.NewPath("spec")
	var errs field.ErrorList

	if v.Exclusions.Excluded(mc.Namespace) {
		errs = append(errs, field.Forbidden(field.NewPath("metadata", "namespace"),
			fmt.Sprintf("namespace %s is excluded from mail credentials (chart credentials.excludeNamespaces)", mc.Namespace)))
	}
	if mc.Spec.ServiceAccountName == "" {
		errs = append(errs, field.Required(spec.Child("serviceAccountName"), "the ServiceAccount the credential authenticates as"))
	} else {
		for _, msg := range validation.IsDNS1123Subdomain(mc.Spec.ServiceAccountName) {
			errs = append(errs, field.Invalid(spec.Child("serviceAccountName"), mc.Spec.ServiceAccountName, msg))
		}
	}

	switch {
	case mc.Spec.PasswordHash != "":
		if mc.Spec.SecretName != "" {
			errs = append(errs, field.Forbidden(spec.Child("secretName"),
				"secretName (generated mode) and passwordHash (bring your own hash) are mutually exclusive"))
		}
		if mc.Spec.Rotation != nil {
			errs = append(errs, field.Forbidden(spec.Child("rotation"),
				"rotation applies to generated passwords only; rotate a bring-your-own hash by replacing it"))
		}
		if _, err := credential.ParseArgon2id(mc.Spec.PasswordHash); err != nil {
			// Never echo the value: it may be a plaintext password.
			errs = append(errs, field.Invalid(spec.Child("passwordHash"), "(redacted)", err.Error()))
		}
	case mc.Spec.SecretName == "":
		errs = append(errs, field.Required(spec.Child("secretName"),
			"set secretName (generated mode) or passwordHash (bring your own hash)"))
	default:
		if !v.GeneratedEnabled {
			errs = append(errs, field.Forbidden(spec.Child("secretName"),
				"generated credentials are disabled in this installation (credentials.enabled=false); set passwordHash instead"))
		}
		if msg := credential.GeneratedNameError(mc.Name); msg != "" {
			errs = append(errs, field.Invalid(field.NewPath("metadata", "name"), mc.Name, msg))
		}
		for _, msg := range validation.IsDNS1123Subdomain(mc.Spec.SecretName) {
			errs = append(errs, field.Invalid(spec.Child("secretName"), mc.Spec.SecretName, msg))
		}
		if _, _, err := credential.ParseRotation(mc.Spec.Rotation); err != nil {
			for _, e := range rotationErrors(err) {
				errs = append(errs, field.Invalid(spec.Child("rotation", e.Field), e.Value, e.Detail))
			}
		}
	}

	if len(errs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(gk, mc.Name, errs)
}

// rotationErrors unpacks the *credential.RotationError values of err.
func rotationErrors(err error) []*credential.RotationError {
	var out []*credential.RotationError
	var one *credential.RotationError
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range joined.Unwrap() {
			if errors.As(e, &one) {
				out = append(out, one)
			}
		}
	} else if errors.As(err, &one) {
		out = append(out, one)
	}
	return out
}

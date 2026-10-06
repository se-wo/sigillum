// Package webhook contains the validating admission webhooks for sigillum CRs.
package webhook

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/driver"
)

// +kubebuilder:webhook:path=/validate-sigillum-dev-v1alpha1-mailbackend,mutating=false,failurePolicy=fail,sideEffects=None,groups=sigillum.dev,resources=mailbackends,verbs=create;update,versions=v1alpha1,name=vmailbackend.sigillum.dev,admissionReviewVersions=v1
// +kubebuilder:webhook:path=/validate-sigillum-dev-v1alpha1-clustermailbackend,mutating=false,failurePolicy=fail,sideEffects=None,groups=sigillum.dev,resources=clustermailbackends,verbs=create;update,versions=v1alpha1,name=vclustermailbackend.sigillum.dev,admissionReviewVersions=v1

// MailBackendValidator validates both MailBackend and ClusterMailBackend.
// One implementation handles both — the only difference is whether
// credentialsRef.namespace is required (cluster-scope: yes). T is the
// concrete CR type the webhook is registered for.
type MailBackendValidator[T runtime.Object] struct {
	clusterScoped bool
}

// SetupMailBackendWebhook registers the namespace-scoped validator.
func SetupMailBackendWebhook(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &sigv1.MailBackend{}).
		WithValidator(&MailBackendValidator[*sigv1.MailBackend]{clusterScoped: false}).
		Complete()
}

// SetupClusterMailBackendWebhook registers the cluster-scoped validator.
func SetupClusterMailBackendWebhook(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &sigv1.ClusterMailBackend{}).
		WithValidator(&MailBackendValidator[*sigv1.ClusterMailBackend]{clusterScoped: true}).
		Complete()
}

// NewMailBackendValidator returns the validator for namespace-scoped
// MailBackends (used by tests outside this package).
func NewMailBackendValidator() *MailBackendValidator[*sigv1.MailBackend] {
	return &MailBackendValidator[*sigv1.MailBackend]{clusterScoped: false}
}

// NewClusterMailBackendValidator returns the validator for
// ClusterMailBackends.
func NewClusterMailBackendValidator() *MailBackendValidator[*sigv1.ClusterMailBackend] {
	return &MailBackendValidator[*sigv1.ClusterMailBackend]{clusterScoped: true}
}

// compile-time interface assertions
var (
	_ admission.Validator[*sigv1.MailBackend]        = &MailBackendValidator[*sigv1.MailBackend]{}
	_ admission.Validator[*sigv1.ClusterMailBackend] = &MailBackendValidator[*sigv1.ClusterMailBackend]{}
)

func (v *MailBackendValidator[T]) ValidateCreate(_ context.Context, obj T) (admission.Warnings, error) {
	return v.validate(obj)
}

func (v *MailBackendValidator[T]) ValidateUpdate(_ context.Context, _, newObj T) (admission.Warnings, error) {
	return v.validate(newObj)
}

func (v *MailBackendValidator[T]) ValidateDelete(_ context.Context, _ T) (admission.Warnings, error) {
	return nil, nil
}

func (v *MailBackendValidator[T]) validate(obj runtime.Object) (admission.Warnings, error) {
	var (
		spec   *sigv1.BackendSpec
		gk     schema.GroupKind
		name   string
		selfNs string
	)
	switch o := obj.(type) {
	case *sigv1.MailBackend:
		spec = &o.Spec
		gk = schema.GroupKind{Group: sigv1.GroupVersion.Group, Kind: "MailBackend"}
		name = o.Name
		selfNs = o.Namespace
	case *sigv1.ClusterMailBackend:
		spec = &o.Spec
		gk = schema.GroupKind{Group: sigv1.GroupVersion.Group, Kind: "ClusterMailBackend"}
		name = o.Name
	default:
		return nil, fmt.Errorf("unexpected object type %T", obj)
	}

	var allErrs field.ErrorList
	var warnings admission.Warnings
	specPath := field.NewPath("spec")

	// Reject unknown / not-yet-implemented backend types — the schema enum
	// permits the future values, but only registered drivers can be used.
	if !driver.IsImplemented(driver.Type(spec.Type)) {
		allErrs = append(allErrs, field.NotSupported(specPath.Child("type"), spec.Type, asStringSlice(driver.Implemented())))
	}

	if spec.Type == sigv1.BackendSMTP {
		smtpPath := specPath.Child("smtp")
		if spec.SMTP == nil {
			allErrs = append(allErrs, field.Required(smtpPath, "spec.smtp is required when type=smtp"))
		} else {
			if len(spec.SMTP.Endpoints) == 0 {
				allErrs = append(allErrs, field.Required(smtpPath.Child("endpoints"), "at least one endpoint is required"))
			}
			for i, ep := range spec.SMTP.Endpoints {
				epPath := smtpPath.Child("endpoints").Index(i)
				if ep.Host == "" {
					allErrs = append(allErrs, field.Required(epPath.Child("host"), "host is required"))
				}
				if ep.Port == 0 {
					allErrs = append(allErrs, field.Required(epPath.Child("port"), "port is required"))
				}
				// Disabling TLS certificate verification exposes credentials to
				// interception; reject at admission time on both backend kinds.
				if ep.InsecureSkipVerify {
					allErrs = append(allErrs, field.Forbidden(epPath.Child("insecureSkipVerify"),
						"TLS certificate verification must not be disabled"))
				}
			}
			if spec.SMTP.AuthType != "" && spec.SMTP.AuthType != sigv1.SMTPAuthNone && spec.SMTP.CredentialsRef == nil {
				allErrs = append(allErrs, field.Required(smtpPath.Child("credentialsRef"), "credentialsRef is required when authType != NONE"))
			}
			if spec.SMTP.CredentialsRef != nil {
				allErrs = append(allErrs, v.validateCredentialsRef(smtpPath.Child("credentialsRef"), *spec.SMTP.CredentialsRef, selfNs)...)
			}
			if ref := spec.SMTP.CASecretRef; ref != nil {
				allErrs = append(allErrs, v.validateCredentialsRef(smtpPath.Child("caSecretRef"),
					sigv1.SecretReference{Name: ref.Name, Namespace: ref.Namespace}, selfNs)...)
				if !anyTLSEndpoint(spec.SMTP.Endpoints) {
					warnings = append(warnings, "spec.smtp.caSecretRef has no effect: no endpoint uses tls or starttls")
				}
			}
		}
		if spec.MicrosoftGraph != nil {
			allErrs = append(allErrs, field.Forbidden(specPath.Child("microsoftGraph"), "only for type microsoftGraph"))
		}
	}

	if spec.Type == sigv1.BackendMicrosoftGraph {
		allErrs = append(allErrs, v.validateGraph(specPath, spec, selfNs)...)
	}

	// A backend's sender list bounds every policy that uses it, so its
	// entries follow the stricter rules of allowedRecipients: a glob must
	// be anchored on a bare domain.
	for i, e := range spec.AllowedSenders {
		if msg := addressEntryError(e); msg != "" {
			allErrs = append(allErrs, field.Invalid(specPath.Child("allowedSenders").Index(i), e, msg))
		}
	}
	if spec.AllowedSenders != nil && len(spec.AllowedSenders) == 0 {
		warnings = append(warnings, "spec.allowedSenders is empty: this backend denies every sender. "+
			"Omit the field to leave senders to the policies.")
	}

	if len(allErrs) == 0 {
		return warnings, nil
	}
	return warnings, apierrors.NewInvalid(gk, name, allErrs)
}

// validateGraph checks a microsoftGraph backend (SPEC US-6.1, US-2.8).
func (v *MailBackendValidator[T]) validateGraph(specPath *field.Path, spec *sigv1.BackendSpec, selfNs string) field.ErrorList {
	var errs field.ErrorList
	gPath := specPath.Child("microsoftGraph")
	if g := spec.MicrosoftGraph; g == nil {
		errs = append(errs, field.Required(gPath, "spec.microsoftGraph is required when type=microsoftGraph"))
	} else {
		// The tenant becomes part of the token URL.
		if len(validation.IsDNS1123Subdomain(g.TenantID)) > 0 {
			errs = append(errs, field.Invalid(gPath.Child("tenantID"), g.TenantID,
				"must be the directory (tenant) ID or a verified domain of the tenant, in lower case"))
		}
		if _, err := uuid.Parse(g.ClientID); err != nil || len(g.ClientID) != 36 {
			errs = append(errs, field.Invalid(gPath.Child("clientID"), g.ClientID,
				"must be the application (client) ID of the app registration, a GUID"))
		}
		errs = append(errs, v.validateCredentialsRef(gPath.Child("credentialsRef"), g.CredentialsRef, selfNs)...)
	}
	// App-only Mail.Send can send as any mailbox of the tenant; the
	// backend's list is what bounds it.
	if len(spec.AllowedSenders) == 0 {
		errs = append(errs, field.Required(specPath.Child("allowedSenders"),
			"a microsoftGraph backend can send as any mailbox of the tenant; list the mailboxes it sends for"))
	}
	if spec.SMTP != nil {
		errs = append(errs, field.Forbidden(specPath.Child("smtp"), "only for type smtp"))
	}
	return errs
}

// validateCredentialsRef requires a namespace on cluster-scoped backends and
// forbids cross-namespace Secret reads from namespace-scoped ones. It
// applies to every Secret a backend references (credentials, CA).
func (v *MailBackendValidator[T]) validateCredentialsRef(p *field.Path, ref sigv1.SecretReference, selfNs string) field.ErrorList {
	if v.clusterScoped && ref.Namespace == "" {
		return field.ErrorList{field.Required(p.Child("namespace"),
			"namespace is required for Secret references on cluster-scoped backends")}
	}
	if !v.clusterScoped && ref.Namespace != "" && ref.Namespace != selfNs {
		return field.ErrorList{field.Invalid(p.Child("namespace"), ref.Namespace,
			"cross-namespace Secret references are not permitted on namespace-scoped backends")}
	}
	return nil
}

func anyTLSEndpoint(eps []sigv1.SMTPEndpoint) bool {
	for _, ep := range eps {
		if ep.TLS != sigv1.SMTPTLSNone {
			return true
		}
	}
	return false
}

func asStringSlice(types []driver.Type) []string {
	out := make([]string, len(types))
	for i, t := range types {
		out[i] = string(t)
	}
	return out
}

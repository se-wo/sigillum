package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	admv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

// Guard describes the credential Secret guard (SPEC §4.10): a
// ValidatingAdmissionPolicy and binding that restrict the controller's
// Secret writes to generated credential Secrets outside the excluded
// namespaces. RBAC cannot narrow create/patch by label, so the controller
// writes Secrets only while this guard is in place, unchanged.
//
// The Helm chart renders the same objects (templates/credential-guard.yaml);
// TestChartGuardMatches keeps both in sync.
type Guard struct {
	// Name of the ValidatingAdmissionPolicy and its binding.
	Name string
	// ControllerUsername is the controller's ServiceAccount username,
	// system:serviceaccount:<namespace>:<name>.
	ControllerUsername string
	Exclusions         Exclusions
}

// Static CEL of the guard. Only the variables below depend on configuration.
const (
	celCredentialVar = "has(object.metadata.labels) && '" + sigv1.CredentialLabel + "' in object.metadata.labels" +
		" ? object.metadata.labels['" + sigv1.CredentialLabel + "'] : ''"
	celUIDVar = "has(object.metadata.annotations) && '" + sigv1.CredentialUIDAnnotation + "' in object.metadata.annotations" +
		" ? object.metadata.annotations['" + sigv1.CredentialUIDAnnotation + "'] : ''"

	celLabelled = "variables.credential != '' && variables.uid != ''"
	celOwned    = "has(object.metadata.ownerReferences) && object.metadata.ownerReferences.exists(r," +
		" r.apiVersion.startsWith('sigillum.dev/') && r.kind == 'MailCredential' &&" +
		" r.name == variables.credential && r.uid == variables.uid && has(r.controller) && r.controller)"
	celSameOwner = "request.operation != 'UPDATE' || (" +
		"has(oldObject.metadata.labels) && '" + sigv1.CredentialLabel + "' in oldObject.metadata.labels &&" +
		" oldObject.metadata.labels['" + sigv1.CredentialLabel + "'] == variables.credential &&" +
		" has(oldObject.metadata.annotations) && '" + sigv1.CredentialUIDAnnotation + "' in oldObject.metadata.annotations &&" +
		" oldObject.metadata.annotations['" + sigv1.CredentialUIDAnnotation + "'] == variables.uid)"
	celNamespace = "request.namespace != variables.releaseNamespace &&" +
		" !(request.namespace in variables.excludedNames) &&" +
		" !variables.excludedPrefixes.exists(p, request.namespace.startsWith(p))"
)

// celJSON renders v as a CEL literal. JSON strings and arrays of strings are
// valid CEL, and Helm's toJson produces the same bytes.
func celJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Policy returns the expected ValidatingAdmissionPolicy.
func (g Guard) Policy() *admv1.ValidatingAdmissionPolicy {
	fail := admv1.Fail
	exact, prefixes := g.Exclusions.split()
	return &admv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: g.Name},
		Spec: admv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: &fail,
			MatchConstraints: &admv1.MatchResources{
				ResourceRules: []admv1.NamedRuleWithOperations{{
					RuleWithOperations: admv1.RuleWithOperations{
						Operations: []admv1.OperationType{admv1.Create, admv1.Update},
						Rule: admv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"secrets"},
						},
					},
				}},
			},
			MatchConditions: []admv1.MatchCondition{{
				Name:       "controller-only",
				Expression: "request.userInfo.username == " + celJSON(g.ControllerUsername),
			}},
			Variables: []admv1.Variable{
				{Name: "releaseNamespace", Expression: celJSON(g.Exclusions.ReleaseNamespace)},
				{Name: "excludedNames", Expression: celJSON(exact)},
				{Name: "excludedPrefixes", Expression: celJSON(prefixes)},
				{Name: "credential", Expression: celCredentialVar},
				{Name: "uid", Expression: celUIDVar},
			},
			Validations: []admv1.Validation{
				{Expression: celLabelled, Message: "the Sigillum controller may only write Secrets labelled " +
					sigv1.CredentialLabel + " and annotated " + sigv1.CredentialUIDAnnotation},
				{Expression: celOwned, Message: "the Secret must be controlled by the MailCredential named in its " +
					sigv1.CredentialLabel + " label"},
				{Expression: celSameOwner, Message: "the Sigillum controller may only update Secrets that already " +
					"belong to the same MailCredential"},
				{Expression: celNamespace, Message: "this namespace is excluded from generated mail credentials"},
			},
		},
	}
}

// Binding returns the expected ValidatingAdmissionPolicyBinding.
func (g Guard) Binding() *admv1.ValidatingAdmissionPolicyBinding {
	return &admv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: g.Name},
		Spec: admv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        g.Name,
			ValidationActions: []admv1.ValidationAction{admv1.Deny},
		},
	}
}

// Verify checks that the guard policy and binding exist in the cluster and
// enforce what Policy and Binding describe. Messages, audit annotations and
// server-side defaults are ignored; anything that could narrow or weaken
// the guard is not.
func (g Guard) Verify(ctx context.Context, c client.Reader) error {
	var vap admv1.ValidatingAdmissionPolicy
	if err := c.Get(ctx, types.NamespacedName{Name: g.Name}, &vap); err != nil {
		return fmt.Errorf("ValidatingAdmissionPolicy %s: %w", g.Name, err)
	}
	var vapb admv1.ValidatingAdmissionPolicyBinding
	if err := c.Get(ctx, types.NamespacedName{Name: g.Name}, &vapb); err != nil {
		return fmt.Errorf("ValidatingAdmissionPolicyBinding %s: %w", g.Name, err)
	}
	if err := g.verifyPolicy(&vap.Spec); err != nil {
		return fmt.Errorf("ValidatingAdmissionPolicy %s: %w", g.Name, err)
	}
	if err := g.verifyBinding(&vapb.Spec); err != nil {
		return fmt.Errorf("ValidatingAdmissionPolicyBinding %s: %w", g.Name, err)
	}
	return nil
}

func (g Guard) verifyPolicy(got *admv1.ValidatingAdmissionPolicySpec) error {
	want := g.Policy().Spec
	if got.FailurePolicy != nil && *got.FailurePolicy != admv1.Fail {
		return fmt.Errorf("failurePolicy is %s, want Fail", *got.FailurePolicy)
	}
	if got.ParamKind != nil {
		return fmt.Errorf("unexpected paramKind")
	}
	mc := got.MatchConstraints
	if mc == nil {
		return fmt.Errorf("matchConstraints missing")
	}
	if len(mc.ExcludeResourceRules) > 0 || !emptySelector(mc.NamespaceSelector) || !emptySelector(mc.ObjectSelector) {
		return fmt.Errorf("matchConstraints are narrowed (excludeResourceRules or selectors)")
	}
	if mc.MatchPolicy != nil && *mc.MatchPolicy != admv1.Equivalent {
		return fmt.Errorf("matchConstraints.matchPolicy is %s, want Equivalent", *mc.MatchPolicy)
	}
	if len(mc.ResourceRules) != 1 {
		return fmt.Errorf("matchConstraints.resourceRules changed")
	}
	gr, wr := mc.ResourceRules[0], want.MatchConstraints.ResourceRules[0]
	if len(gr.ResourceNames) > 0 || !slices.Equal(gr.Operations, wr.Operations) ||
		!slices.Equal(gr.APIGroups, wr.APIGroups) || !slices.Equal(gr.APIVersions, wr.APIVersions) ||
		!slices.Equal(gr.Resources, wr.Resources) ||
		(gr.Scope != nil && *gr.Scope != admv1.AllScopes && *gr.Scope != admv1.NamespacedScope) {
		return fmt.Errorf("matchConstraints.resourceRules changed")
	}
	if !slices.Equal(got.MatchConditions, want.MatchConditions) {
		return fmt.Errorf("matchConditions changed")
	}
	if !slices.Equal(got.Variables, want.Variables) {
		return fmt.Errorf("variables changed (does --credential-exclude-namespaces match the chart's credentials.excludeNamespaces?)")
	}
	if len(got.Validations) != len(want.Validations) {
		return fmt.Errorf("validations changed")
	}
	for i := range want.Validations {
		if got.Validations[i].Expression != want.Validations[i].Expression {
			return fmt.Errorf("validation %d changed", i)
		}
	}
	return nil
}

func (g Guard) verifyBinding(got *admv1.ValidatingAdmissionPolicyBindingSpec) error {
	if got.PolicyName != g.Name {
		return fmt.Errorf("policyName is %q, want %q", got.PolicyName, g.Name)
	}
	if got.ParamRef != nil {
		return fmt.Errorf("unexpected paramRef")
	}
	if !slices.Contains(got.ValidationActions, admv1.Deny) {
		return fmt.Errorf("validationActions %v do not include Deny", got.ValidationActions)
	}
	if mr := got.MatchResources; mr != nil {
		if len(mr.ResourceRules) > 0 || len(mr.ExcludeResourceRules) > 0 ||
			!emptySelector(mr.NamespaceSelector) || !emptySelector(mr.ObjectSelector) {
			return fmt.Errorf("matchResources narrow the binding")
		}
	}
	return nil
}

func emptySelector(s *metav1.LabelSelector) bool {
	return s == nil || (len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0)
}

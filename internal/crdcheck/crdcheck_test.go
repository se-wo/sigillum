package crdcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

// loadCRDs reads the generated CRDs, keyed by kind.
func loadCRDs(t *testing.T) map[string]*apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "config", "crd", "bases", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no CRDs found: %v", err)
	}
	crds := map[string]*apiextensionsv1.CustomResourceDefinition{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.UnmarshalStrict(raw, crd); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		crds[crd.Spec.Names.Kind] = crd
	}
	return crds
}

func TestRequiredFieldsExistInCRDs(t *testing.T) {
	crds := loadCRDs(t)
	for _, f := range Required {
		crd, ok := crds[f.Kind]
		if !ok {
			t.Errorf("%s: no CRD for kind", f)
			continue
		}
		s := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
		for _, name := range f.Path {
			p, ok := s.Properties[name]
			if !ok {
				t.Errorf("%s: no property %q", f, name)
				break
			}
			s = &p
		}
	}
}

const doc = `{"components":{"schemas":{
 "dev.sigillum.v1alpha1.MailPolicy":{
  "x-kubernetes-group-version-kind":[{"group":"sigillum.dev","version":"v1alpha1","kind":"MailPolicy"}],
  "properties":{"spec":{"properties":{"recipientRestrictions":{"properties":{%s}},"rateLimits":{"properties":{%r}}}}}},
 "dev.sigillum.v1alpha1.MailCredential":{
  "x-kubernetes-group-version-kind":[{"group":"sigillum.dev","version":"v1alpha1","kind":"MailCredential"}],
  "properties":{"spec":{"properties":{"serviceAccountName":{}}}}}}}}`

func TestVerifyDoc(t *testing.T) {
	rateLimits := `"messagesPerMinute":{},"messagesPerHour":{}`
	withRateLimits := strings.Replace(doc, "%r", rateLimits+`,"messagesPerDay":{}`, 1)
	current := strings.Replace(withRateLimits, "%s", `"allowedDomains":{},"allowedRecipients":{}`, 1)
	if err := verifyDoc([]byte(current), Required); err != nil {
		t.Fatalf("current schema: %v", err)
	}

	stale := strings.Replace(withRateLimits, "%s", `"allowedDomains":{}`, 1)
	err := verifyDoc([]byte(stale), Required)
	if err == nil || !strings.Contains(err.Error(), "MailPolicy CRD has no field spec.recipientRestrictions.allowedRecipients") {
		t.Fatalf("stale MailPolicy: got %v", err)
	}

	v030 := strings.Replace(strings.Replace(doc, "%r", rateLimits, 1), "%s", `"allowedRecipients":{}`, 1)
	err = verifyDoc([]byte(v030), Required)
	if err == nil || !strings.Contains(err.Error(), "MailPolicy CRD has no field spec.rateLimits.messagesPerDay") {
		t.Fatalf("0.3.0 MailPolicy: got %v", err)
	}

	noKind := strings.Replace(current, `"kind":"MailCredential"`, `"kind":"Other"`, 1)
	err = verifyDoc([]byte(noKind), Required)
	if err == nil || !strings.Contains(err.Error(), "kind MailCredential is not installed") {
		t.Fatalf("missing MailCredential: got %v", err)
	}

	if err := verifyDoc([]byte("{"), Required); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

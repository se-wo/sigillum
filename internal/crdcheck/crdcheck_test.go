package crdcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"
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
  "properties":{"spec":{"properties":{"serviceAccountName":{}}}}},
 "dev.sigillum.v1alpha1.MailBackend":{
  "x-kubernetes-group-version-kind":[{"group":"sigillum.dev","version":"v1alpha1","kind":"MailBackend"}],
  "properties":{"spec":{"properties":{"type":{},%b}}}},
 "dev.sigillum.v1alpha1.ClusterMailBackend":{
  "x-kubernetes-group-version-kind":[{"group":"sigillum.dev","version":"v1alpha1","kind":"ClusterMailBackend"}],
  "properties":{"spec":{"properties":{"type":{},"allowedSenders":{}}}}}}}}`

func TestVerifyDoc(t *testing.T) {
	rateLimits := `"messagesPerMinute":{},"messagesPerHour":{}`
	withBackend := strings.Replace(doc, "%b", `"allowedSenders":{}`, 1)
	withRateLimits := strings.Replace(withBackend, "%r", rateLimits+`,"messagesPerDay":{}`, 1)
	current := strings.Replace(withRateLimits, "%s", `"allowedDomains":{},"allowedRecipients":{}`, 1)
	if err := verifyDoc([]byte(current), Required); err != nil {
		t.Fatalf("current schema: %v", err)
	}

	stale := strings.Replace(withRateLimits, "%s", `"allowedDomains":{}`, 1)
	err := verifyDoc([]byte(stale), Required)
	if err == nil || !strings.Contains(err.Error(), "MailPolicy CRD has no field spec.recipientRestrictions.allowedRecipients") {
		t.Fatalf("stale MailPolicy: got %v", err)
	}

	v030 := strings.Replace(strings.Replace(strings.Replace(doc, "%b", `"healthCheck":{}`, 1), "%r", rateLimits, 1), "%s", `"allowedRecipients":{}`, 1)
	err = verifyDoc([]byte(v030), Required)
	if err == nil || !strings.Contains(err.Error(), "the MailBackend CRD has no field spec.allowedSenders") ||
		!strings.Contains(err.Error(), "MailPolicy CRD has no field spec.rateLimits.messagesPerDay") {
		t.Fatalf("0.3.0 CRDs: got %v", err)
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

// TestWaitErrorWording checks that only missing kinds or fields are
// reported as outdated CRDs, not an API server that cannot serve the
// schemas (#71).
func TestWaitErrorWording(t *testing.T) {
	stale := strings.Replace(strings.Replace(strings.Replace(doc, "%b", `"allowedSenders":{}`, 1),
		"%r", `"messagesPerDay":{}`, 1), "%s", `"allowedDomains":{}`, 1)
	cases := []struct {
		name    string
		handler http.HandlerFunc
		want    []string
		notWant string
	}{
		{
			name: "unavailable",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "starting", http.StatusServiceUnavailable)
			},
			want:    []string{"could not read the CRD schemas from the API server", "retrying on restart"},
			notWant: "do not match",
		},
		{
			name: "no CRDs",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"paths":{}}`))
			},
			want: []string{"installed CRDs do not match this version", "no sigillum.dev/v1alpha1 CRDs are installed", UpgradeHint},
		},
		{
			name: "missing field",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/openapi/v3" {
					_, _ = w.Write([]byte(`{"paths":{"apis/sigillum.dev/v1alpha1":{"serverRelativeURL":"/openapi/v3/apis/sigillum.dev/v1alpha1?hash=1"}}}`))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(stale))
			},
			want: []string{"installed CRDs do not match this version", "no field spec.recipientRestrictions.allowedRecipients", UpgradeHint},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			err := Wait(context.Background(), &rest.Config{Host: srv.URL}, Required, 100*time.Millisecond)
			if err == nil {
				t.Fatal("no error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("want %q in %v", w, err)
				}
			}
			if tc.notWant != "" && strings.Contains(err.Error(), tc.notWant) {
				t.Errorf("unexpected %q in %v", tc.notWant, err)
			}
		})
	}
}

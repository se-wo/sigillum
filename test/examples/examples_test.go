// Package examples checks the recipes in examples/: every YAML document
// parses, Kubernetes objects decode strictly into their types, and Sigillum
// resources pass Sigillum's own admission validation. The admission-policy
// recipes are applied to a real API server in admission_envtest_test.go.
package examples

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/yaml"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/credential"
	_ "github.com/se-wo/sigillum/internal/driver/gmail" // registers type gmail
	_ "github.com/se-wo/sigillum/internal/driver/graph"
	_ "github.com/se-wo/sigillum/internal/driver/smtp"
	"github.com/se-wo/sigillum/internal/webhook"
)

func examplesDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "examples")
}

// document is one YAML document of an example file.
type document struct {
	file string
	obj  unstructured.Unstructured
	raw  []byte
}

// loadExamples returns every Kubernetes object in examples/ (Helm values
// files excluded).
func loadExamples(t *testing.T) []document {
	t.Helper()
	var docs []document
	err := filepath.WalkDir(examplesDir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") || strings.HasPrefix(d.Name(), "values-") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rd := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(b)))
		for {
			raw, err := rd.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			var u unstructured.Unstructured
			if err := yaml.Unmarshal(raw, &u.Object); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			if len(u.Object) == 0 {
				continue
			}
			rel, _ := filepath.Rel(examplesDir(), path)
			docs = append(docs, document{file: rel, obj: u, raw: raw})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return docs
}

func TestExamplesAreValid(t *testing.T) {
	docs := loadExamples(t)
	if len(docs) < 20 {
		t.Fatalf("expected the recipes in examples/, found %d documents", len(docs))
	}
	scheme := k8sruntime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := sigv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	credValidator := &webhook.MailCredentialValidator{
		Exclusions:       credential.ParseExclusions("kube-*", "sigillum-system"),
		GeneratedEnabled: true,
	}
	for _, d := range docs {
		gvk := d.obj.GroupVersionKind()
		name := d.file + ": " + gvk.Kind + " " + d.obj.GetName()
		if gvk.Kind == "" || gvk.Version == "" {
			t.Errorf("%s: apiVersion and kind are required", d.file)
			continue
		}
		if !scheme.Recognizes(gvk) {
			// Kyverno, Cilium: CRDs we do not vendor. Require a spec.
			if _, ok := d.obj.Object["spec"]; !ok {
				t.Errorf("%s: no spec", name)
			}
			continue
		}
		obj, err := scheme.New(gvk)
		if err != nil {
			t.Fatal(err)
		}
		if err := yaml.UnmarshalStrict(d.raw, obj); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		switch o := obj.(type) {
		case *sigv1.MailPolicy:
			_, err = (&webhook.MailPolicyValidator{}).ValidateCreate(ctx, o)
		case *sigv1.MailCredential:
			_, err = credValidator.ValidateCreate(ctx, o)
		case *sigv1.MailBackend:
			_, err = webhook.NewMailBackendValidator().ValidateCreate(ctx, o)
		case *sigv1.ClusterMailBackend:
			_, err = webhook.NewClusterMailBackendValidator().ValidateCreate(ctx, o)
		}
		if err != nil {
			t.Errorf("%s: rejected by Sigillum's webhook: %v", name, err)
		}
	}
}

// The local-development values must render.
func TestLocalDevValuesRender(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	chart := filepath.Join(examplesDir(), "..", "charts", "sigillum")
	cmd := exec.Command(helm, "template", "sigillum", chart, "-n", "sigillum-system", "--kube-version", "1.32.0",
		"-f", filepath.Join(examplesDir(), "local-dev", "values-local.yaml"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{"--auth-modes=oauthbearer,credential", "--allow-insecure-credential-auth=true", "--disable-webhook=true"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("rendered local profile lacks %s", want)
		}
	}
}

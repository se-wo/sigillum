// Package chart renders the Helm chart with `helm template` and checks the
// parts that must agree with the Go code. Skipped when helm is not on PATH.
package chart

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	admv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	"github.com/se-wo/sigillum/internal/credential"
)

// testKubeVersion is the oldest Kubernetes version the chart supports.
const testKubeVersion = "1.32.0"

func chartDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "charts", "sigillum")
}

// render runs helm template and returns the rendered objects.
func render(t *testing.T, args ...string) []unstructured.Unstructured {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	// An explicit --kube-version: helm's default depends on how it was
	// built (v1.20 for a plain `go install`), and the chart requires 1.32.
	base := []string{"template", "t", chartDir(t), "-n", "mail", "--kube-version", testKubeVersion}
	cmd := exec.Command(helm, append(base, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, stderr.String())
	}
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(out), 4096)
	var objs []unstructured.Unstructured
	for {
		var u unstructured.Unstructured
		if err := dec.Decode(&u.Object); err != nil {
			if errors.Is(err, io.EOF) {
				return objs
			}
			t.Fatalf("decode rendered chart: %v", err)
		}
		if len(u.Object) > 0 {
			objs = append(objs, u)
		}
	}
}

func find(objs []unstructured.Unstructured, kind, name string) *unstructured.Unstructured {
	for i := range objs {
		if objs[i].GetKind() == kind && (name == "" || objs[i].GetName() == name) {
			return &objs[i]
		}
	}
	return nil
}

func into(t *testing.T, u *unstructured.Unstructured, out any) {
	t.Helper()
	b, err := yaml.Marshal(u.Object)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.UnmarshalStrict(b, out); err != nil {
		t.Fatalf("%s %s: %v", u.GetKind(), u.GetName(), err)
	}
}

// args returns the container args of a Deployment as flag -> value.
func args(t *testing.T, objs []unstructured.Unstructured, name string) map[string]string {
	t.Helper()
	u := find(objs, "Deployment", name)
	if u == nil {
		t.Fatalf("Deployment %s not rendered", name)
	}
	var d appsv1.Deployment
	into(t, u, &d)
	out := map[string]string{}
	for _, a := range d.Spec.Template.Spec.Containers[0].Args {
		k, v, _ := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		out[k] = v
	}
	return out
}

// TestChartGuardMatchesController renders the guard and checks it with the
// same code the controller runs at startup, configured from the flags the
// chart passes it.
func TestChartGuardMatchesController(t *testing.T) {
	testChartGuardMatchesController(t, "--set", "credentials.excludeNamespaces={kube-*,cert-manager,istio-*}")
}

// Review of #20: the controller trims the exclusion list, so the chart must
// render the same guard for entries with spaces or empty entries.
func TestChartGuardMatchesControllerWithSpaces(t *testing.T) {
	testChartGuardMatchesController(t, "--set-json", `credentials.excludeNamespaces=["kube-*"," cert-manager ",""," istio-*"]`)
}

func testChartGuardMatchesController(t *testing.T, set ...string) {
	t.Helper()
	objs := render(t, set...)
	ctrlArgs := args(t, objs, "t-sigillum-controller")
	guard := credential.Guard{
		Name:               ctrlArgs["credential-guard-name"],
		ControllerUsername: "system:serviceaccount:mail:t-sigillum-controller",
		Exclusions:         credential.ParseExclusions(ctrlArgs["credential-exclude-namespaces"], "mail"),
	}
	if guard.Name != "t-sigillum-credential-guard" || ctrlArgs["credentials-generated"] != "true" {
		t.Fatalf("unexpected controller args %v", ctrlArgs)
	}

	vapU, bindU := find(objs, "ValidatingAdmissionPolicy", guard.Name), find(objs, "ValidatingAdmissionPolicyBinding", guard.Name)
	if vapU == nil || bindU == nil {
		t.Fatal("guard policy and binding must be rendered")
	}
	var vap admv1.ValidatingAdmissionPolicy
	var vapb admv1.ValidatingAdmissionPolicyBinding
	into(t, vapU, &vap)
	into(t, bindU, &vapb)

	scheme := k8sruntime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&vap, &vapb).Build()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := guard.Verify(ctx, c); err != nil {
		t.Fatalf("chart guard does not match internal/credential/guard.go: %v", err)
	}
	for i, v := range guard.Policy().Spec.Validations {
		if vap.Spec.Validations[i].Message != v.Message {
			t.Errorf("validation %d message differs:\nchart: %s\ngo:    %s", i, vap.Spec.Validations[i].Message, v.Message)
		}
	}

	// The Secret write permission comes with the guard, and only then.
	writer := find(objs, "ClusterRole", "t-sigillum-controller-credential-writer")
	if writer == nil {
		t.Fatal("credential writer ClusterRole missing")
	}
	var cr rbacv1.ClusterRole
	into(t, writer, &cr)
	if len(cr.Rules) != 1 || strings.Join(cr.Rules[0].Verbs, ",") != "create,patch" {
		t.Fatalf("controller must get create/patch on Secrets and nothing else: %+v", cr.Rules)
	}
}

func TestChartNoSecretWritesWithoutGuard(t *testing.T) {
	for name, extra := range map[string][]string{
		"credentials disabled": {"--set", "credentials.enabled=false"},
	} {
		t.Run(name, func(t *testing.T) {
			objs := render(t, extra...)
			if find(objs, "ValidatingAdmissionPolicy", "") != nil {
				t.Fatal("guard must not be rendered")
			}
			// Without the guard, generated mode is off, so the webhook
			// rejects generated credentials instead of admitting ones
			// that stay GuardMissing forever.
			if got := args(t, objs, "t-sigillum-controller")["credentials-generated"]; got != "false" {
				t.Fatalf("--credentials-generated=%q without the guard, want false", got)
			}
			for _, u := range objs {
				if u.GetKind() != "ClusterRole" && u.GetKind() != "Role" {
					continue
				}
				var cr rbacv1.ClusterRole
				into(t, &u, &cr)
				for _, r := range cr.Rules {
					for _, res := range r.Resources {
						if res != "secrets" {
							continue
						}
						for _, v := range r.Verbs {
							if v == "create" || v == "patch" || v == "update" {
								t.Fatalf("%s %s grants %s on secrets without the guard", u.GetKind(), u.GetName(), v)
							}
						}
					}
				}
			}
		})
	}
}

func TestChartAggregatedRolesKeepCredentialStatusToController(t *testing.T) {
	objs := render(t)
	for _, name := range []string{"sigillum-view", "sigillum-edit", "sigillum-admin"} {
		u := find(objs, "ClusterRole", name)
		if u == nil {
			t.Fatalf("%s missing", name)
		}
		var cr rbacv1.ClusterRole
		into(t, u, &cr)
		hasCreds := false
		for _, r := range cr.Rules {
			for _, res := range r.Resources {
				if res == "mailcredentials/status" || res == "*" {
					t.Fatalf("%s must not grant %s: the hashes in status are written by the controller only", name, res)
				}
				hasCreds = hasCreds || res == "mailcredentials"
			}
		}
		// view must not expose spec.passwordHash (offline guessing of
		// bring-your-own passwords); edit and admin manage credentials.
		if wantCreds := name != "sigillum-view"; hasCreds != wantCreds {
			t.Fatalf("%s: covers mailcredentials = %v, want %v", name, hasCreds, wantCreds)
		}
	}
}

func TestChartClusterNameAndShutdown(t *testing.T) {
	objs := render(t, "--set", "clusterName=prod-eu", "--set", "serviceMonitor.enabled=true",
		"--set", "smtp.enabled=true", "--set", "rbac.allowedSecretNamespaces={mail,relay}")
	for _, dep := range []string{"t-sigillum-api", "t-sigillum-smtp", "t-sigillum-controller"} {
		a := args(t, objs, dep)
		if a["cluster-name"] != "prod-eu" || a["secret-namespaces"] != "mail,relay" {
			t.Fatalf("%s: cluster-name=%q secret-namespaces=%q", dep, a["cluster-name"], a["secret-namespaces"])
		}
	}
	sm := find(objs, "ServiceMonitor", "")
	if sm == nil {
		t.Fatal("ServiceMonitor missing")
	}
	eps, _, _ := unstructured.NestedSlice(sm.Object, "spec", "endpoints")
	relabel, _, _ := unstructured.NestedSlice(eps[0].(map[string]any), "relabelings")
	if len(relabel) != 1 || relabel[0].(map[string]any)["targetLabel"] != "cluster" ||
		relabel[0].(map[string]any)["replacement"] != "prod-eu" {
		t.Fatalf("want a cluster target label, got %v", relabel)
	}

	for _, dep := range []string{"t-sigillum-api", "t-sigillum-smtp"} {
		var d appsv1.Deployment
		into(t, find(objs, "Deployment", dep), &d)
		a := args(t, objs, dep)
		delay, err1 := time.ParseDuration(a["shutdown-delay"])
		timeout, err2 := time.ParseDuration(a["shutdown-timeout"])
		if err1 != nil || err2 != nil || delay <= 0 {
			t.Fatalf("%s: shutdown-delay=%q shutdown-timeout=%q", dep, a["shutdown-delay"], a["shutdown-timeout"])
		}
		grace := time.Duration(*d.Spec.Template.Spec.TerminationGracePeriodSeconds) * time.Second
		if delay+timeout >= grace {
			t.Fatalf("%s: shutdown delay %v + timeout %v must fit in terminationGracePeriodSeconds %v", dep, delay, timeout, grace)
		}
	}
}

func TestChartCredentialAuthNeedsTLS(t *testing.T) {
	cases := []struct {
		set  []string
		want string
	}{
		{nil, "false"}, // allowInsecureAuth unset follows TLS for tokens, never for passwords
		{[]string{"--set", "smtp.tls.secretName=smtp-tls"}, "false"},
		{[]string{"--set", "smtp.allowInsecureAuth=true"}, "true"},
	}
	for _, tc := range cases {
		objs := render(t, append([]string{"--set", "smtp.enabled=true", "--set", "smtp.authModes={oauthbearer,credential}"}, tc.set...)...)
		if got := args(t, objs, "t-sigillum-smtp")["allow-insecure-credential-auth"]; got != tc.want {
			t.Errorf("%v: allow-insecure-credential-auth=%q, want %q", tc.set, got, tc.want)
		}
	}
}

// The release workflow publishes the CHANGELOG.md section of the tagged
// version as release notes and fails without one; catch that before a tag.
func TestChangelogCoversChartVersion(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	chart, err := os.ReadFile(filepath.Join(chartDir(t), "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Version    string `json:"version"`
		AppVersion string `json:"appVersion"`
	}
	if err := yaml.Unmarshal(chart, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Version != meta.AppVersion {
		t.Fatalf("chart version %s != appVersion %s", meta.Version, meta.AppVersion)
	}
	root := filepath.Join(chartDir(t), "..", "..")
	out, err := exec.Command(bash, filepath.Join(root, "hack", "release-notes.sh"), meta.Version).CombinedOutput()
	if err != nil {
		t.Fatalf("CHANGELOG.md has no section for %s: %v\n%s", meta.Version, err, out)
	}
	if strings.Contains(string(out), "## [") {
		t.Fatalf("release notes for %s run into the next version:\n%s", meta.Version, out)
	}
}

// The chart declares its minimum Kubernetes version (1.32; the guard needs
// ValidatingAdmissionPolicy, GA in 1.30) instead of rendering the guard
// conditionally, so `helm template` without --api-versions (GitOps) still
// renders it.
func TestChartRequiresKubernetes132(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	out, err := exec.Command(helm, "template", "t", chartDir(t), "--kube-version", "1.31.9").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "kubeVersion") {
		t.Fatalf("chart must refuse Kubernetes 1.31, got %v\n%s", err, out)
	}
	objs := render(t)
	if find(objs, "ValidatingAdmissionPolicy", "t-sigillum-credential-guard") == nil {
		t.Fatal("guard must be rendered without --api-versions")
	}
}

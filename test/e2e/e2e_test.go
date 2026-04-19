//go:build e2e

// Package e2e runs an end-to-end smoke test against a kind cluster:
//   1. Assumes a kind cluster is up and the sigillum image is loaded
//      (both driven by `helm/kind-action` + `make kind-load` in CI).
//   2. Installs MailHog (a disposable SMTP sink) into the cluster.
//   3. Helm-installs the local chart with a ClusterMailBackend pointing at
//      MailHog and a permissive MailPolicy.
//   4. Creates a ServiceAccount, mints a TokenRequest for it, and POSTs a
//      message to the api-server.
//   5. Asserts the message landed in MailHog's HTTP inbox.
//
// All kubectl/helm calls shell out — this keeps the test independent of the
// specific go kube client generation used in the rest of the code base and
// makes it obvious what the test is doing.
package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	namespace  = "sigillum-e2e"
	mailhogNS  = "mailhog"
	chartPath  = "charts/sigillum"
	imageRepo  = "ghcr.io/se-wo/sigillum"
	imageTag   = "ci"
	apiPort    = "18443" // local forward port
	mailhogWeb = "18025"
)

func TestE2E_Smoke(t *testing.T) {
	if os.Getenv("SIGILLUM_E2E") != "1" && os.Getenv("CI") != "true" {
		t.Skip("set SIGILLUM_E2E=1 (or run in CI) to enable — requires a kind cluster")
	}
	root := repoRoot(t)

	run(t, root, "kubectl", "create", "namespace", namespace)
	run(t, root, "kubectl", "create", "namespace", mailhogNS)
	t.Cleanup(func() {
		run(t, root, "kubectl", "delete", "namespace", namespace, "--ignore-not-found", "--wait=false")
		run(t, root, "kubectl", "delete", "namespace", mailhogNS, "--ignore-not-found", "--wait=false")
		run(t, root, "helm", "uninstall", "sigillum", "-n", namespace, "--ignore-not-found")
	})

	// MailHog (single-pod, unauthenticated SMTP sink).
	apply(t, root, mailhogManifest)
	waitForReady(t, mailhogNS, "app=mailhog", 60*time.Second)

	// Install the chart — image is baked from the CI step that loaded it
	// into kind with tag `ci`. cert-manager was installed by the outer
	// workflow; we toggle useCertManager so the chart drops an Issuer +
	// Certificate and the cainjector fills in the webhook's caBundle.
	run(t, root, "helm", "upgrade", "--install", "sigillum", chartPath,
		"-n", namespace,
		"--set", "image.repository="+imageRepo,
		"--set", "image.tag="+imageTag,
		"--set", "image.pullPolicy=Never",
		"--set", "webhook.certificate.useCertManager=true",
		"--set", "api.tokenAudience=sigillum",
		"--wait", "--timeout", "300s",
	)

	// The webhook Secret arrives asynchronously from cert-manager, so a
	// bare `kubectl apply` can race with webhook readiness and get
	// rejected by the Fail-policy validating webhook. Retry creation
	// until admission accepts it.
	if err := pollUntil(120*time.Second, func() error {
		return applyErr(t, root, clusterBackendManifest)
	}); err != nil {
		t.Fatalf("apply ClusterMailBackend: %v", err)
	}
	if err := pollUntil(60*time.Second, func() error {
		return applyErr(t, root, policyManifest)
	}); err != nil {
		t.Fatalf("apply MailPolicy: %v", err)
	}

	// Wait for backend to go Ready (probe will dial MailHog).
	if err := pollUntil(60*time.Second, func() error {
		out, err := runOut(t, root, "kubectl", "get", "clustermailbackend", "mailhog", "-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
		if err != nil {
			return err
		}
		if strings.TrimSpace(out) != "True" {
			return fmt.Errorf("not ready yet: %q", out)
		}
		return nil
	}); err != nil {
		t.Fatalf("cmb never became Ready: %v", err)
	}

	// Create client ServiceAccount + mint a token.
	run(t, root, "kubectl", "-n", namespace, "create", "serviceaccount", "billing-mailer")
	token := tokenRequest(t, root, namespace, "billing-mailer")

	// Port-forward the api-server to localhost.
	stop := portForward(t, root, namespace, "svc/sigillum-api", apiPort+":8443")
	defer stop()

	// POST a message and assert 202.
	payload := map[string]any{
		"from":    map[string]string{"address": "billing@example.com"},
		"to":      []map[string]string{{"address": "bob@noreply.example.com"}},
		"subject": "e2e hello",
		"body":    map[string]string{"text": "hello from e2e"},
	}
	body, _ := json.Marshal(payload)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, "https://127.0.0.1:"+apiPort+"/v1/messages", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	var resp *http.Response
	err := pollUntil(30*time.Second, func() error {
		var err error
		resp, err = client.Do(req)
		return err
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 202, got %d body=%s", resp.StatusCode, b)
	}

	// Confirm MailHog received the mail via its HTTP v2 API.
	stop2 := portForward(t, root, mailhogNS, "svc/mailhog", mailhogWeb+":8025")
	defer stop2()

	if err := pollUntil(30*time.Second, func() error {
		r, err := http.Get("http://127.0.0.1:" + mailhogWeb + "/api/v2/messages")
		if err != nil {
			return err
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if !bytes.Contains(b, []byte("e2e hello")) {
			return fmt.Errorf("not delivered yet: %s", string(b))
		}
		return nil
	}); err != nil {
		t.Fatalf("MailHog never saw the message: %v", err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// test/e2e → repo root is two dirs up.
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v: %v", name, args, err)
	}
}

func runOut(t *testing.T, dir string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}

func apply(t *testing.T, dir, manifest string) {
	t.Helper()
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("apply: %v", err)
	}
}

// applyErr returns the apply error instead of failing the test — used for
// polling scenarios where admission races with webhook readiness.
func applyErr(t *testing.T, dir, manifest string) error {
	t.Helper()
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func waitForReady(t *testing.T, ns, selector string, timeout time.Duration) {
	t.Helper()
	args := []string{"wait", "--for=condition=Ready", "pod", "-n", ns, "-l", selector, fmt.Sprintf("--timeout=%s", timeout)}
	run(t, ".", "kubectl", args...)
}

func pollUntil(total time.Duration, fn func() error) error {
	deadline := time.Now().Add(total)
	var last error
	for time.Now().Before(deadline) {
		if err := fn(); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(2 * time.Second)
	}
	return last
}

func tokenRequest(t *testing.T, root, ns, sa string) string {
	t.Helper()
	out, err := runOut(t, root, "kubectl", "-n", ns, "create", "token", sa,
		"--audience=sigillum", "--duration=1h")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return strings.TrimSpace(out)
}

// portForward starts kubectl port-forward in the background. Returns a stop
// function to terminate it. Blocks until the forward appears usable.
func portForward(t *testing.T, root, ns, target, ports string) func() {
	t.Helper()
	cmd := exec.Command("kubectl", "-n", ns, "port-forward", target, ports)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("port-forward: %v", err)
	}
	// Give kubectl a moment to bind the local port.
	time.Sleep(2 * time.Second)
	return func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

// Manifests below are small enough to inline. All hostnames resolve inside
// the cluster.

const mailhogManifest = `---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mailhog
  namespace: mailhog
  labels: { app: mailhog }
spec:
  replicas: 1
  selector: { matchLabels: { app: mailhog } }
  template:
    metadata:
      labels: { app: mailhog }
    spec:
      containers:
      - name: mailhog
        image: mailhog/mailhog:v1.0.1
        ports:
        - { name: smtp, containerPort: 1025 }
        - { name: http, containerPort: 8025 }
        readinessProbe:
          tcpSocket: { port: 1025 }
---
apiVersion: v1
kind: Service
metadata:
  name: mailhog
  namespace: mailhog
spec:
  selector: { app: mailhog }
  ports:
  - { name: smtp, port: 1025, targetPort: 1025 }
  - { name: http, port: 8025, targetPort: 8025 }
`

const clusterBackendManifest = `---
apiVersion: sigillum.dev/v1alpha1
kind: ClusterMailBackend
metadata:
  name: mailhog
spec:
  type: smtp
  smtp:
    endpoints:
    - host: mailhog.mailhog.svc.cluster.local
      port: 1025
      tls: none
    authType: NONE
    connectionTimeoutSeconds: 5
`

const policyManifest = `---
apiVersion: sigillum.dev/v1alpha1
kind: MailPolicy
metadata:
  name: allow-billing
  namespace: sigillum-e2e
spec:
  priority: 100
  subjects:
  - serviceAccount:
      name: billing-mailer
  backendRef:
    name: mailhog
    kind: ClusterMailBackend
  senderRestrictions:
    allowedSenders:
    - "*@example.com"
`

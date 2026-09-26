//go:build e2e

// Package e2e runs an end-to-end smoke test against a kind cluster:
//  1. Assumes a kind cluster is up and the sigillum image is loaded
//     (both driven by `helm/kind-action` + `make kind-load` in CI).
//  2. Installs Mailpit (a disposable SMTP sink) into the cluster.
//  3. Helm-installs the local chart with a ClusterMailBackend pointing at
//     Mailpit and a permissive MailPolicy.
//  4. Creates a ServiceAccount, mints a TokenRequest for it, and POSTs a
//     message to the api-server.
//  5. Asserts the message landed in Mailpit's HTTP inbox and was audited.
//  6. Sends a second message through the SMTP proxy with AUTH OAUTHBEARER,
//     checks a spoofed header From is refused, and asserts delivery.
//  7. Issues a generated MailCredential, sends with AUTH PLAIN using the
//     password from the controller-written Secret, rotates it, and checks
//     that old (grace period) and new password both work (US-3.7).
//  8. Applies the require-sender-restrictions admission recipe and checks
//     that it refuses a MailPolicy without senders (US-5.7).
//
// All kubectl/helm calls shell out — this keeps the test independent of the
// specific go kube client generation used in the rest of the code base and
// makes it obvious what the test is doing.
package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

const (
	namespace  = "sigillum-e2e"
	mailpitNS  = "mailpit"
	appsNS     = "sigillum-e2e-apps"
	chartPath  = "charts/sigillum"
	imageRepo  = "ghcr.io/se-wo/sigillum"
	imageTag   = "ci"
	apiPort    = "18443" // local forward port
	smtpPort   = "12587"
	mailpitWeb = "18025"
)

func TestE2E_Smoke(t *testing.T) {
	if os.Getenv("SIGILLUM_E2E") != "1" && os.Getenv("CI") != "true" {
		t.Skip("set SIGILLUM_E2E=1 (or run in CI) to enable — requires a kind cluster")
	}
	root := repoRoot(t)

	run(t, root, "kubectl", "create", "namespace", namespace)
	run(t, root, "kubectl", "create", "namespace", mailpitNS)
	t.Cleanup(func() {
		run(t, root, "kubectl", "delete", "namespace", namespace, "--ignore-not-found", "--wait=false")
		run(t, root, "kubectl", "delete", "namespace", mailpitNS, "--ignore-not-found", "--wait=false")
		run(t, root, "helm", "uninstall", "sigillum", "-n", namespace, "--ignore-not-found")
	})

	// Mailpit (single-pod, unauthenticated SMTP sink).
	apply(t, root, mailpitManifest)
	waitForReady(t, mailpitNS, "app=mailpit", 60*time.Second)

	// Install the chart. Webhook admission is disabled for E2E — the
	// envtest suite already covers the validator; here we want the fast
	// path with no cert-manager dependency. See chart
	// controller-deployment.yaml: webhook.enabled=false also toggles
	// --disable-webhook=true on the controller binary.
	run(t, root, "helm", "upgrade", "--install", "sigillum", chartPath,
		"-n", namespace,
		"--set", "image.repository="+imageRepo,
		"--set", "image.tag="+imageTag,
		"--set", "image.pullPolicy=Never",
		"--set", "webhook.enabled=false",
		"--set", "api.tokenAudience=sigillum",
		"--set", "smtp.enabled=true",
		"--set", "smtp.replicas=1",
		"--set", "smtp.authModes={oauthbearer,credential}",
		// No STARTTLS certificate in e2e: allow credential logins in
		// plaintext (only ever over the port-forward).
		"--set", "smtp.allowInsecureAuth=true",
		"--set", "clusterName=e2e",
		"--wait", "--timeout", "180s",
	)

	apply(t, root, clusterBackendManifest)
	apply(t, root, policyManifest)

	// Wait for backend to go Ready (probe will dial Mailpit).
	if err := pollUntil(60*time.Second, func() error {
		out, err := runOut(t, root, "kubectl", "get", "clustermailbackend", "mailpit", "-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
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
		"from":    "billing@example.com",
		"to":      []string{"bob@noreply.example.com"},
		"subject": "e2e hello",
		"body":    map[string]string{"text": "hello from e2e"},
	}
	body, _ := json.Marshal(payload)
	// The chart's api.tls.secretName is empty by default so the
	// api-server listens plain HTTP on its service port.
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+apiPort+"/v1/messages", bytes.NewReader(body))
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

	// Confirm Mailpit received the mail via its HTTP API.
	stop2 := portForward(t, root, mailpitNS, "svc/mailpit", mailpitWeb+":8025")
	defer stop2()
	waitForMailpit(t, "e2e hello")

	// The accepted request must show up in the audit stream (US-4.3).
	if err := pollUntil(30*time.Second, func() error {
		out, err := runOut(t, root, "kubectl", "-n", namespace, "logs", "-l", "app.kubernetes.io/component=api", "--tail=-1")
		if err != nil {
			return err
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, `"stream":"audit"`) && strings.Contains(line, `"decision":"accept"`) &&
				strings.Contains(line, `"service_account":"billing-mailer"`) && strings.Contains(line, `"cluster":"e2e"`) {
				return nil
			}
		}
		return fmt.Errorf("no audit record yet")
	}); err != nil {
		t.Fatalf("audit stream: %v", err)
	}

	// SMTP proxy with AUTH OAUTHBEARER (US-1.2, US-3.4).
	stop3 := portForward(t, root, namespace, "svc/sigillum-smtp", smtpPort+":587")
	defer stop3()
	var c *smtp.Client
	if err := pollUntil(30*time.Second, func() error {
		var err error
		c, err = smtp.Dial("127.0.0.1:" + smtpPort)
		return err
	}); err != nil {
		t.Fatalf("dial smtp proxy: %v", err)
	}
	defer c.Close()
	if err := c.Auth(sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{Username: "billing-mailer", Token: token})); err != nil {
		t.Fatalf("AUTH OAUTHBEARER: %v", err)
	}
	spoofed := "From: ceo@evil.test\r\nTo: bob@noreply.example.com\r\nSubject: spoof\r\n\r\nx\r\n"
	err = smtpSend(c, "billing@example.com", "bob@noreply.example.com", spoofed)
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 550 {
		t.Fatalf("spoofed header From must be refused with 550, got %v", err)
	}
	legit := "From: billing@example.com\r\nTo: bob@noreply.example.com\r\nSubject: e2e smtp hello\r\n\r\nhello via smtp\r\n"
	if err := smtpSend(c, "billing@example.com", "bob@noreply.example.com", legit); err != nil {
		t.Fatalf("send via smtp proxy: %v", err)
	}
	_ = c.Quit()
	waitForMailpit(t, "e2e smtp hello")

	testMailCredential(t, root)
	testAdmissionRecipe(t, root)
}

// testMailCredential covers generated MailCredentials end to end: the
// controller writes the Secret (through the credential Secret guard), the
// proxy accepts AUTH PLAIN with it, and a rotation keeps the old password
// valid for the grace period.
func testMailCredential(t *testing.T, root string) {
	// The release namespace never holds MailCredentials; use an app namespace.
	run(t, root, "kubectl", "create", "namespace", appsNS)
	t.Cleanup(func() {
		run(t, root, "kubectl", "delete", "namespace", appsNS, "--ignore-not-found", "--wait=false")
	})
	run(t, root, "kubectl", "-n", appsNS, "create", "serviceaccount", "grafana")
	apply(t, root, credentialManifest)
	secretPassword := func() string {
		t.Helper()
		var pw string
		if err := pollUntil(120*time.Second, func() error {
			out, err := runOut(t, root, "kubectl", "-n", appsNS, "get", "secret", "grafana-smtp",
				"-o", "jsonpath={.data.password}")
			if err != nil || strings.TrimSpace(out) == "" {
				return fmt.Errorf("secret not written yet: %v", err)
			}
			b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
			pw = string(b)
			return err
		}); err != nil {
			out, _ := runOut(t, root, "kubectl", "-n", appsNS, "get", "mailcredential", "grafana", "-o", "yaml")
			t.Fatalf("credential Secret: %v\n%s", err, out)
		}
		return pw
	}
	waitReady := func() {
		t.Helper()
		if err := pollUntil(60*time.Second, func() error {
			out, err := runOut(t, root, "kubectl", "-n", appsNS, "get", "mailcredential", "grafana",
				"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
			if err != nil || strings.TrimSpace(out) != "True" {
				return fmt.Errorf("not ready: %q %v", out, err)
			}
			return nil
		}); err != nil {
			t.Fatalf("MailCredential never became Ready: %v", err)
		}
	}
	waitReady()
	first := secretPassword()
	user := "grafana." + appsNS

	sendAs := func(password, subject string) error {
		c, err := smtp.Dial("127.0.0.1:" + smtpPort)
		if err != nil {
			return err
		}
		defer c.Close()
		if err := c.Auth(sasl.NewPlainClient("", user, password)); err != nil {
			return fmt.Errorf("AUTH PLAIN: %w", err)
		}
		msg := "From: grafana@example.com\r\nTo: bob@noreply.example.com\r\nSubject: " + subject + "\r\n\r\nvia credential\r\n"
		if err := smtpSend(c, "grafana@example.com", "bob@noreply.example.com", msg); err != nil {
			return err
		}
		return c.Quit()
	}
	if err := pollUntil(30*time.Second, func() error { return sendAs(first, "e2e credential hello") }); err != nil {
		t.Fatalf("send with MailCredential: %v", err)
	}
	waitForMailpit(t, "e2e credential hello")
	if err := sendAs("wrong-password", "never"); err == nil {
		t.Fatal("a wrong password must be refused")
	}

	// allowedRecipients: a listed mailbox and a glob match pass, another
	// mailbox in the same domain is refused (issue #6).
	sendTo := func(rcpt, subject string) error {
		c, err := smtp.Dial("127.0.0.1:" + smtpPort)
		if err != nil {
			return err
		}
		defer c.Close()
		if err := c.Auth(sasl.NewPlainClient("", user, first)); err != nil {
			return fmt.Errorf("AUTH PLAIN: %w", err)
		}
		msg := "From: grafana@example.com\r\nTo: " + rcpt + "\r\nSubject: " + subject + "\r\n\r\nrecipient check\r\n"
		if err := smtpSend(c, "grafana@example.com", rcpt, msg); err != nil {
			return err
		}
		return c.Quit()
	}
	if err := sendTo("pager@oncall.example.com", "e2e glob recipient"); err != nil {
		t.Fatalf("glob-matched recipient must be accepted: %v", err)
	}
	waitForMailpit(t, "e2e glob recipient")
	var se *smtp.SMTPError
	if err := sendTo("eve@noreply.example.com", "never"); !errors.As(err, &se) || se.Code != 550 {
		t.Fatalf("mailbox outside allowedRecipients must be refused with 550, got %v", err)
	}

	// Rotate on demand; both passwords work during the grace period.
	run(t, root, "kubectl", "-n", appsNS, "annotate", "mailcredential", "grafana", "sigillum.dev/rotate=1", "--overwrite")
	var second string
	if err := pollUntil(60*time.Second, func() error {
		second = secretPassword()
		if second == first {
			return fmt.Errorf("not rotated yet")
		}
		return nil
	}); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	waitReady()
	if err := pollUntil(30*time.Second, func() error { return sendAs(second, "e2e rotated hello") }); err != nil {
		t.Fatalf("send with rotated password: %v", err)
	}
	if err := sendAs(first, "e2e previous hello"); err != nil {
		t.Fatalf("previous password must work during the grace period: %v", err)
	}
	waitForMailpit(t, "e2e previous hello")

	if err := pollUntil(30*time.Second, func() error {
		out, err := runOut(t, root, "kubectl", "-n", namespace, "logs", "-l", "app.kubernetes.io/component=smtp", "--tail=-1")
		if err != nil {
			return err
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, `"stream":"audit"`) && strings.Contains(line, `"auth_method":"smtp_credential"`) &&
				strings.Contains(line, `"credential_previous":true`) && strings.Contains(line, `"decision":"accept"`) {
				return nil
			}
		}
		return fmt.Errorf("no audit record for the previous password yet")
	}); err != nil {
		t.Fatalf("audit stream: %v", err)
	}
}

// testAdmissionRecipe applies examples/admission/vap-require-sender-restrictions.yaml.
func testAdmissionRecipe(t *testing.T, root string) {
	recipe := filepath.Join(root, "examples", "admission", "vap-require-sender-restrictions.yaml")
	run(t, root, "kubectl", "apply", "-f", recipe)
	t.Cleanup(func() { run(t, root, "kubectl", "delete", "-f", recipe, "--ignore-not-found") })
	if err := pollUntil(60*time.Second, func() error {
		cmd := exec.Command("kubectl", "apply", "--dry-run=server", "-f", "-")
		cmd.Dir = root
		cmd.Stdin = strings.NewReader(noSendersPolicyManifest)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return fmt.Errorf("policy without senders was admitted")
		}
		if !strings.Contains(string(out), "allowedSenders") {
			return fmt.Errorf("unexpected error: %v: %s", err, out)
		}
		return nil
	}); err != nil {
		t.Fatalf("admission recipe: %v", err)
	}
}

func smtpSend(c *smtp.Client, from, to, msg string) error {
	if err := c.Mail(from, nil); err != nil {
		return err
	}
	if err := c.Rcpt(to, nil); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, msg); err != nil {
		return err
	}
	return w.Close()
}

func waitForMailpit(t *testing.T, subject string) {
	t.Helper()
	if err := pollUntil(30*time.Second, func() error {
		r, err := http.Get("http://127.0.0.1:" + mailpitWeb + "/api/v1/messages")
		if err != nil {
			return err
		}
		defer r.Body.Close()
		var inbox struct {
			Messages []struct {
				Subject string `json:"Subject"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&inbox); err != nil {
			return fmt.Errorf("decode mailpit inbox: %w", err)
		}
		seen := make([]string, 0, len(inbox.Messages))
		for _, m := range inbox.Messages {
			if m.Subject == subject {
				return nil
			}
			seen = append(seen, m.Subject)
		}
		return fmt.Errorf("not delivered yet; inbox subjects: %q", seen)
	}); err != nil {
		t.Fatalf("Mailpit never saw %q: %v", subject, err)
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

const mailpitManifest = `---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mailpit
  namespace: mailpit
  labels: { app: mailpit }
spec:
  replicas: 1
  selector: { matchLabels: { app: mailpit } }
  template:
    metadata:
      labels: { app: mailpit }
    spec:
      containers:
      - name: mailpit
        image: axllent/mailpit:v1.31.2
        ports:
        - { name: smtp, containerPort: 1025 }
        - { name: http, containerPort: 8025 }
        readinessProbe:
          tcpSocket: { port: 1025 }
---
apiVersion: v1
kind: Service
metadata:
  name: mailpit
  namespace: mailpit
spec:
  selector: { app: mailpit }
  ports:
  - { name: smtp, port: 1025, targetPort: 1025 }
  - { name: http, port: 8025, targetPort: 8025 }
`

const clusterBackendManifest = `---
apiVersion: sigillum.dev/v1alpha1
kind: ClusterMailBackend
metadata:
  name: mailpit
spec:
  type: smtp
  smtp:
    endpoints:
    - host: mailpit.mailpit.svc.cluster.local
      port: 1025
      tls: none
    authType: NONE
    connectionTimeoutSeconds: 5
`

const credentialManifest = `---
apiVersion: sigillum.dev/v1alpha1
kind: MailCredential
metadata:
  name: grafana
  namespace: sigillum-e2e-apps
spec:
  serviceAccountName: grafana
  secretName: grafana-smtp
  rotation:
    gracePeriod: 1h
---
apiVersion: sigillum.dev/v1alpha1
kind: MailPolicy
metadata:
  name: grafana
  namespace: sigillum-e2e-apps
spec:
  subjects:
  - serviceAccount:
      name: grafana
  backendRef:
    name: mailpit
    kind: ClusterMailBackend
  senderRestrictions:
    allowedSenders:
    - grafana@example.com
  recipientRestrictions:        # issue #6: single mailboxes and domain globs
    allowedRecipients:
    - bob@noreply.example.com
    - "*@oncall.example.com"
`

const noSendersPolicyManifest = `---
apiVersion: sigillum.dev/v1alpha1
kind: MailPolicy
metadata:
  name: no-senders
  namespace: sigillum-e2e
spec:
  subjects:
  - serviceAccount:
      name: billing-mailer
  backendRef:
    name: mailpit
    kind: ClusterMailBackend
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
    name: mailpit
    kind: ClusterMailBackend
  senderRestrictions:
    allowedSenders:
    - "*@example.com"
`

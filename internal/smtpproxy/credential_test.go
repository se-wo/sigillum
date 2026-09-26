package smtpproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/textproto"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/credential"
	"github.com/se-wo/sigillum/internal/gateway"
)

const (
	credUser     = "grafana.monitoring"
	credPassword = "correct-horse-battery-staple-0123456789abcdef"
)

// readyCredential is a generated-mode MailCredential as the controller
// leaves it once the password is issued.
func readyCredential(currentPassword string) *sigv1.MailCredential {
	return &sigv1.MailCredential{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "monitoring", Generation: 1, UID: "uid-1"},
		Spec:       sigv1.MailCredentialSpec{ServiceAccountName: "grafana", SecretName: "grafana-smtp"},
		Status: sigv1.MailCredentialStatus{
			Username:           credUser,
			ServiceAccountName: "grafana",
			SecretName:         "grafana-smtp",
			Current:            &sigv1.CredentialHash{Hash: credential.HashGenerated(currentPassword), CreatedAt: metav1.Now()},
			ObservedGeneration: 1,
			Conditions: []metav1.Condition{{Type: sigv1.ConditionReady, Status: metav1.ConditionTrue,
				ObservedGeneration: 1, Reason: sigv1.ReasonReady, LastTransitionTime: metav1.Now()}},
		},
	}
}

func credentialClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := sigv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&sigv1.MailCredential{}).Build()
}

func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sigillum"},
		DNSNames:     []string{"sigillum"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func startTLSProxy(t *testing.T, b *Backend) string {
	t.Helper()
	b.Logger = discardLogger()
	b.AuthTimeout = time.Second
	o, err := ParseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(o, b, selfSignedTLS(t))
	srv.AllowInsecureAuth = true // tokens may use plaintext; credentials still need TLS
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestCredential_PlainRequiresTLS(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	b := &Backend{Sender: sender, Tokens: stubTokens{},
		Credentials: credential.NewVerifier(credentialClient(t, readyCredential(credPassword)), 1)}
	addr := startTLSProxy(t, b)

	c := dial(t, addr)
	if _, params := c.Extension("AUTH"); strings.Contains(params, "PLAIN") || strings.Contains(params, "LOGIN") {
		t.Fatalf("PLAIN/LOGIN must not be offered before STARTTLS: %q", params)
	}
	err := c.Auth(sasl.NewPlainClient("", credUser, credPassword))
	if smtpCode(err) != 538 {
		t.Fatalf("want 538 encryption required, got %v", err)
	}

	c, err = smtp.DialStartTLS(addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test certificate
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, params := c.Extension("AUTH"); !strings.Contains(params, "PLAIN") || !strings.Contains(params, "LOGIN") {
		t.Fatalf("PLAIN and LOGIN must be offered after STARTTLS: %q", params)
	}
	if err := c.Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
		t.Fatalf("AUTH PLAIN: %v", err)
	}
	msg := "From: grafana@monitoring.example\r\nTo: ops@example.com\r\nSubject: alert\r\n\r\nfiring\r\n"
	if err := send(c, "grafana@monitoring.example", []string{"ops@example.com"}, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(sender.reqs) != 1 {
		t.Fatalf("want one gateway request, got %d", len(sender.reqs))
	}
	id := sender.reqs[0].Identity
	if id.Namespace != "monitoring" || id.ServiceAccount != "grafana" || id.AuthMethod != gateway.AuthSMTPCredential ||
		id.Credential != credUser || id.CredentialPrevious {
		t.Fatalf("unexpected identity %+v", id)
	}
	if !strings.Contains(string(sender.reqs[0].Raw), "with ESMTPSA id ") {
		t.Fatalf("Received header must say ESMTPSA: %q", sender.reqs[0].Raw[:120])
	}
}

func TestCredential_LoginMechanismAndInsecureOptIn(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	addr := startProxy(t, &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(credentialClient(t, readyCredential(credPassword)), 1)})

	conn, err := textproto.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expect := func(code int) string {
		t.Helper()
		_, msg, err := conn.ReadResponse(code)
		if err != nil {
			t.Fatalf("want %d: %v", code, err)
		}
		return msg
	}
	b64 := base64.StdEncoding.EncodeToString
	expect(220)
	_ = conn.PrintfLine("EHLO client.test")
	if ext := expect(250); !strings.Contains(ext, "AUTH PLAIN LOGIN") {
		t.Fatalf("PLAIN/LOGIN must be offered with the insecure opt-in: %q", ext)
	}
	_ = conn.PrintfLine("AUTH LOGIN")
	if ch, _ := base64.StdEncoding.DecodeString(expect(334)); string(ch) != "Username:" {
		t.Fatalf("unexpected challenge %q", ch)
	}
	_ = conn.PrintfLine("%s", b64([]byte(credUser)))
	if ch, _ := base64.StdEncoding.DecodeString(expect(334)); string(ch) != "Password:" {
		t.Fatalf("unexpected challenge %q", ch)
	}
	_ = conn.PrintfLine("%s", b64([]byte(credPassword)))
	expect(235)
	_ = conn.PrintfLine("MAIL FROM:<grafana@monitoring.example>")
	expect(250)
}

// byoCredential is a ready bring-your-own-hash credential for password.
func byoCredential(password string) *sigv1.MailCredential {
	mc := readyCredential("unused")
	mc.Spec.SecretName, mc.Status.SecretName = "", ""
	mc.Spec.PasswordHash = credential.HashArgon2id(password, []byte("0123456789abcdef"), 7*1024, 5, 1)
	mc.Status.Current = &sigv1.CredentialHash{Hash: mc.Spec.PasswordHash, CreatedAt: metav1.Now()}
	return mc
}

func TestCredential_FailuresAreAuditedAndThrottled(t *testing.T) {
	sender := &stubSender{}
	b := &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials:  credential.NewVerifier(credentialClient(t, byoCredential(credPassword)), 1),
		AuthFailures: &FailureLimiter{Window: time.Minute, PerUserIP: 2}}
	addr := startProxy(t, b)

	for i := 0; i < 2; i++ {
		c := dial(t, addr)
		if err := c.Auth(sasl.NewPlainClient("", credUser, "wrong")); smtpCode(err) != 535 {
			t.Fatalf("attempt %d: want 535, got %v", i, err)
		}
	}
	// The limit is reached for this username from this IP: even the right
	// password is refused for now.
	c := dial(t, addr)
	if err := c.Auth(sasl.NewPlainClient("", credUser, credPassword)); smtpCode(err) != 454 {
		t.Fatalf("want 454 while throttled, got %v", err)
	}
	want := []string{"invalid_credentials", "invalid_credentials", "auth_rate_limited"}
	if strings.Join(sender.rejects, ",") != strings.Join(want, ",") {
		t.Fatalf("audit reasons %v, want %v", sender.rejects, want)
	}
	for _, ev := range sender.events {
		if ev.AuthMethod != gateway.AuthSMTPCredential || ev.Credential != credUser {
			t.Fatalf("failed login must be audited with the credential username: %+v", ev)
		}
	}

	// A different, unthrottled user with a bad authzid is refused.
	c = dial(t, addr)
	if err := c.Auth(sasl.NewPlainClient("other.monitoring", "x.monitoring", "pw")); smtpCode(err) != 535 {
		t.Fatalf("mismatched authzid: want 535, got %v", err)
	}
}

// Attempts count before the check; a successful login must take its
// attempt back, or an app would lock itself out after a few logins.
func TestCredential_SuccessfulLoginsAreNotThrottled(t *testing.T) {
	addr := startProxy(t, &Backend{Sender: &stubSender{}, AllowInsecureCredentialAuth: true,
		Credentials:  credential.NewVerifier(credentialClient(t, byoCredential(credPassword)), 1),
		AuthFailures: &FailureLimiter{Window: time.Minute, PerUserIP: 2}})
	for i := 0; i < 4; i++ {
		if err := dial(t, addr).Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}
}

func TestCredential_PreviousPasswordAndRevocation(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	mc := readyCredential("new-password-0123456789abcdef0123456789")
	mc.Status.Previous = &sigv1.PreviousCredentialHash{Hash: credential.HashGenerated(credPassword),
		ValidUntil: metav1.NewTime(time.Now().Add(time.Hour))}
	cl := credentialClient(t, mc)
	addr := startProxy(t, &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(cl, 1)})

	c := dial(t, addr)
	if err := c.Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
		t.Fatalf("previous password must work during the grace period: %v", err)
	}
	msg := "From: grafana@monitoring.example\r\nTo: ops@example.com\r\nSubject: alert\r\n\r\nfiring\r\n"
	if err := send(c, "grafana@monitoring.example", []string{"ops@example.com"}, msg); err != nil {
		t.Fatal(err)
	}
	if !sender.reqs[0].Identity.CredentialPrevious {
		t.Fatal("use of the previous password must be flagged for the audit record")
	}

	// Deleting the MailCredential ends the open session too.
	if err := cl.Delete(context.Background(), mc); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("grafana@monitoring.example", nil); smtpCode(err) != 454 {
		t.Fatalf("want 454 after revocation, got %v", err)
	}
}

// Review of #20: a revoked session stays revoked; with the pod-IP fallback
// enabled it must not continue as the pod that owns the source IP.
func TestCredential_RevokedSessionDoesNotFallBackToPodIP(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	mc := readyCredential(credPassword)
	cl := credentialClient(t, mc)
	pods := stubPods{id: &PodIdentity{Namespace: "legacy", Name: "cron-1", ServiceAccount: "default"}}
	addr := startProxy(t, &Backend{Sender: sender, AllowInsecureCredentialAuth: true, Pods: pods,
		Credentials: credential.NewVerifier(cl, 1)})
	c := dial(t, addr)
	if err := c.Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
		t.Fatal(err)
	}
	if err := cl.Delete(context.Background(), mc); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := c.Mail("grafana@monitoring.example", nil); smtpCode(err) != 454 {
			t.Fatalf("MAIL %d after revocation: want 454, got %v", i, err)
		}
	}
	if len(sender.reqs) != 0 {
		t.Fatalf("nothing may be sent: %+v", sender.reqs)
	}
}

// Review of #20: a transaction started before the revocation must not be
// relayed; the credential is checked again before the message goes out.
func TestCredential_RevokedBeforeDataIsNotRelayed(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	mc := readyCredential(credPassword)
	cl := credentialClient(t, mc)
	addr := startProxy(t, &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(cl, 1)})
	c := dial(t, addr)
	if err := c.Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("grafana@monitoring.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("ops@example.com", nil); err != nil {
		t.Fatal(err)
	}
	if err := cl.Delete(context.Background(), mc); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "From: grafana@monitoring.example\r\nTo: ops@example.com\r\nSubject: x\r\n\r\nbody\r\n")
	// Temporary: a message queued before a rotation must not bounce.
	err = w.Close()
	if smtpCode(err) != 454 {
		t.Fatalf("want 454 at the end of DATA, got %v", err)
	}
	if len(sender.reqs) != 0 {
		t.Fatalf("a revoked credential's message must not be relayed: %+v", sender.reqs)
	}
	// The refusal is audited under the message ID quoted in the reply.
	ev := sender.events[len(sender.events)-1]
	if sender.rejects[len(sender.rejects)-1] != "invalid_credentials" || ev.MessageID == "" ||
		!strings.Contains(err.Error(), "(id "+ev.MessageID+")") {
		t.Fatalf("audit message ID %q not in reply %q", ev.MessageID, err)
	}
}

// Review of #20: switching a bring-your-own-hash credential to generated
// mode ends sessions that logged in with the old password, even before the
// controller issued a generated one (status.current still holds the
// argon2id hash).
func TestCredential_SwitchToGeneratedEndsOwnHashSessions(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	mc := byoCredential(credPassword)
	cl := credentialClient(t, mc)
	addr := startProxy(t, &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(cl, 1)})
	c := dial(t, addr)
	if err := c.Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
		t.Fatal(err)
	}
	mc.Spec.PasswordHash, mc.Spec.SecretName = "", "grafana-smtp"
	if err := cl.Update(context.Background(), mc); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("grafana@monitoring.example", nil); smtpCode(err) != 454 {
		t.Fatalf("want 454 after the switch to generated mode, got %v", err)
	}
}

// Review of #20: a failed lookup is a temporary failure, not a revocation.
func TestCredential_LookupErrorIsTemporary(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	var failing atomic.Bool
	cl := interceptor.NewClient(credentialClient(t, readyCredential(credPassword)).(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if failing.Load() {
				return context.DeadlineExceeded
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	addr := startProxy(t, &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(cl, 1)})
	c := dial(t, addr)
	if err := c.Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
		t.Fatal(err)
	}
	failing.Store(true)
	if err := c.Mail("grafana@monitoring.example", nil); smtpCode(err) != 454 {
		t.Fatalf("lookup failure: want 454, got %v", err)
	}
	failing.Store(false)
	msg := "From: grafana@monitoring.example\r\nTo: ops@example.com\r\nSubject: alert\r\n\r\nfiring\r\n"
	if err := send(c, "grafana@monitoring.example", []string{"ops@example.com"}, msg); err != nil {
		t.Fatalf("the session must go on once the lookup works again: %v", err)
	}
}

// Review of #20: a session that logged in with the current password and
// keeps sending after a rotation uses the previous password from then on;
// its messages must be audited as such.
func TestCredential_PreviousFlagFollowsRotation(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	mc := readyCredential(credPassword)
	cl := credentialClient(t, mc)
	addr := startProxy(t, &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(cl, 1)})
	c := dial(t, addr)
	if err := c.Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
		t.Fatal(err)
	}
	msg := "From: grafana@monitoring.example\r\nTo: ops@example.com\r\nSubject: alert\r\n\r\nfiring\r\n"
	if err := send(c, "grafana@monitoring.example", []string{"ops@example.com"}, msg); err != nil {
		t.Fatal(err)
	}
	mc.Status.Previous = &sigv1.PreviousCredentialHash{Hash: mc.Status.Current.Hash,
		ValidUntil: metav1.NewTime(time.Now().Add(time.Hour))}
	mc.Status.Current = &sigv1.CredentialHash{Hash: credential.HashGenerated("rotated"), CreatedAt: metav1.Now()}
	if err := cl.Status().Update(context.Background(), mc); err != nil {
		t.Fatal(err)
	}
	if err := send(c, "grafana@monitoring.example", []string{"ops@example.com"}, msg); err != nil {
		t.Fatal(err)
	}
	if sender.reqs[0].Identity.CredentialPrevious || !sender.reqs[1].Identity.CredentialPrevious {
		t.Fatalf("credential_previous must follow the rotation: %v, %v",
			sender.reqs[0].Identity.CredentialPrevious, sender.reqs[1].Identity.CredentialPrevious)
	}
}

func TestCredential_BringYourOwnHash(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	addr := startProxy(t, &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(credentialClient(t, byoCredential("user-chosen")), 1)})

	if err := dial(t, addr).Auth(sasl.NewPlainClient("", credUser, "wrong")); smtpCode(err) != 535 {
		t.Fatalf("want 535, got %v", err)
	}
	if err := dial(t, addr).Auth(sasl.NewPlainClient("", credUser, "user-chosen")); err != nil {
		t.Fatalf("argon2id credential: %v", err)
	}
}

func TestCredential_NotReadyIsRefused(t *testing.T) {
	notReady := readyCredential(credPassword)
	notReady.Status.Conditions[0].Status = metav1.ConditionFalse
	// Review of #20: a changed ServiceAccount or bring-your-own hash takes
	// effect only once the controller accepted it; the old values stop
	// working at once.
	newSA := readyCredential(credPassword)
	newSA.Generation, newSA.Spec.ServiceAccountName = 2, "admin"
	newHash := byoCredential(credPassword)
	newHash.Generation = 2
	newHash.Status.Current.Hash = credential.HashArgon2id("replaced", []byte("0123456789abcdef"), 7*1024, 5, 1)
	for name, mc := range map[string]*sigv1.MailCredential{"not ready": notReady, "new ServiceAccount": newSA, "new hash": newHash} {
		addr := startProxy(t, &Backend{Sender: &stubSender{}, AllowInsecureCredentialAuth: true,
			Credentials: credential.NewVerifier(credentialClient(t, mc), 1)})
		if err := dial(t, addr).Auth(sasl.NewPlainClient("", credUser, credPassword)); smtpCode(err) != 535 {
			t.Fatalf("%s: want 535 for a credential the controller has not accepted, got %v", name, err)
		}
	}
}

// Review of #20: other spec edits must not suspend a credential until the
// controller catches up (it may be down).
func TestCredential_SpecEditKeepsWorking(t *testing.T) {
	mc := readyCredential(credPassword)
	mc.Generation = 2
	mc.Spec.Rotation = &sigv1.CredentialRotation{Interval: "90d"}
	addr := startProxy(t, &Backend{Sender: &stubSender{}, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(credentialClient(t, mc), 1)})
	if err := dial(t, addr).Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
		t.Fatalf("a rotation edit must not lock out the app: %v", err)
	}
}

// failOnce records one failed attempt of username from ip.
func failOnce(t *testing.T, f *FailureLimiter, username, ip string) {
	t.Helper()
	done, err := f.Begin(context.Background(), username, ip)
	if err != nil {
		t.Fatalf("attempt of %s from %s refused: %v", username, ip, err)
	}
	done(true)
}

// blocked reports whether the next attempt of username from ip is refused.
func blocked(f *FailureLimiter, username, ip string) bool {
	done, err := f.Begin(context.Background(), username, ip)
	if err != nil {
		return errors.Is(err, errThrottled)
	}
	done(false)
	return false
}

func TestFailureLimiterWindow(t *testing.T) {
	now := time.Unix(0, 0)
	f := &FailureLimiter{Window: time.Minute, PerUserIP: 2, now: func() time.Time { return now }}
	failOnce(t, f, "a", "1.1.1.1")
	failOnce(t, f, "a", "1.1.1.1")
	if !blocked(f, "a", "1.1.1.1") {
		t.Fatal("username+IP limit reached")
	}
	// Failing on a username from one IP must not lock out the real app,
	// which logs in from another IP, nor other users behind the same IP
	// (a mesh sidecar or SNAT gives every caller one source IP).
	if blocked(f, "a", "2.2.2.2") || blocked(f, "b", "1.1.1.1") {
		t.Fatal("only the username+IP pair is blocked")
	}
	now = now.Add(61 * time.Second)
	if blocked(f, "a", "1.1.1.1") {
		t.Fatal("failures must expire after the window")
	}
	if f.hits.Len() != 0 || len(f.busy) != 0 {
		t.Fatalf("expired keys and finished turns must be pruned, have %d keys, %d turns", f.hits.Len(), len(f.busy))
	}
}

// Review of #20: parallel attempts of one username and source IP run one
// at a time. Parallel correct logins all succeed (they used to be counted
// as failures while waiting), and parallel wrong ones cannot pass the
// limit.
func TestCredential_ParallelLoginsAreSerialized(t *testing.T) {
	addr := startProxy(t, &Backend{Sender: &stubSender{}, AllowInsecureCredentialAuth: true,
		Credentials:  credential.NewVerifier(credentialClient(t, byoCredential(credPassword)), 1),
		AuthFailures: &FailureLimiter{Window: time.Minute, PerUserIP: 3},
		AuthTimeout:  10 * time.Second})
	login := func(password string) []int {
		codes := make([]int, 8)
		var wg sync.WaitGroup
		for i := range codes {
			c := dial(t, addr)
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[i] = smtpCode(c.Auth(sasl.NewPlainClient("", credUser, password)))
			}()
		}
		wg.Wait()
		sort.Ints(codes)
		return codes
	}
	if got := login(credPassword); fmt.Sprint(got) != "[0 0 0 0 0 0 0 0]" {
		t.Fatalf("parallel correct logins: %v", got)
	}
	if got := login("wrong"); fmt.Sprint(got) != "[454 454 454 454 454 535 535 535]" {
		t.Fatalf("parallel wrong logins: want 3×535 and the rest throttled, got %v", got)
	}
}

// Flooding the tracker with new keys must not evict a key that keeps
// failing (review of #20: a full reset used to clear active blocks).
func TestFailureLimiterFloodKeepsActiveBlock(t *testing.T) {
	f := &FailureLimiter{Window: time.Hour, PerUserIP: 3}
	for i := 0; i < 3; i++ {
		failOnce(t, f, "victim.ns", "10.0.0.1")
	}
	for i := 0; i < maxFailureKeys+10; i++ {
		failOnce(t, f, fmt.Sprintf("u%d.ns", i), "10.0.0.2")
		if i%1000 == 0 && !blocked(f, "victim.ns", "10.0.0.1") {
			t.Fatalf("active block evicted after %d new keys", i)
		}
	}
	if !blocked(f, "victim.ns", "10.0.0.1") {
		t.Fatal("active block evicted by a flood of new keys")
	}
}

// Generated passwords have 256 bits: they are never throttled, so nobody
// can lock out the real app by failing on its username.
func TestCredential_GeneratedNotThrottled(t *testing.T) {
	addr := startProxy(t, &Backend{Sender: &stubSender{}, AllowInsecureCredentialAuth: true,
		Credentials:  credential.NewVerifier(credentialClient(t, readyCredential(credPassword)), 1),
		AuthFailures: &FailureLimiter{Window: time.Minute, PerUserIP: 1}})
	for i := 0; i < 3; i++ {
		if err := dial(t, addr).Auth(sasl.NewPlainClient("", credUser, "wrong")); smtpCode(err) != 535 {
			t.Fatalf("attempt %d: want 535, got %v", i, err)
		}
	}
	if err := dial(t, addr).Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
		t.Fatalf("generated credential must not be throttled: %v", err)
	}
}

func TestSMTPAuthModeCredentialFlag(t *testing.T) {
	o, err := ParseFlags([]string{"--auth-modes=oauthbearer,credential"})
	if err != nil || !o.has(ModeCredential) || o.AllowInsecureCredentialAuth {
		t.Fatalf("parse: %v %+v", err, o)
	}
	var _ smtp.Backend = &Backend{}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Command-level rejects of a credential session carry the credential in
// the audit record, like accepted messages do.
func TestCredential_CommandRejectAuditsCredential(t *testing.T) {
	sender := &stubSender{}
	addr := startProxy(t, &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(credentialClient(t, readyCredential(credPassword)), 1)})
	c := dial(t, addr)
	if err := c.Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("", nil); smtpCode(err) != 550 {
		t.Fatalf("null sender: want 550, got %v", err)
	}
	ev := sender.events[len(sender.events)-1]
	if sender.rejects[len(sender.rejects)-1] != "null_sender" || ev.Credential != credUser ||
		ev.AuthMethod != gateway.AuthSMTPCredential {
		t.Fatalf("reject must be audited with the credential: %+v", ev)
	}
}

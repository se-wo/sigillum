package controller

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/oauth/oauthtest"

	_ "github.com/se-wo/sigillum/internal/driver/smtp"
)

const testClientID = "11111111-2222-3333-4444-555555555555"

// ehloRelay answers EHLO, enough for the health check of an endpoint with
// tls: none. The driver allows that only towards localhost.
func ehloRelay(t *testing.T) int32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = c.Write([]byte("220 relay ESMTP\r\n"))
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if strings.HasPrefix(strings.ToUpper(line), "QUIT") {
						_, _ = c.Write([]byte("221 bye\r\n"))
						return
					}
					_, _ = c.Write([]byte("250 relay\r\n"))
				}
			}(c)
		}
	}()
	return int32(ln.Addr().(*net.TCPAddr).Port)
}

type xoauth2Fixture struct {
	client client.Client
	server *oauthtest.Server
	broker *TokenBroker
	rec    *MailBackendReconciler
}

func newXOAUTH2Fixture(t *testing.T, seed string) *xoauth2Fixture {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := sigv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	mb := &sigv1.MailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "outlook", Namespace: "team", UID: "uid-1", Generation: 1},
		Spec: sigv1.BackendSpec{Type: sigv1.BackendSMTP, SMTP: &sigv1.SMTPBackendSpec{
			Endpoints:      []sigv1.SMTPEndpoint{{Host: "127.0.0.1", Port: ehloRelay(t), TLS: sigv1.SMTPTLSNone}},
			AuthType:       sigv1.SMTPAuthXOAUTH2,
			CredentialsRef: &sigv1.SecretReference{Name: "outlook-signin"},
			OAuth:          &sigv1.SMTPOAuthSpec{Provider: sigv1.OAuthProviderMicrosoft, ClientID: testClientID, Mailbox: "me@outlook.com"},
		}},
	}
	signin := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "outlook-signin", Namespace: "team"}, Data: map[string][]byte{}}
	if seed != "" {
		signin.Data[sigv1.OAuthSecretRefreshTokenKey] = []byte(seed)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mb, signin).WithStatusSubresource(mb).Build()
	s := oauthtest.New(t, testClientID, "")
	s.SetRefreshToken("seed", true)
	b := &TokenBroker{Reader: c, Writer: c, Guard: &GuardChecker{checked: true}, HTTPClient: s.Client(),
		TokenURL: func(tenant string) (string, error) {
			if tenant != "consumers" {
				t.Errorf("tenant %q, want the default consumers", tenant)
			}
			return s.TokenURL(), nil
		}}
	t.Cleanup(func() { backendAuthorized.DeleteLabelValues("team/outlook") })
	return &xoauth2Fixture{client: c, server: s, broker: b, rec: &MailBackendReconciler{Client: c, Broker: b}}
}

func (f *xoauth2Fixture) reconcile(t *testing.T) *sigv1.MailBackend {
	t.Helper()
	key := types.NamespacedName{Namespace: "team", Name: "outlook"}
	if _, err := f.rec.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	var mb sigv1.MailBackend
	if err := f.client.Get(context.Background(), key, &mb); err != nil {
		t.Fatal(err)
	}
	return &mb
}

func wantCondition(t *testing.T, mb *sigv1.MailBackend, typ string, status metav1.ConditionStatus, reason string) {
	t.Helper()
	c := meta.FindStatusCondition(mb.Status.Conditions, typ)
	if c == nil || c.Status != status || c.Reason != reason {
		t.Fatalf("condition %s: want %s/%s, got %+v", typ, status, reason, c)
	}
}

func TestReconcile_XOAUTH2Authorized(t *testing.T) {
	f := newXOAUTH2Fixture(t, "seed")
	ctx := context.Background()

	// The send path reads the token Secret, which does not exist yet.
	mb := &sigv1.MailBackend{}
	if err := f.client.Get(ctx, types.NamespacedName{Namespace: "team", Name: "outlook"}, mb); err != nil {
		t.Fatal(err)
	}
	cfg, err := ResolveBackendConfig(ctx, f.client, "team/outlook", &mb.Spec, "team")
	if err != nil || cfg.SMTP.Username != "me@outlook.com" || cfg.SMTP.Password != "" {
		t.Fatalf("resolve: %v %+v", err, cfg.SMTP)
	}
	if _, err := cfg.SMTP.Tokens.Token(ctx); err == nil || !strings.Contains(err.Error(), "has not stored an access token yet") {
		t.Fatalf("want a missing token Secret, got %v", err)
	}

	mb = f.reconcile(t)
	wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionTrue, sigv1.ReasonAuthorized)
	wantCondition(t, mb, sigv1.ConditionReady, metav1.ConditionTrue, sigv1.ReasonAtLeastOneEndpointReady)
	if got := f.server.LastForm().Get("scope"); got != "https://outlook.office.com/SMTP.Send offline_access" {
		t.Fatalf("scope %q", got)
	}

	// Now the send path finds the broker's token.
	tok, err := cfg.SMTP.Tokens.Token(ctx)
	if err != nil || tok.AccessToken != "token-1" {
		t.Fatalf("token from the Secret: %v %v", tok, err)
	}

	// A second reconcile within the token's half life redeems nothing.
	mb = f.reconcile(t)
	if n := f.server.Requests(); n != 1 {
		t.Fatalf("%d token requests, want 1", n)
	}

	// Switching to PLAIN drops the condition and the broker's state.
	mb.Spec.SMTP.AuthType, mb.Spec.SMTP.OAuth = sigv1.SMTPAuthPlain, nil
	if err := f.client.Update(ctx, mb); err != nil {
		t.Fatal(err)
	}
	mb = f.reconcile(t)
	if meta.FindStatusCondition(mb.Status.Conditions, sigv1.ConditionAuthorized) != nil || len(f.broker.state) != 0 {
		t.Fatalf("Authorized must go with XOAUTH2: %+v, state %d", mb.Status.Conditions, len(f.broker.state))
	}
}

func TestReconcile_XOAUTH2NotReadyWithoutToken(t *testing.T) {
	t.Run("no sign-in yet", func(t *testing.T) {
		f := newXOAUTH2Fixture(t, "")
		mb := f.reconcile(t)
		wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionFalse, sigv1.ReasonAuthorizationRequired)
		wantCondition(t, mb, sigv1.ConditionReady, metav1.ConditionFalse, sigv1.ReasonAuthorizationRequired)
	})
	t.Run("revoked sign-in", func(t *testing.T) {
		f := newXOAUTH2Fixture(t, "revoked")
		mb := f.reconcile(t)
		wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionFalse, sigv1.ReasonAuthorizationRequired)
		wantCondition(t, mb, sigv1.ConditionReady, metav1.ConditionFalse, sigv1.ReasonAuthorizationRequired)
		if c := meta.FindStatusCondition(mb.Status.Conditions, sigv1.ConditionReady); !strings.Contains(c.Message, "invalid_grant") {
			t.Fatalf("the message should name the provider's answer: %q", c.Message)
		}
	})
	t.Run("no guard", func(t *testing.T) {
		f := newXOAUTH2Fixture(t, "seed")
		f.broker.Guard = nil
		mb := f.reconcile(t)
		wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionFalse, sigv1.ReasonGuardMissing)
		wantCondition(t, mb, sigv1.ConditionReady, metav1.ConditionFalse, sigv1.ReasonGuardMissing)
		if f.server.Requests() != 0 {
			t.Fatal("no refresh token may be redeemed while the result cannot be stored")
		}
	})
	t.Run("no broker", func(t *testing.T) {
		f := newXOAUTH2Fixture(t, "seed")
		f.rec.Broker = nil
		mb := f.reconcile(t)
		wantCondition(t, mb, sigv1.ConditionReady, metav1.ConditionFalse, sigv1.ReasonInvalidConfiguration)
	})
}

func TestReconcile_XOAUTH2DeletedBackendIsForgotten(t *testing.T) {
	f := newXOAUTH2Fixture(t, "seed")
	mb := f.reconcile(t)
	if len(f.broker.state) != 1 {
		t.Fatalf("state %d, want 1", len(f.broker.state))
	}
	if err := f.client.Delete(context.Background(), mb); err != nil {
		t.Fatal(err)
	}
	if _, err := f.rec.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "team", Name: "outlook"}}); err != nil {
		t.Fatal(err)
	}
	if len(f.broker.state) != 0 {
		t.Fatal("a deleted backend's state must be dropped")
	}
}

func TestBackendKindName(t *testing.T) {
	for key, want := range map[string][2]string{
		"team/outlook": {"MailBackend", "outlook"},
		"/outlook":     {"ClusterMailBackend", "outlook"},
	} {
		if k, n := backendKindName(key); k != want[0] || n != want[1] {
			t.Errorf("backendKindName(%q) = %s, %s", key, k, n)
		}
	}
	// The resolver and the broker agree on the token Secret's name.
	if TokenSecretName("ClusterMailBackend", "outlook") != "sigillum-oauth-cmb-outlook" {
		t.Fatal("unexpected token Secret name")
	}
}

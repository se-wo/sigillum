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
	offset time.Duration // the broker's clock runs ahead by this
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
	objs := []client.Object{mb}
	// Without a seed there is no credentials Secret at all: the device
	// code sign-in needs none.
	if seed != "" {
		objs = append(objs, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "outlook-signin", Namespace: "team"},
			Data: map[string][]byte{sigv1.OAuthSecretRefreshTokenKey: []byte(seed)}})
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithStatusSubresource(mb).Build()
	s := oauthtest.New(t, testClientID, "")
	s.SetRefreshToken("seed", true)
	f := &xoauth2Fixture{client: c, server: s}
	f.broker = f.newBroker(t)
	f.rec = &MailBackendReconciler{Client: c, Broker: f.broker}
	t.Cleanup(func() { backendAuthorized.DeleteLabelValues("team/outlook") })
	return f
}

// newBroker is a broker as after a controller restart.
func (f *xoauth2Fixture) newBroker(t *testing.T) *TokenBroker {
	return &TokenBroker{Reader: f.client, Writer: f.client, Guard: &GuardChecker{checked: true}, HTTPClient: f.server.Client(),
		Now: func() time.Time { return time.Now().Add(f.offset) },
		Endpoints: func(tenant string) (string, string, error) {
			if tenant != "consumers" {
				t.Errorf("tenant %q, want the default consumers", tenant)
			}
			return f.server.TokenURL(), f.server.DeviceURL(), nil
		}}
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
	// Without a usable refresh token the controller starts a device code
	// sign-in (TestReconcile_XOAUTH2DeviceSignIn).
	for name, seed := range map[string]string{"no sign-in yet": "", "revoked sign-in": "revoked"} {
		t.Run(name, func(t *testing.T) {
			f := newXOAUTH2Fixture(t, seed)
			mb := f.reconcile(t)
			wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionFalse, sigv1.ReasonAuthorizationPending)
			wantCondition(t, mb, sigv1.ConditionReady, metav1.ConditionFalse, sigv1.ReasonAuthorizationPending)
		})
	}
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

func (f *xoauth2Fixture) annotate(t *testing.T, value string) {
	t.Helper()
	var mb sigv1.MailBackend
	if err := f.client.Get(context.Background(), types.NamespacedName{Namespace: "team", Name: "outlook"}, &mb); err != nil {
		t.Fatal(err)
	}
	mb.Annotations = map[string]string{sigv1.AuthorizeAnnotation: value}
	if err := f.client.Update(context.Background(), &mb); err != nil {
		t.Fatal(err)
	}
}

func authorizedMessage(mb *sigv1.MailBackend) string {
	return meta.FindStatusCondition(mb.Status.Conditions, sigv1.ConditionAuthorized).Message
}

func TestReconcile_XOAUTH2DeviceSignIn(t *testing.T) {
	f := newXOAUTH2Fixture(t, "")

	mb := f.reconcile(t)
	wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionFalse, sigv1.ReasonAuthorizationPending)
	if m := authorizedMessage(mb); !strings.Contains(m, "https://login.example.test/link") || !strings.Contains(m, "CODE-1") ||
		!strings.Contains(m, "me@outlook.com") {
		t.Fatalf("the message must tell the person where to go, with which code and account: %q", m)
	}
	// Within the poll interval nothing is asked.
	f.reconcile(t)
	if n := f.server.Requests(); n != 0 {
		t.Fatalf("polled %d times before the interval", n)
	}
	f.offset += 6 * time.Second
	mb = f.reconcile(t)
	wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionFalse, sigv1.ReasonAuthorizationPending)
	if f.server.Requests() != 1 || f.server.DeviceStarts() != 1 {
		t.Fatalf("want one poll and one start, got %d and %d", f.server.Requests(), f.server.DeviceStarts())
	}

	f.server.SetDevice(oauthtest.DeviceApproved, "Me@Outlook.com")
	f.offset += 6 * time.Second
	mb = f.reconcile(t)
	wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionTrue, sigv1.ReasonAuthorized)
	wantCondition(t, mb, sigv1.ConditionReady, metav1.ConditionTrue, sigv1.ReasonAtLeastOneEndpointReady)
	if scope := f.server.LastForm(); scope.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
		t.Fatalf("last request %v", scope)
	}
	var sec corev1.Secret
	if err := f.client.Get(context.Background(), types.NamespacedName{Namespace: "team", Name: "sigillum-oauth-mb-outlook"}, &sec); err != nil {
		t.Fatal(err)
	}
	if rt := string(sec.Data[sigv1.OAuthSecretRefreshTokenKey]); !strings.HasPrefix(rt, "refresh-device-") {
		t.Fatalf("the sign-in's refresh token must be stored, got %q", rt)
	}

	// After a restart the stored sign-in is used; no new code.
	f.broker = f.newBroker(t)
	f.rec.Broker = f.broker
	mb = f.reconcile(t)
	wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionTrue, sigv1.ReasonAuthorized)
	if f.server.DeviceStarts() != 1 {
		t.Fatal("a restart must not start another sign-in")
	}
}

func TestReconcile_XOAUTH2DeviceSignInWrongAccountOrExpired(t *testing.T) {
	f := newXOAUTH2Fixture(t, "")
	f.reconcile(t)
	f.server.SetDevice(oauthtest.DeviceApproved, "someone-else@outlook.com")
	f.offset += 6 * time.Second
	mb := f.reconcile(t)
	wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionFalse, sigv1.ReasonAuthorizationExpired)
	if m := authorizedMessage(mb); !strings.Contains(m, "someone-else@outlook.com") || !strings.Contains(m, sigv1.AuthorizeAnnotation) {
		t.Fatalf("the message must name the account and the way out: %q", m)
	}
	var sec corev1.Secret
	if err := f.client.Get(context.Background(), types.NamespacedName{Namespace: "team", Name: "sigillum-oauth-mb-outlook"}, &sec); err == nil {
		t.Fatal("another account's sign-in must not be stored")
	}

	// It stays expired, without new codes, until the annotation changes.
	f.offset += time.Hour
	f.reconcile(t)
	if f.server.DeviceStarts() != 1 {
		t.Fatal("no new code without a new request")
	}
	f.annotate(t, "1")
	mb = f.reconcile(t)
	wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionFalse, sigv1.ReasonAuthorizationPending)
	if f.server.DeviceStarts() != 2 || !strings.Contains(authorizedMessage(mb), "CODE-2") {
		t.Fatalf("a new annotation value must start a new sign-in: %q", authorizedMessage(mb))
	}

	// Nobody signs in within the code's lifetime.
	f.offset += 16 * time.Minute
	mb = f.reconcile(t)
	wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionFalse, sigv1.ReasonAuthorizationExpired)
	if !strings.Contains(authorizedMessage(mb), "expired") {
		t.Fatalf("message %q", authorizedMessage(mb))
	}
}

// A new sign-in asked for while the backend works keeps it sending until
// the new one is done.
func TestReconcile_XOAUTH2ReSignInKeepsSending(t *testing.T) {
	f := newXOAUTH2Fixture(t, "seed")
	f.reconcile(t)
	f.annotate(t, "switch-account")
	mb := f.reconcile(t)
	wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionTrue, sigv1.ReasonAuthorizationPending)
	wantCondition(t, mb, sigv1.ConditionReady, metav1.ConditionTrue, sigv1.ReasonAtLeastOneEndpointReady)

	f.server.SetDevice(oauthtest.DeviceApproved, "me@outlook.com")
	f.offset += 6 * time.Second
	mb = f.reconcile(t)
	wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionTrue, sigv1.ReasonAuthorized)
	var sec corev1.Secret
	if err := f.client.Get(context.Background(), types.NamespacedName{Namespace: "team", Name: "sigillum-oauth-mb-outlook"}, &sec); err != nil {
		t.Fatal(err)
	}
	if rt := string(sec.Data[sigv1.OAuthSecretRefreshTokenKey]); !strings.HasPrefix(rt, "refresh-device-") {
		t.Fatalf("the new sign-in must replace the old chain, got %q", rt)
	}
}

// A new sign-in that fails while the old one works leaves the old one in
// use, refreshed as before, and the failure visible.
func TestReconcile_XOAUTH2FailedReSignInKeepsTheOldOne(t *testing.T) {
	f := newXOAUTH2Fixture(t, "seed")
	f.reconcile(t)
	f.annotate(t, "switch-account")
	f.reconcile(t)
	f.server.SetDevice(oauthtest.DeviceApproved, "someone-else@outlook.com")
	f.offset += 6 * time.Second
	mb := f.reconcile(t)
	wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionTrue, sigv1.ReasonAuthorizationExpired)
	wantCondition(t, mb, sigv1.ConditionReady, metav1.ConditionTrue, sigv1.ReasonAtLeastOneEndpointReady)

	// Past the old token's half life it is refreshed, and the notice stays.
	before := f.server.Requests()
	f.offset += 40 * time.Minute
	mb = f.reconcile(t)
	if f.server.Requests() != before+1 || f.server.LastForm().Get("grant_type") != "refresh_token" {
		t.Fatalf("the old sign-in must be refreshed: %d requests, last %v", f.server.Requests()-before, f.server.LastForm())
	}
	wantCondition(t, mb, sigv1.ConditionAuthorized, metav1.ConditionTrue, sigv1.ReasonAuthorizationExpired)
	if !strings.Contains(authorizedMessage(mb), "someone-else@outlook.com") {
		t.Fatalf("message %q", authorizedMessage(mb))
	}
	if f.server.DeviceStarts() != 1 {
		t.Fatal("no new code without a new request")
	}
}

// An app-only XOAUTH2 backend (flow clientCredentials) gets its tokens
// from the application's secret: no broker, no sign-in, no token Secret.
func TestReconcile_XOAUTH2AppOnly(t *testing.T) {
	s := oauthtest.New(t, testClientID, "app-secret")
	old := appOnlyEnv
	appOnlyEnv.tokenURL = func(tenant string) (string, error) {
		if tenant != "contoso.onmicrosoft.com" {
			t.Errorf("tenant %q", tenant)
		}
		return s.TokenURL(), nil
	}
	appOnlyEnv.httpClient = s.Client()
	t.Cleanup(func() { appOnlyEnv = old })

	for _, tc := range []struct {
		name, secret string
		wantReady    metav1.ConditionStatus
		wantReason   string
	}{
		{"valid secret", "app-secret", metav1.ConditionTrue, sigv1.ReasonAtLeastOneEndpointReady},
		{"wrong secret", "wrong", metav1.ConditionFalse, sigv1.ReasonAllEndpointsDown},
		{"no secret", "", metav1.ConditionFalse, sigv1.ReasonInvalidConfiguration},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newXOAUTH2Fixture(t, "")
			ctx := context.Background()
			var mb sigv1.MailBackend
			if err := f.client.Get(ctx, types.NamespacedName{Namespace: "team", Name: "outlook"}, &mb); err != nil {
				t.Fatal(err)
			}
			mb.Spec.SMTP.OAuth.Flow, mb.Spec.SMTP.OAuth.Tenant, mb.Spec.SMTP.OAuth.Mailbox =
				sigv1.OAuthFlowClientCredentials, "contoso.onmicrosoft.com", "noreply@contoso.com"
			if err := f.client.Update(ctx, &mb); err != nil {
				t.Fatal(err)
			}
			if err := f.client.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "outlook-signin", Namespace: "team"},
				Data: map[string][]byte{sigv1.GraphSecretClientSecretKey: []byte(tc.secret)}}); err != nil {
				t.Fatal(err)
			}
			got := f.reconcile(t)
			wantCondition(t, got, sigv1.ConditionReady, tc.wantReady, tc.wantReason)
			if meta.FindStatusCondition(got.Status.Conditions, sigv1.ConditionAuthorized) != nil || f.server.DeviceStarts() != 0 {
				t.Fatal("an app-only backend has no sign-in")
			}
			if tc.secret == "app-secret" {
				if form := s.LastForm(); form.Get("grant_type") != "client_credentials" || form.Get("scope") != MicrosoftSMTPAppScope {
					t.Fatalf("token request %v", form)
				}
				// The send path gets the same application token.
				cfg, err := ResolveBackendConfig(ctx, f.client, "team/outlook", &got.Spec, "team")
				if err != nil || cfg.SMTP.Username != "noreply@contoso.com" {
					t.Fatalf("resolve: %v %+v", err, cfg.SMTP)
				}
				if tok, err := cfg.SMTP.Tokens.Token(ctx); err != nil || tok.AccessToken == "" {
					t.Fatalf("token: %v %v", tok, err)
				}
			}
		})
	}
}

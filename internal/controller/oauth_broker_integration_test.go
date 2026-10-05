//go:build envtest

package controller

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/credential"
	"github.com/se-wo/sigillum/internal/oauth"
	"github.com/se-wo/sigillum/internal/oauth/oauthtest"
)

// The Secrets the broker writes pass the real guard, as the controller's
// ServiceAccount, for both backend kinds; a foreign Secret of the same
// name is a conflict.
func TestIntegration_TokenBrokerWritesThroughGuard(t *testing.T) {
	ctx := context.Background()
	cc := controllerClient(t)
	ensureNamespace(t, testReleaseNamespace)
	guard := credential.Guard{Name: "sigillum-credential-guard", ControllerUsername: testControllerUsername, Exclusions: testExclusions}
	installGuard(t, guard, cc)
	checker := NewGuardChecker(guard, testClient, cc, time.Minute, logr.Discard())
	checker.Check(ctx)

	ns := "broker-it"
	ensureNamespace(t, ns)
	smtp := &sigv1.SMTPBackendSpec{Endpoints: []sigv1.SMTPEndpoint{{Host: "mx", Port: 587, TLS: sigv1.SMTPTLSStartTLS}}, AuthType: sigv1.SMTPAuthNone}
	mb := &sigv1.MailBackend{ObjectMeta: metav1.ObjectMeta{Name: "outlook", Namespace: ns},
		Spec: sigv1.BackendSpec{Type: sigv1.BackendSMTP, SMTP: smtp}}
	cmb := &sigv1.ClusterMailBackend{ObjectMeta: metav1.ObjectMeta{Name: "broker-it"},
		Spec: sigv1.BackendSpec{Type: sigv1.BackendSMTP, SMTP: smtp}}
	other := &sigv1.MailBackend{ObjectMeta: metav1.ObjectMeta{Name: "taken", Namespace: ns},
		Spec: sigv1.BackendSpec{Type: sigv1.BackendSMTP, SMTP: smtp}}
	for _, o := range []client.Object{mb, cmb, other} {
		if err := testClient.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: TokenSecretName("MailBackend", "taken"), Namespace: ns}}
	if err := testClient.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}

	broker := &TokenBroker{Reader: testClient, Writer: cc, Guard: checker}
	for _, tc := range []struct {
		owner     client.Object
		kind, ns  string
		want      string
		readsBack bool
	}{
		{mb, "MailBackend", ns, sigv1.ReasonAuthorized, true},
		{cmb, "ClusterMailBackend", testReleaseNamespace, sigv1.ReasonAuthorized, true},
		{other, "MailBackend", ns, sigv1.ReasonSecretConflict, false},
	} {
		s := oauthtest.New(t, "client", "")
		s.SetRefreshToken("seed", true)
		d := DelegatedBackend{Owner: tc.owner, Kind: tc.kind, Key: tc.ns + "/" + tc.owner.GetName(), Namespace: tc.ns, Seed: "seed",
			Refresher: &oauth.RefreshToken{TokenURL: s.TokenURL(), ClientID: "client", HTTPClient: s.Client()}}
		t.Cleanup(func() { backendAuthorized.DeleteLabelValues(d.Key) })
		if res := broker.Ensure(ctx, d); res.Reason != tc.want {
			t.Fatalf("%s %s: want %s, got %+v", tc.kind, tc.owner.GetName(), tc.want, res)
		}
		if !tc.readsBack {
			continue
		}
		var sec corev1.Secret
		if err := testClient.Get(ctx, types.NamespacedName{Namespace: tc.ns, Name: TokenSecretName(tc.kind, tc.owner.GetName())}, &sec); err != nil {
			t.Fatal(err)
		}
		if tok, err := AccessTokenFromSecret(&sec); err != nil || tok.AccessToken != "token-1" {
			t.Fatalf("%s: access token %v %v", tc.kind, tok, err)
		}
		// The second write is a patch of the existing Secret.
		broker.Now = func() time.Time { return time.Now().Add(31 * time.Minute) }
		if res := broker.Ensure(ctx, d); res.Reason != sigv1.ReasonAuthorized {
			t.Fatalf("%s: refresh: %+v", tc.kind, res)
		}
		broker.Now = nil
	}
}

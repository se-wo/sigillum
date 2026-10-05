package controller

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/oauth"
	"github.com/se-wo/sigillum/internal/oauth/oauthtest"
)

// failingWriter fails the next n writes.
type failingWriter struct {
	client.Writer
	mu sync.Mutex
	n  int
}

func (w *failingWriter) fail() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.n > 0 {
		w.n--
		return errors.New("etcd unavailable")
	}
	return nil
}

func (w *failingWriter) Create(ctx context.Context, o client.Object, opts ...client.CreateOption) error {
	if err := w.fail(); err != nil {
		return err
	}
	return w.Writer.Create(ctx, o, opts...)
}

type brokerFixture struct {
	broker *TokenBroker
	client client.Client
	writer *failingWriter
	server *oauthtest.Server
	offset time.Duration
	d      DelegatedBackend
}

func newBrokerFixture(t *testing.T) *brokerFixture {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := oauthtest.New(t, "client", "")
	s.SetRefreshToken("seed", true)
	f := &brokerFixture{client: c, writer: &failingWriter{Writer: c}, server: s}
	f.broker = f.newBroker()
	mb := &sigv1.MailBackend{ObjectMeta: metav1.ObjectMeta{Name: "outlook", Namespace: "team", UID: "uid-1"}}
	f.d = DelegatedBackend{Owner: mb, Kind: "MailBackend", Key: "team/outlook", Namespace: "team", Seed: "seed",
		Refresher: &oauth.RefreshToken{TokenURL: s.TokenURL(), ClientID: "client", HTTPClient: s.Client()}}
	t.Cleanup(func() { backendAuthorized.DeleteLabelValues(f.d.Key) })
	return f
}

// newBroker is a broker as after a controller restart: same cluster, no
// memory. The token endpoint uses the real clock; the broker's runs ahead
// by offset.
func (f *brokerFixture) newBroker() *TokenBroker {
	return &TokenBroker{Reader: f.client, Writer: f.writer, Guard: &GuardChecker{checked: true},
		Now: func() time.Time { return time.Now().Add(f.offset) }}
}

func (f *brokerFixture) ensure(t *testing.T, want string) BrokerResult {
	t.Helper()
	res := f.broker.Ensure(context.Background(), f.d)
	if res.Reason != want {
		t.Fatalf("want reason %s, got %+v", want, res)
	}
	return res
}

func (f *brokerFixture) secret(t *testing.T) *corev1.Secret {
	t.Helper()
	var sec corev1.Secret
	key := types.NamespacedName{Namespace: "team", Name: "sigillum-oauth-mb-outlook"}
	if err := f.client.Get(context.Background(), key, &sec); err != nil {
		t.Fatal(err)
	}
	return &sec
}

// authorizedMetric reads sigillum_backend_authorized for the backend as
// scraped, or -1 if it is not exported.
func (f *brokerFixture) authorizedMetric() float64 {
	mfs, _ := ctrlmetrics.Registry.Gather()
	for _, mf := range mfs {
		if mf.GetName() != "sigillum_backend_authorized" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "backend" && l.GetValue() == f.d.Key {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	return -1
}

func TestTokenBroker_RefreshesStoresAndRotates(t *testing.T) {
	f := newBrokerFixture(t)
	res := f.ensure(t, sigv1.ReasonAuthorized)
	if !res.Authorized || res.RequeueAfter < 29*time.Minute || res.RequeueAfter > 31*time.Minute {
		t.Fatalf("want authorized and a refresh at half the hour, got %+v", res)
	}
	sec := f.secret(t)
	if sec.Labels[sigv1.OAuthTokenLabel] != "outlook" || sec.Annotations[sigv1.OAuthTokenUIDAnnotation] != "uid-1" ||
		sec.Annotations[sigv1.OAuthSeedAnnotation] != seedHash("seed") || sec.Type != corev1.SecretTypeOpaque {
		t.Fatalf("unexpected metadata %+v", sec.ObjectMeta)
	}
	if o := sec.OwnerReferences; len(o) != 1 || o[0].Kind != "MailBackend" || o[0].UID != "uid-1" || o[0].Controller == nil || !*o[0].Controller {
		t.Fatalf("the backend must control the Secret: %+v", o)
	}
	if string(sec.Data[sigv1.OAuthSecretRefreshTokenKey]) != "refresh-1" || len(sec.Data) != 3 {
		t.Fatalf("the rotated refresh token must be stored: %v", sec.Data)
	}
	if tok, err := AccessTokenFromSecret(sec); err != nil || tok.AccessToken != "token-1" || time.Until(tok.Expiry) < 59*time.Minute {
		t.Fatalf("access token: %v %v", tok, err)
	}
	if f.authorizedMetric() != 1 {
		t.Fatal("sigillum_backend_authorized must be 1")
	}

	f.ensure(t, sigv1.ReasonAuthorized)
	if f.server.Requests() != 1 {
		t.Fatal("no refresh before half the token's lifetime")
	}
	f.offset = 31 * time.Minute
	f.ensure(t, sigv1.ReasonAuthorized)
	if f.server.Requests() != 2 || f.server.LastForm().Get("refresh_token") != "refresh-1" {
		t.Fatal("the refresh must use the rotated token")
	}
	if got := string(f.secret(t).Data[sigv1.OAuthSecretRefreshTokenKey]); got != "refresh-2" {
		t.Fatalf("stored refresh token %q, want refresh-2", got)
	}
}

func TestTokenBroker_ResumesFromSecretAfterRestart(t *testing.T) {
	f := newBrokerFixture(t)
	f.ensure(t, sigv1.ReasonAuthorized)

	f.broker = f.newBroker()
	f.ensure(t, sigv1.ReasonAuthorized)
	if f.server.Requests() != 1 {
		t.Fatal("a restarted broker must reuse the stored access token until it is due")
	}
	// The seed was rotated away; only the stored token still works.
	f.broker = f.newBroker()
	f.offset = 31 * time.Minute
	f.ensure(t, sigv1.ReasonAuthorized)
	if f.server.LastForm().Get("refresh_token") != "refresh-1" {
		t.Fatal("a restarted broker must continue with the stored refresh token, not the seed")
	}
}

func TestTokenBroker_NewSignInReplacesTheChain(t *testing.T) {
	f := newBrokerFixture(t)
	f.ensure(t, sigv1.ReasonAuthorized)
	f.server.SetRefreshToken("seed-2", true)
	f.d.Seed = "seed-2"
	f.ensure(t, sigv1.ReasonAuthorized)
	if f.server.LastForm().Get("refresh_token") != "seed-2" {
		t.Fatal("a new sign-in in the credentials Secret must be used at once")
	}
	if f.secret(t).Annotations[sigv1.OAuthSeedAnnotation] != seedHash("seed-2") {
		t.Fatal("the Secret must record the new sign-in")
	}
}

func TestTokenBroker_RevokedAsksForSignIn(t *testing.T) {
	f := newBrokerFixture(t)
	f.server.SetRefreshToken("someone-else", true)
	res := f.ensure(t, sigv1.ReasonAuthorizationRequired)
	if res.Authorized || !strings.Contains(res.Message, "invalid_grant") || f.authorizedMetric() != 0 {
		t.Fatalf("a revoked token needs a new sign-in: %+v metric=%v", res, f.authorizedMetric())
	}
}

func TestTokenBroker_NoRefreshToken(t *testing.T) {
	f := newBrokerFixture(t)
	f.d.Seed = ""
	if res := f.ensure(t, sigv1.ReasonAuthorizationRequired); res.Authorized || f.server.Requests() != 0 {
		t.Fatalf("nothing to redeem without a sign-in: %+v", res)
	}
}

func TestTokenBroker_NoRefreshWithoutGuard(t *testing.T) {
	f := newBrokerFixture(t)
	f.broker.Guard = &GuardChecker{checked: true, err: errors.New("missing")}
	f.ensure(t, sigv1.ReasonGuardMissing)
	if f.server.Requests() != 0 {
		t.Fatal("a refresh token must not be redeemed while the result cannot be stored")
	}
}

func TestTokenBroker_TemporaryFailure(t *testing.T) {
	f := newBrokerFixture(t)
	f.server.Fail(503, nil, `{"error":"temporarily_unavailable"}`)
	if res := f.ensure(t, sigv1.ReasonTokenRefreshFailed); !res.Authorized || res.RequeueAfter != brokerRetry {
		t.Fatalf("a temporary failure is retried and does not ask for a sign-in: %+v", res)
	}
	f.server.Recover()
	f.ensure(t, sigv1.ReasonAuthorized)
}

// A rotated refresh token that could not be stored must not be lost: the
// next Ensure stores it without redeeming it again.
func TestTokenBroker_KeepsRotatedTokenWhenTheWriteFails(t *testing.T) {
	f := newBrokerFixture(t)
	f.writer.n = 1
	if res := f.ensure(t, sigv1.ReasonSecretWriteFailed); !res.Authorized {
		t.Fatalf("got %+v", res)
	}
	f.ensure(t, sigv1.ReasonAuthorized)
	if f.server.Requests() != 1 || string(f.secret(t).Data[sigv1.OAuthSecretRefreshTokenKey]) != "refresh-1" {
		t.Fatal("the rotated token from the first refresh must be stored, without a second refresh")
	}
}

func TestTokenSecretName(t *testing.T) {
	if TokenSecretName("MailBackend", "x") == TokenSecretName("ClusterMailBackend", "x") {
		t.Fatal("a MailBackend and a ClusterMailBackend of one name must not share a Secret")
	}
	long := strings.Repeat("a", 240) + "." + strings.Repeat("b", 12)
	for _, kind := range []string{"MailBackend", "ClusterMailBackend"} {
		n := TokenSecretName(kind, long)
		if errs := validation.IsDNS1123Subdomain(n); len(errs) > 0 {
			t.Errorf("%s: %q: %v", kind, n, errs)
		}
	}
	if TokenSecretName("MailBackend", long) == TokenSecretName("MailBackend", long+"c") {
		t.Fatal("long names must stay distinct")
	}
}

func TestAccessTokenFromSecret(t *testing.T) {
	if _, err := AccessTokenFromSecret(&corev1.Secret{}); err == nil {
		t.Fatal("an empty Secret has no access token")
	}
}

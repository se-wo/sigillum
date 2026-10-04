package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/audit"
	"github.com/se-wo/sigillum/internal/driver"
	"github.com/se-wo/sigillum/internal/policy"
	"github.com/se-wo/sigillum/internal/policy/ratelimit"
)

type recordingAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingAudit) Record(e audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recordingAudit) last(t *testing.T) audit.Event {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) != 1 {
		t.Fatalf("want exactly 1 audit event, got %d: %+v", len(r.events), r.events)
	}
	return r.events[0]
}

type fakeDriver struct {
	err  error
	sent []*driver.Message
}

func (f *fakeDriver) Type() driver.Type                                   { return driver.TypeSMTP }
func (f *fakeDriver) Capabilities() []driver.Capability                   { return nil }
func (f *fakeDriver) HealthCheck(context.Context) []driver.EndpointHealth { return nil }
func (f *fakeDriver) Close() error                                        { return nil }
func (f *fakeDriver) Send(_ context.Context, m *driver.Message) (*driver.SendResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.sent = append(f.sent, m)
	return &driver.SendResult{UpstreamID: "up-1", AcceptedAt: time.Unix(1, 0)}, nil
}

type denyLimiter struct{}

func (denyLimiter) Refund(context.Context, string) error { return nil }

// countingLimiter admits everything and counts hits minus refunds.
type countingLimiter struct {
	hits   int
	limits ratelimit.Limits
}

func (c *countingLimiter) Allow(_ context.Context, _ string, limits ratelimit.Limits) (bool, time.Duration, error) {
	c.hits++
	c.limits = limits
	return true, 0, nil
}

func (c *countingLimiter) Refund(context.Context, string) error {
	c.hits--
	return nil
}

func (denyLimiter) Allow(context.Context, string, ratelimit.Limits) (bool, time.Duration, error) {
	return false, 42 * time.Second, nil
}

type brokenLimiter struct{}

func (brokenLimiter) Refund(context.Context, string) error { return nil }

func (brokenLimiter) Allow(context.Context, string, ratelimit.Limits) (bool, time.Duration, error) {
	return false, 0, ratelimit.ErrUnavailable
}

func readyBackend(name string, ready bool) *sigv1.ClusterMailBackend {
	status := metav1.ConditionTrue
	if !ready {
		status = metav1.ConditionFalse
	}
	return &sigv1.ClusterMailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: sigv1.BackendSpec{Type: sigv1.BackendSMTP, SMTP: &sigv1.SMTPBackendSpec{
			Endpoints: []sigv1.SMTPEndpoint{{Host: "relay", Port: 25}},
			AuthType:  sigv1.SMTPAuthNone,
		}},
		Status: sigv1.BackendStatus{Conditions: []metav1.Condition{{
			Type: sigv1.ConditionReady, Status: status, Reason: "Test", LastTransitionTime: metav1.Now(),
		}}},
	}
}

func testPolicy() *sigv1.MailPolicy {
	return &sigv1.MailPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "team"},
		Spec: sigv1.MailPolicySpec{
			Subjects:           []sigv1.PolicySubject{{ServiceAccount: &sigv1.ServiceAccountSubject{Name: "mailer"}}},
			BackendRef:         sigv1.BackendRef{Name: "relay", Kind: sigv1.KindClusterMailBackend},
			SenderRestrictions: &sigv1.SenderRestrictions{AllowedSenders: []string{"*@team.example"}},
			RateLimits:         &sigv1.RateLimitsSpec{MessagesPerMinute: 10},
		},
	}
}

func newGateway(t *testing.T, d *fakeDriver, objs ...client.Object) (*Gateway, *recordingAudit) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := sigv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&sigv1.ClusterMailBackend{}).Build()
	rec := &recordingAudit{}
	return &Gateway{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Audit:     rec,
		Policies:  CachedPolicyStore{C: c},
		Reader:    c,
		Limiter:   ratelimit.NewMemoryLimiter(),
		NewDriver: func(driver.Config) (driver.Driver, error) { return d, nil },
	}, rec
}

func request(from string) Request {
	return Request{
		Identity:  Identity{Namespace: "team", ServiceAccount: "mailer", AuthMethod: AuthOAuthBearer},
		Transport: TransportREST,
		MessageID: "m-1",
		Message: &driver.Message{
			From: driver.Address{Address: from},
			To:   []driver.Address{{Address: "a@x.example"}},
			Bcc:  []driver.Address{{Address: "b@x.example"}},
		},
		SizeBytes: 10,
	}
}

func TestSend_Accepted(t *testing.T) {
	d := &fakeDriver{}
	g, rec := newGateway(t, d, testPolicy(), readyBackend("relay", true))
	res := g.Send(context.Background(), request("app@team.example"))
	if res.Status != StatusAccepted || res.Policy != "p" || res.Backend != "/relay" {
		t.Fatalf("unexpected result %+v", res)
	}
	if len(d.sent) != 1 {
		t.Fatalf("driver not called")
	}
	ev := rec.last(t)
	if ev.Decision != audit.DecisionAccept || ev.Policy != "p" || ev.Backend != "/relay" ||
		ev.Namespace != "team" || ev.ServiceAccount != "mailer" || ev.From != "app@team.example" {
		t.Fatalf("unexpected audit event %+v", ev)
	}
	if len(ev.To) != 2 {
		t.Fatalf("audit must list all recipients incl. bcc, got %v", ev.To)
	}
}

func TestSend_Denied(t *testing.T) {
	d := &fakeDriver{}
	g, rec := newGateway(t, d, testPolicy(), readyBackend("relay", true))
	res := g.Send(context.Background(), request("spoof@evil.example"))
	if res.Status != StatusDenied || res.DenyReason != policy.DenySenderNotAllowed {
		t.Fatalf("unexpected result %+v", res)
	}
	if len(d.sent) != 0 {
		t.Fatal("driver must not be called on deny")
	}
	if ev := rec.last(t); ev.Decision != audit.DecisionReject || ev.Reason != "sender_not_allowed" || ev.Policy != "p" {
		t.Fatalf("unexpected audit event %+v", ev)
	}
}

func TestSend_NoPolicy(t *testing.T) {
	g, rec := newGateway(t, &fakeDriver{})
	res := g.Send(context.Background(), request("app@team.example"))
	if res.Status != StatusDenied || res.DenyReason != policy.DenyNoPolicy {
		t.Fatalf("unexpected result %+v", res)
	}
	if ev := rec.last(t); ev.Reason != "no_policy_matched" {
		t.Fatalf("unexpected audit event %+v", ev)
	}
}

func TestSend_RateLimited(t *testing.T) {
	g, rec := newGateway(t, &fakeDriver{}, testPolicy(), readyBackend("relay", true))
	g.Limiter = denyLimiter{}
	res := g.Send(context.Background(), request("app@team.example"))
	if res.Status != StatusRateLimited || res.RetryAfter != 42*time.Second {
		t.Fatalf("unexpected result %+v", res)
	}
	if ev := rec.last(t); ev.Reason != "rate_limited" {
		t.Fatalf("unexpected audit event %+v", ev)
	}
}

func TestSend_BackendNotReady(t *testing.T) {
	g, rec := newGateway(t, &fakeDriver{}, testPolicy(), readyBackend("relay", false))
	if res := g.Send(context.Background(), request("app@team.example")); res.Status != StatusBackendNotReady {
		t.Fatalf("unexpected result %+v", res)
	}
	if ev := rec.last(t); ev.Reason != "backend_not_ready" {
		t.Fatalf("unexpected audit event %+v", ev)
	}
}

func TestSend_UpstreamError(t *testing.T) {
	g, rec := newGateway(t, &fakeDriver{err: errors.New("boom")}, testPolicy(), readyBackend("relay", true))
	if res := g.Send(context.Background(), request("app@team.example")); res.Status != StatusUpstreamError {
		t.Fatalf("unexpected result %+v", res)
	}
	if ev := rec.last(t); ev.Reason != "upstream_error" || ev.Backend != "/relay" {
		t.Fatalf("unexpected audit event %+v", ev)
	}
}

func TestSend_ServiceAccountSelectorResolvesLabels(t *testing.T) {
	p := testPolicy()
	p.Spec.Subjects = []sigv1.PolicySubject{{ServiceAccountSelector: &sigv1.LabelSelectorSubject{
		MatchLabels: map[string]string{"mail": "yes"},
	}}}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name: "mailer", Namespace: "team", Labels: map[string]string{"mail": "yes"},
	}}
	g, _ := newGateway(t, &fakeDriver{}, p, sa, readyBackend("relay", true))
	if res := g.Send(context.Background(), request("app@team.example")); res.Status != StatusAccepted {
		t.Fatalf("selector subject should match via SA labels, got %+v", res)
	}
}

func TestSend_LimiterUnavailable(t *testing.T) {
	d := &fakeDriver{}
	g, rec := newGateway(t, d, testPolicy(), readyBackend("relay", true))
	g.Limiter = brokenLimiter{}
	if res := g.Send(context.Background(), request("app@team.example")); res.Status != StatusUnavailable {
		t.Fatalf("unexpected result %+v", res)
	}
	if len(d.sent) != 0 {
		t.Fatal("must not send when the limiter is down (fail closed)")
	}
	if ev := rec.last(t); ev.Reason != "ratelimit_unavailable" {
		t.Fatalf("unexpected audit event %+v", ev)
	}
}

func TestSend_SpanHierarchy(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	g, _ := newGateway(t, &fakeDriver{}, testPolicy(), readyBackend("relay", true))
	ctx, root := tp.Tracer("test").Start(context.Background(), "http.request")
	if res := g.Send(ctx, request("app@team.example")); res.Status != StatusAccepted {
		t.Fatalf("unexpected result %+v", res)
	}
	root.End()

	parents := map[string]string{}
	ids := map[string]string{}
	for _, s := range exp.GetSpans() {
		ids[s.SpanContext.SpanID().String()] = s.Name
	}
	for _, s := range exp.GetSpans() {
		parents[s.Name] = ids[s.Parent.SpanID().String()]
	}
	for child, parent := range map[string]string{
		"policy.evaluate": "http.request",
		"ratelimit.allow": "http.request",
		"backend.send":    "http.request",
	} {
		if parents[child] != parent {
			t.Errorf("%s: parent %q, want %q (all: %v)", child, parents[child], parent, parents)
		}
	}
}

func TestSend_TransientFailureRefundsRateLimit(t *testing.T) {
	transient := &fakeDriver{err: fmt.Errorf("%w: relay down", driver.ErrUpstreamTransient)}
	g, _ := newGateway(t, transient, testPolicy(), readyBackend("relay", true))
	lim := &countingLimiter{}
	g.Limiter = lim
	if res := g.Send(context.Background(), request("app@team.example")); res.Status != StatusUpstreamError || res.Permanent {
		t.Fatalf("unexpected result %+v", res)
	}
	if lim.hits != 0 {
		t.Fatalf("transient failure must refund the hit, %d left", lim.hits)
	}

	permanent := &fakeDriver{err: fmt.Errorf("%w: 550 no such user", driver.ErrUpstreamPermanent)}
	g2, rec := newGateway(t, permanent, testPolicy(), readyBackend("relay", true))
	g2.Limiter = lim
	if res := g2.Send(context.Background(), request("app@team.example")); !res.Permanent {
		t.Fatalf("unexpected result %+v", res)
	}
	if ev := rec.last(t); ev.Reason != "upstream_rejected" {
		t.Fatalf("permanent rejection must be audited as upstream_rejected, got %q", ev.Reason)
	}
	if lim.hits != 1 {
		t.Fatalf("permanent rejection stays charged, want 1 hit, got %d", lim.hits)
	}
}

func TestSend_DailyLimitAloneIsCharged(t *testing.T) {
	p := testPolicy()
	p.Spec.RateLimits = &sigv1.RateLimitsSpec{MessagesPerDay: 500}
	g, _ := newGateway(t, &fakeDriver{}, p, readyBackend("relay", true))
	lim := &countingLimiter{}
	g.Limiter = lim
	if res := g.Send(context.Background(), request("app@team.example")); res.Status != StatusAccepted {
		t.Fatalf("unexpected result %+v", res)
	}
	if lim.hits != 1 || lim.limits != (ratelimit.Limits{PerDay: 500}) {
		t.Fatalf("a policy with only a daily limit must be charged against it, hits=%d limits=%+v", lim.hits, lim.limits)
	}
}

func TestSend_BackendNotReadyDoesNotChargeRateLimit(t *testing.T) {
	g, _ := newGateway(t, &fakeDriver{}, testPolicy(), readyBackend("relay", false))
	lim := &countingLimiter{}
	g.Limiter = lim
	if res := g.Send(context.Background(), request("app@team.example")); res.Status != StatusBackendNotReady {
		t.Fatalf("unexpected result %+v", res)
	}
	if lim.hits != 0 {
		t.Fatalf("an unavailable backend must not use up the budget, got %d hits", lim.hits)
	}
}

func TestSend_SALookupFailureFailsClosed(t *testing.T) {
	p := testPolicy()
	p.Spec.Subjects = []sigv1.PolicySubject{{ServiceAccountSelector: &sigv1.LabelSelectorSubject{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "tier", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"untrusted"},
		}},
	}}}
	// No ServiceAccount object exists, so the lookup fails.
	g, _ := newGateway(t, &fakeDriver{}, p, readyBackend("relay", true))
	if res := g.Send(context.Background(), request("app@team.example")); res.Status != StatusDenied {
		t.Fatalf("negative selector must not match when the SA lookup fails, got %+v", res)
	}
}

func TestSend_CredentialIdentityIsAudited(t *testing.T) {
	g, rec := newGateway(t, &fakeDriver{}, testPolicy(), readyBackend("relay", true))
	req := request("app@team.example")
	req.Transport = TransportSMTP
	req.Identity.AuthMethod = AuthSMTPCredential
	req.Identity.Credential = "grafana.team"
	req.Identity.CredentialPrevious = true
	if res := g.Send(context.Background(), req); res.Status != StatusAccepted {
		t.Fatalf("unexpected result %+v", res)
	}
	ev := rec.last(t)
	if ev.AuthMethod != AuthSMTPCredential || ev.Credential != "grafana.team" || !ev.CredentialPrevious {
		t.Fatalf("credential identity missing from audit record: %+v", ev)
	}
}

package controller

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

func readyConditionOf(t *testing.T, conds []metav1.Condition) metav1.Condition {
	t.Helper()
	for _, c := range conds {
		if c.Type == sigv1.ConditionReady {
			return c
		}
	}
	t.Fatalf("no Ready condition in %+v", conds)
	return metav1.Condition{}
}

// #41: without the webhook, a policy the webhook would reject must not look
// Ready (the gateway refuses it).
func TestMailPolicyReconcilerReportsInvalidPolicy(t *testing.T) {
	cmb := &sigv1.ClusterMailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "relay"},
		Spec: sigv1.BackendSpec{Type: sigv1.BackendSMTP, SMTP: &sigv1.SMTPBackendSpec{
			Endpoints: []sigv1.SMTPEndpoint{{Host: "relay", Port: 25}}, AuthType: sigv1.SMTPAuthNone,
		}},
		Status: sigv1.BackendStatus{Conditions: []metav1.Condition{{
			Type: sigv1.ConditionReady, Status: metav1.ConditionTrue, Reason: sigv1.ReasonReady, LastTransitionTime: metav1.Now(),
		}}},
	}
	mp := &sigv1.MailPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "pol", Namespace: "team"},
		Spec: sigv1.MailPolicySpec{
			Subjects:   []sigv1.PolicySubject{{ServiceAccount: &sigv1.ServiceAccountSubject{Name: "sa"}}},
			BackendRef: sigv1.BackendRef{Name: "relay", Kind: sigv1.KindClusterMailBackend},
			RecipientRestrictions: &sigv1.RecipientRestrictions{
				AllowedDomains:    []string{"*.example.com"},
				AllowedRecipients: []string{"*"},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cmb, mp).
		WithStatusSubresource(&sigv1.MailPolicy{}).Build()
	r := &MailPolicyReconciler{Client: c, Scheme: scheme}
	key := types.NamespacedName{Namespace: "team", Name: "pol"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	var got sigv1.MailPolicy
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatal(err)
	}
	ready := readyConditionOf(t, got.Status.Conditions)
	if ready.Status != metav1.ConditionFalse || ready.Reason != sigv1.ReasonInvalidConfiguration ||
		!strings.Contains(ready.Message, "allowedDomains[0]") || !strings.Contains(ready.Message, "allowedRecipients[0]") {
		t.Fatalf("want Ready=False InvalidConfiguration naming both fields, got %+v", ready)
	}
}

// #41: an invalid backend is never Ready and is not probed.
func TestBackendReconcilersReportInvalidBackend(t *testing.T) {
	spec := sigv1.BackendSpec{Type: sigv1.BackendSMTP, SMTP: &sigv1.SMTPBackendSpec{
		Endpoints: []sigv1.SMTPEndpoint{{Host: "relay", Port: 25, InsecureSkipVerify: true}},
		AuthType:  sigv1.SMTPAuthNone,
	}}
	// Results of a probe from before the spec turned invalid.
	now := metav1.Now()
	stale := sigv1.BackendStatus{
		EndpointStatus: []sigv1.EndpointStatus{{Host: "relay", Port: 25, Ready: true}},
		LastProbeTime:  &now,
	}
	cmb := &sigv1.ClusterMailBackend{ObjectMeta: metav1.ObjectMeta{Name: "relay"}, Spec: spec, Status: *stale.DeepCopy()}
	mb := &sigv1.MailBackend{ObjectMeta: metav1.ObjectMeta{Name: "relay", Namespace: "team"}, Spec: spec, Status: *stale.DeepCopy()}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cmb, mb).
		WithStatusSubresource(&sigv1.ClusterMailBackend{}, &sigv1.MailBackend{}).Build()
	ctx := context.Background()

	for _, tc := range []struct {
		key types.NamespacedName
		rec interface {
			Reconcile(context.Context, ctrl.Request) (ctrl.Result, error)
		}
		object client.Object
		status func() *sigv1.BackendStatus
	}{
		{types.NamespacedName{Name: "relay"}, &ClusterMailBackendReconciler{Client: c, Scheme: scheme},
			cmb, func() *sigv1.BackendStatus { return &cmb.Status }},
		{types.NamespacedName{Namespace: "team", Name: "relay"}, &MailBackendReconciler{Client: c, Scheme: scheme},
			mb, func() *sigv1.BackendStatus { return &mb.Status }},
	} {
		res, err := tc.rec.Reconcile(ctx, ctrl.Request{NamespacedName: tc.key})
		if err != nil {
			t.Fatal(err)
		}
		if res.RequeueAfter != 0 {
			t.Fatalf("%T: only a spec change can fix an invalid backend; want no requeue, got %v", tc.object, res.RequeueAfter)
		}
		if err := c.Get(ctx, tc.key, tc.object); err != nil {
			t.Fatal(err)
		}
		st := tc.status()
		ready := readyConditionOf(t, st.Conditions)
		if ready.Status != metav1.ConditionFalse || ready.Reason != sigv1.ReasonInvalidConfiguration ||
			!strings.Contains(ready.Message, "insecureSkipVerify") {
			t.Fatalf("%T: want Ready=False InvalidConfiguration, got %+v", tc.object, ready)
		}
		if st.LastProbeTime != nil || st.EndpointStatus != nil {
			t.Fatalf("%T: an invalid backend must not show probe results, got %+v", tc.object, st)
		}
	}
}

// A validation error that echoes hundreds of entries must not exceed the
// API's limit on condition messages.
func TestErrorReadyConditionTruncatesMessage(t *testing.T) {
	msg := strings.Repeat("é", 20000) // 40000 bytes
	got := errorReadyCondition(1, sigv1.ReasonInvalidConfiguration, msg).Message
	if len(got) > maxConditionMessage+32 || !strings.HasSuffix(got, "(truncated)") || !utf8.ValidString(got) {
		t.Fatalf("want a valid UTF-8 message of about %d bytes, got %d bytes", maxConditionMessage, len(got))
	}
	if short := errorReadyCondition(1, sigv1.ReasonInvalidConfiguration, "short").Message; short != "short" {
		t.Fatalf("short message changed to %q", short)
	}
}

package webhook

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

func TestSenderNeverAllowed(t *testing.T) {
	backend := []string{"*@example.com", "ops@other.test"}
	for _, tc := range []struct {
		entry string
		never bool
	}{
		{"app@example.com", false},
		{"APP@Example.COM", false},
		{"app@other.test", true},
		{"ops@other.test", false},
		{"*@example.com", false},
		{"noreply-*@example.com", false}, // same domain: assumed to overlap
		{"*@other.test", false},          // matches ops@other.test
		{"o?s@other.test", false},
		{"*@third.test", true},
		{"*@sub.example.com", true},
		{"*", false},            // not anchored on a domain: cannot tell
		{"*example.com", false}, // ditto
	} {
		if got := senderNeverAllowed(tc.entry, backend); got != tc.never {
			t.Errorf("senderNeverAllowed(%q) = %v, want %v", tc.entry, got, tc.never)
		}
	}
	if !senderNeverAllowed("app@example.com", []string{}) {
		t.Error("an empty backend list allows nothing")
	}
}

// #49: a policy entry its backend never allows draws a warning naming it.
func TestMailPolicyValidator_WarnsAboutSendersTheBackendRefuses(t *testing.T) {
	s := runtime.NewScheme()
	if err := sigv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	cmb := &sigv1.ClusterMailBackend{ObjectMeta: metav1.ObjectMeta{Name: "b"},
		Spec: sigv1.BackendSpec{AllowedSenders: []string{"*@example.com"}}}
	mb := &sigv1.MailBackend{ObjectMeta: metav1.ObjectMeta{Name: "own", Namespace: "ns"},
		Spec: sigv1.BackendSpec{AllowedSenders: []string{"*@example.com"}}}
	open := &sigv1.ClusterMailBackend{ObjectMeta: metav1.ObjectMeta{Name: "open"}}
	v := &MailPolicyValidator{Reader: fake.NewClientBuilder().WithScheme(s).WithObjects(cmb, mb, open).Build()}

	for _, tc := range []struct {
		name string
		ref  sigv1.BackendRef
		want string // "" = no warning
	}{
		{"cluster backend", sigv1.BackendRef{Name: "b", Kind: sigv1.KindClusterMailBackend}, `ClusterMailBackend b allows none of ["app@other.test"]`},
		{"namespaced backend", sigv1.BackendRef{Name: "own", Kind: sigv1.KindMailBackend}, `MailBackend own allows none of ["app@other.test"]`},
		{"backend without allowedSenders", sigv1.BackendRef{Name: "open", Kind: sigv1.KindClusterMailBackend}, ""},
		{"missing backend", sigv1.BackendRef{Name: "gone", Kind: sigv1.KindClusterMailBackend}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mp := validPolicy()
			mp.Spec.BackendRef = tc.ref
			mp.Spec.SenderRestrictions = &sigv1.SenderRestrictions{AllowedSenders: []string{"app@other.test", "app@example.com"}}
			warnings, err := v.ValidateCreate(context.Background(), mp)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(warnings, "\n")
			if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
				t.Fatalf("want warning %q, got %q", tc.want, got)
			}
		})
	}
}

// #82: messagesPerDay with the in-memory store is per pod and reset by
// restarts; the webhook says so when it knows the store.
func TestMailPolicyValidator_WarnsAboutDailyCapInMemory(t *testing.T) {
	for _, tc := range []struct {
		store  string
		perDay int32
		warn   bool
	}{
		{"memory", 100, true},
		{"memory", 0, false},
		{"redis", 100, false},
		{"", 100, false},
	} {
		mp := validPolicy()
		mp.Spec.RateLimits = &sigv1.RateLimitsSpec{MessagesPerMinute: 10, MessagesPerDay: tc.perDay}
		warnings, err := (&MailPolicyValidator{RateLimitBackend: tc.store}).ValidateCreate(context.Background(), mp)
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Contains(strings.Join(warnings, "\n"), "messagesPerDay")
		if got != tc.warn {
			t.Errorf("store %q, messagesPerDay %d: warning %v, want %v (%q)", tc.store, tc.perDay, got, tc.warn, warnings)
		}
	}
}

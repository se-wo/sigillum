//go:build envtest

package controller

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	_ "github.com/se-wo/sigillum/internal/driver/smtp"
)

// startFakeSMTPListener returns a listener that never completes an SMTP
// handshake — enough for TCP reachability to prove the probe dials out, but
// the endpoint will fail the EHLO step and be marked not-ready. That is
// sufficient to exercise the probe + status-write loop.
func startFakeSMTPListener(t *testing.T) (host string, port int32, closer func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Speak just enough of RFC 5321 so probe treats us as ready.
				c.SetDeadline(time.Now().Add(5 * time.Second))
				c.Write([]byte("220 fake.test ESMTP\r\n"))
				buf := make([]byte, 1024)
				for {
					select {
					case <-stop:
						return
					default:
					}
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					line := string(buf[:n])
					switch {
					case len(line) >= 4 && (line[:4] == "EHLO" || line[:4] == "HELO"):
						c.Write([]byte("250 fake.test\r\n"))
					case len(line) >= 4 && line[:4] == "QUIT":
						c.Write([]byte("221 bye\r\n"))
						return
					default:
						c.Write([]byte("250 OK\r\n"))
					}
				}
			}(conn)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, int32(pn), func() { close(stop); ln.Close() }
}

func TestIntegration_MailBackendReconcileSetsReady(t *testing.T) {
	host, port, closer := startFakeSMTPListener(t)
	defer closer()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sigillum-itest-1"}}
	if err := testClient.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}

	mb := &sigv1.MailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "smtp", Namespace: ns.Name},
		Spec: sigv1.BackendSpec{
			Type: sigv1.BackendSMTP,
			SMTP: &sigv1.SMTPBackendSpec{
				Endpoints: []sigv1.SMTPEndpoint{{Host: host, Port: port, TLS: sigv1.SMTPTLSNone}},
				AuthType:  sigv1.SMTPAuthNone,
			},
		},
	}
	if err := testClient.Create(context.Background(), mb); err != nil {
		t.Fatalf("create mailbackend: %v", err)
	}

	// Drive the reconciler in-process against envtest — no need to run a manager.
	r := &MailBackendReconciler{Client: testClient, Scheme: testScheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: mb.Name, Namespace: mb.Namespace}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got sigv1.MailBackend
	if err := testClient.Get(context.Background(), types.NamespacedName{Name: mb.Name, Namespace: mb.Namespace}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.ObservedGeneration != got.Generation {
		t.Fatalf("observedGeneration %d != generation %d", got.Status.ObservedGeneration, got.Generation)
	}
	var ready *metav1.Condition
	for i := range got.Status.Conditions {
		if got.Status.Conditions[i].Type == sigv1.ConditionReady {
			ready = &got.Status.Conditions[i]
		}
	}
	if ready == nil {
		t.Fatalf("Ready condition missing: %+v", got.Status.Conditions)
	}
	if ready.Status != metav1.ConditionTrue {
		t.Fatalf("Ready=%s reason=%s message=%s", ready.Status, ready.Reason, ready.Message)
	}
	if len(got.Status.EndpointStatus) != 1 || !got.Status.EndpointStatus[0].Ready {
		t.Fatalf("want 1 ready endpoint, got %+v", got.Status.EndpointStatus)
	}
}

func TestIntegration_MailPolicyReadyWhenBackendReady(t *testing.T) {
	// Seed a ClusterMailBackend whose Ready condition is True so the
	// policy reconciler accepts it as a valid backendRef.
	cmbName := "cmb-itest-" + randSuffix()
	cmb := &sigv1.ClusterMailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: cmbName},
		Spec: sigv1.BackendSpec{
			Type: sigv1.BackendSMTP,
			SMTP: &sigv1.SMTPBackendSpec{
				Endpoints: []sigv1.SMTPEndpoint{{Host: "127.0.0.1", Port: 2525, TLS: sigv1.SMTPTLSNone}},
				AuthType:  sigv1.SMTPAuthNone,
			},
		},
	}
	if err := testClient.Create(context.Background(), cmb); err != nil {
		t.Fatalf("create cmb: %v", err)
	}
	cmb.Status.Conditions = []metav1.Condition{{
		Type:               sigv1.ConditionReady,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             sigv1.ReasonReady,
		Message:            "forced ready for test",
	}}
	if err := testClient.Status().Update(context.Background(), cmb); err != nil {
		t.Fatalf("update cmb status: %v", err)
	}

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sigillum-itest-policy"}}
	_ = testClient.Create(context.Background(), ns)

	mp := &sigv1.MailPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "pol", Namespace: ns.Name},
		Spec: sigv1.MailPolicySpec{
			Priority:   10,
			Subjects:   []sigv1.PolicySubject{{ServiceAccount: &sigv1.ServiceAccountSubject{Name: "sa"}}},
			BackendRef: sigv1.BackendRef{Name: cmbName, Kind: sigv1.KindClusterMailBackend},
			SenderRestrictions: &sigv1.SenderRestrictions{
				AllowedSenders: []string{"*@example.com"},
			},
		},
	}
	if err := testClient.Create(context.Background(), mp); err != nil {
		t.Fatalf("create mp: %v", err)
	}

	pr := &MailPolicyReconciler{Client: testClient, Scheme: testScheme}
	if _, err := pr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: mp.Name, Namespace: mp.Namespace}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got sigv1.MailPolicy
	if err := testClient.Get(context.Background(), types.NamespacedName{Name: mp.Name, Namespace: mp.Namespace}, &got); err != nil {
		t.Fatal(err)
	}
	var ready *metav1.Condition
	for i := range got.Status.Conditions {
		if got.Status.Conditions[i].Type == sigv1.ConditionReady {
			ready = &got.Status.Conditions[i]
		}
	}
	if ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready=True, got %+v", got.Status.Conditions)
	}
}

func randSuffix() string {
	return fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000)
}

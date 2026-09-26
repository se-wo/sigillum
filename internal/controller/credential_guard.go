package controller

import (
	"context"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/credential"
)

var credentialGuardOK = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "sigillum_credential_guard_ok",
	Help: "1 if the credential Secret guard (ValidatingAdmissionPolicy and binding) is in place and unchanged, " +
		"0 if the controller refuses to write generated credential Secrets.",
})

func init() {
	ctrlmetrics.Registry.MustRegister(credentialGuardOK)
}

// GuardChecker periodically verifies the credential Secret guard (SPEC
// §4.10). While the guard is missing or changed the MailCredential
// reconciler writes no Secrets. When the verdict changes, every
// MailCredential is requeued so its Ready condition follows.
type GuardChecker struct {
	Guard    credential.Guard
	Reader   client.Reader // uncached: the controller may only get the guard by name
	Lister   client.Reader
	Interval time.Duration
	Log      logr.Logger

	mu      sync.Mutex
	checked bool
	err     error
	events  chan event.GenericEvent
}

// NewGuardChecker returns a checker; call Check once before the manager
// starts so reconcilers never act on an unknown verdict.
func NewGuardChecker(g credential.Guard, reader, lister client.Reader, interval time.Duration, log logr.Logger) *GuardChecker {
	return &GuardChecker{Guard: g, Reader: reader, Lister: lister, Interval: interval, Log: log,
		events: make(chan event.GenericEvent, 1024)}
}

// OK reports whether the guard was verified, and the reason if not.
func (g *GuardChecker) OK() (bool, string) {
	if g == nil {
		return false, "credential Secret guard is not being checked"
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case !g.checked:
		return false, "credential Secret guard not verified yet"
	case g.err != nil:
		return false, "credential Secret guard missing or changed, refusing to write Secrets: " + g.err.Error()
	}
	return true, ""
}

// Events feeds requeues into the MailCredential controller.
func (g *GuardChecker) Events() <-chan event.GenericEvent { return g.events }

// Check verifies the guard now and reports whether the verdict changed.
func (g *GuardChecker) Check(ctx context.Context) bool {
	err := g.Guard.Verify(ctx, g.Reader)
	g.mu.Lock()
	changed := !g.checked || (g.err == nil) != (err == nil)
	g.checked, g.err = true, err
	g.mu.Unlock()
	if err != nil {
		credentialGuardOK.Set(0)
		if changed {
			g.Log.Error(err, "credential Secret guard missing or changed; generated MailCredentials will not be written",
				"guard", g.Guard.Name)
		}
	} else {
		credentialGuardOK.Set(1)
		if changed {
			g.Log.Info("credential Secret guard verified", "guard", g.Guard.Name)
		}
	}
	return changed
}

// retryInterval re-checks a missing guard sooner than Interval: Helm
// creates the policy after the Deployments (an unknown kind to Helm), so
// the controller may start before it exists.
const retryInterval = 30 * time.Second

// Start implements manager.Runnable.
func (g *GuardChecker) Start(ctx context.Context) error {
	for {
		wait := g.Interval
		if ok, _ := g.OK(); !ok && retryInterval < wait {
			wait = retryInterval
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
			if g.Check(ctx) {
				g.requeueAll(ctx)
			}
		}
	}
}

// NeedLeaderElection implements manager.LeaderElectionRunnable: every
// replica keeps its verdict current so a new leader starts with one.
func (g *GuardChecker) NeedLeaderElection() bool { return false }

func (g *GuardChecker) requeueAll(ctx context.Context) {
	var list sigv1.MailCredentialList
	if err := g.Lister.List(ctx, &list); err != nil {
		g.Log.Error(err, "list MailCredentials after guard change")
		return
	}
	for i := range list.Items {
		if !list.Items[i].Generated() {
			continue
		}
		// Non-blocking: on a replica that is not the leader nobody consumes
		// the channel. Dropped events are caught by the reconciler's
		// periodic requeue of credentials waiting for the guard.
		select {
		case g.events <- event.GenericEvent{Object: &list.Items[i]}:
		default:
		}
	}
}

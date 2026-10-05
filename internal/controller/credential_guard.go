package controller

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
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
// reconciler writes no Secrets. When the verdict changes, the leader
// requeues every generated MailCredential (Requeuer) so its conditions
// follow.
type GuardChecker struct {
	Guard    credential.Guard
	Reader   client.Reader // uncached: the controller may only get the guard by name
	Lister   client.Reader
	Interval time.Duration
	Log      logr.Logger

	mu      sync.Mutex
	checked bool
	err     error
	// changed signals a verdict change (buffer 1: changes coalesce).
	changed chan struct{}
	events  chan event.GenericEvent
}

// NewGuardChecker returns a checker; call Check once before the manager
// starts so reconcilers never act on an unknown verdict.
func NewGuardChecker(g credential.Guard, reader, lister client.Reader, interval time.Duration, log logr.Logger) *GuardChecker {
	return &GuardChecker{Guard: g, Reader: reader, Lister: lister, Interval: interval, Log: log,
		changed: make(chan struct{}, 1), events: make(chan event.GenericEvent)}
}

// OK reports whether the guard was verified, and the reason if not.
func (g *GuardChecker) OK() (bool, string) {
	if g == nil {
		return false, "credential Secret guard is not installed (chart value credentials.enabled is false)"
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

// Check verifies the guard now and reports whether the verdict changed. A
// lookup that fails for another reason than a missing, forbidden or
// changed guard (a timeout, an API server restart) keeps the last verdict,
// so one failed GET does not flip every credential's condition.
func (g *GuardChecker) Check(ctx context.Context) bool {
	err := g.Guard.Verify(ctx, g.Reader)
	g.mu.Lock()
	if err != nil && g.checked && !definitive(err) {
		g.mu.Unlock()
		g.Log.Info("could not verify the credential Secret guard; keeping the last verdict",
			"guard", g.Guard.Name, "err", err.Error())
		return false
	}
	// A new reason counts as a change too (missing, then tampered), so
	// the conditions and the error log name the current problem.
	changed := !g.checked || (g.err == nil) != (err == nil) ||
		(err != nil && g.err != nil && err.Error() != g.err.Error())
	g.checked, g.err = true, err
	g.mu.Unlock()
	if changed && g.changed != nil {
		g.signal()
	}
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

// definitive reports whether err says the guard is missing or changed, as
// opposed to a lookup that could not be completed.
func definitive(err error) bool {
	return errors.Is(err, credential.ErrGuardChanged) || apierrors.IsNotFound(err) || apierrors.IsForbidden(err)
}

// retryInterval re-checks a missing guard sooner than Interval: Helm
// creates the policy after the Deployments (an unknown kind to Helm), so
// the controller may start before it exists.
const retryInterval = 30 * time.Second

// Start implements manager.Runnable.
func (g *GuardChecker) Start(ctx context.Context) error {
	for {
		wait := g.Interval
		if ok, _ := g.OK(); (!ok && retryInterval < wait) || wait <= 0 {
			wait = retryInterval
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
			g.Check(ctx)
		}
	}
}

// NeedLeaderElection implements manager.LeaderElectionRunnable: every
// replica keeps its verdict current so a new leader starts with one.
func (g *GuardChecker) NeedLeaderElection() bool { return false }

// Requeuer returns the leader-only runnable that requeues every generated
// MailCredential after a verdict change. It runs where the controller (the
// consumer of Events) runs, so it can send without dropping events.
func (g *GuardChecker) Requeuer() manager.Runnable { return guardRequeuer{g} }

type guardRequeuer struct{ g *GuardChecker }

func (r guardRequeuer) NeedLeaderElection() bool { return true }

func (r guardRequeuer) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.g.changed:
			if err := r.g.requeueAll(ctx); err != nil {
				r.g.Log.Error(err, "list MailCredentials after guard change; retrying")
				// The signal was consumed: re-arm it after a pause, or
				// the conditions would stay stale until an unrelated event.
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(requeueRetryDelay):
				}
				r.g.signal()
			}
		}
	}
}

// requeueRetryDelay spaces retries of a failed requeue.
var requeueRetryDelay = 5 * time.Second

// signal records a pending verdict change (coalescing).
func (g *GuardChecker) signal() {
	select {
	case g.changed <- struct{}{}:
	default: // a change is already pending
	}
}

func (g *GuardChecker) requeueAll(ctx context.Context) error {
	var list sigv1.MailCredentialList
	if err := g.Lister.List(ctx, &list); err != nil {
		return err
	}
	for i := range list.Items {
		if !list.Items[i].Generated() {
			continue
		}
		select {
		case g.events <- event.GenericEvent{Object: &list.Items[i]}:
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}

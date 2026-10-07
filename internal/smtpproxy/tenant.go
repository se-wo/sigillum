package smtpproxy

import (
	"context"
	"sync"

	"github.com/se-wo/sigillum/internal/telemetry"
)

// tenantLimiter bounds how many messages one tenant (namespace) relays at
// once, so a single tenant's slow or hung relay cannot hold every global
// slot and stall the others (#73). It is acquired before the global slot,
// so a tenant waiting at its own cap holds no global slot.
//
// A per-namespace channel is created on first use and removed when idle,
// so the map holds only namespaces with messages in flight.
type tenantLimiter struct {
	cap int
	mu  sync.Mutex
	ns  map[string]*nsSlot
}

type nsSlot struct {
	ch   chan struct{}
	refs int // holders + waiters, so the entry is not removed while in use
}

func newTenantLimiter(cap int) *tenantLimiter {
	if cap <= 0 {
		return nil
	}
	return &tenantLimiter{cap: cap, ns: map[string]*nsSlot{}}
}

// acquire waits for a slot for namespace, or returns ok=false when ctx ends
// first. The returned release must be called exactly once on success.
func (t *tenantLimiter) acquire(ctx context.Context, namespace string) (release func(), ok bool) {
	if t == nil {
		return func() {}, true
	}
	t.mu.Lock()
	s := t.ns[namespace]
	if s == nil {
		s = &nsSlot{ch: make(chan struct{}, t.cap)}
		t.ns[namespace] = s
	}
	s.refs++
	t.mu.Unlock()

	done := func() {
		t.mu.Lock()
		s.refs--
		if s.refs == 0 {
			delete(t.ns, namespace)
		}
		t.mu.Unlock()
	}

	select {
	case s.ch <- struct{}{}:
		telemetry.SMTPMessagesInFlight.WithLabelValues(namespace).Inc()
		return func() {
			<-s.ch
			telemetry.SMTPMessagesInFlight.WithLabelValues(namespace).Dec()
			done()
		}, true
	case <-ctx.Done():
		done()
		return nil, false
	}
}

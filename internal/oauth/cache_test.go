package oauth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/se-wo/sigillum/internal/oauth/oauthtest"
)

// fakeSource returns scripted results and counts calls. With block set,
// each call waits until a value is sent on it.
type fakeSource struct {
	mu      sync.Mutex
	calls   int
	results []result
	block   chan struct{}
	started chan struct{}
}

type result struct {
	tok Token
	err error
}

func (f *fakeSource) Token(ctx context.Context) (Token, error) {
	f.mu.Lock()
	f.calls++
	r := f.results[0]
	if len(f.results) > 1 {
		f.results = f.results[1:]
	}
	block, started := f.block, f.started
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return Token{}, ctx.Err()
		}
	}
	return r.tok, r.err
}

func (f *fakeSource) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) set(t time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.t = t }

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func tok(name string, lifetime time.Duration) Token {
	return Token{AccessToken: name, Expiry: t0.Add(lifetime)}
}

func newCache(src Source) (*Cache, *clock) {
	clk := &clock{t: t0}
	c := NewCache(src)
	c.now = clk.now
	return c, clk
}

// waitFor polls cond; background refreshes finish asynchronously.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

func mustToken(t *testing.T, c *Cache, want string) {
	t.Helper()
	got, err := c.Token(context.Background())
	if err != nil || got.AccessToken != want {
		t.Fatalf("want %q, got %q (%v)", want, got.AccessToken, err)
	}
}

func TestCache_ReusesUntilRefreshThenRefreshesAhead(t *testing.T) {
	src := &fakeSource{results: []result{{tok: tok("a", time.Hour)}, {tok: tok("b", 2*time.Hour)}}}
	c, clk := newCache(src)
	mustToken(t, c, "a")
	clk.set(t0.Add(54 * time.Minute))
	mustToken(t, c, "a")
	if src.Calls() != 1 {
		t.Fatalf("a token is reused until 5 minutes before expiry, %d fetches", src.Calls())
	}
	// Within the refresh margin the current token is still handed out
	// while the next is fetched in the background.
	clk.set(t0.Add(56 * time.Minute))
	mustToken(t, c, "a")
	waitFor(t, func() bool { return src.Calls() == 2 })
	waitFor(t, func() bool { got, _ := c.Token(context.Background()); return got.AccessToken == "b" })
}

func TestCache_ShortLivedTokenRefreshedAtHalfLife(t *testing.T) {
	src := &fakeSource{results: []result{{tok: tok("a", 4*time.Minute)}, {tok: tok("b", time.Hour)}}}
	c, clk := newCache(src)
	mustToken(t, c, "a")
	clk.set(t0.Add(119 * time.Second))
	mustToken(t, c, "a")
	if src.Calls() != 1 {
		t.Fatal("refreshed before half its lifetime")
	}
	clk.set(t0.Add(121 * time.Second))
	mustToken(t, c, "a")
	waitFor(t, func() bool { return src.Calls() == 2 })
}

func TestCache_ConcurrentCallersShareOneFetch(t *testing.T) {
	s := oauthtest.New(t, "client", secret)
	c := NewCache(source(s))
	var wg sync.WaitGroup
	var failures atomic.Int32
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := c.Token(context.Background()); err != nil || got.AccessToken != "token-1" {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 || s.Requests() != 1 {
		t.Fatalf("%d callers failed, %d requests; want 0 and 1", failures.Load(), s.Requests())
	}
}

func TestCache_FailureIsRememberedForBackoff(t *testing.T) {
	boom := &Error{Status: 401, Code: "invalid_client", Permanent: true}
	src := &fakeSource{results: []result{{err: boom}, {tok: tok("a", time.Hour)}}}
	c, clk := newCache(src)
	for range 3 {
		if _, err := c.Token(context.Background()); !errors.Is(err, boom) {
			t.Fatalf("want the fetch error, got %v", err)
		}
	}
	if src.Calls() != 1 {
		t.Fatalf("a failure must not be retried on every call, %d fetches", src.Calls())
	}
	clk.set(t0.Add(failureBackoff))
	mustToken(t, c, "a")
}

func TestCache_RetryAfterExtendsBackoff(t *testing.T) {
	throttled := &Error{Status: 429, RetryAfter: time.Minute}
	src := &fakeSource{results: []result{{err: throttled}, {tok: tok("a", time.Hour)}}}
	c, clk := newCache(src)
	_, _ = c.Token(context.Background())
	clk.set(t0.Add(59 * time.Second))
	if _, err := c.Token(context.Background()); !errors.Is(err, throttled) || src.Calls() != 1 {
		t.Fatalf("Retry-After must be honoured: err=%v fetches=%d", err, src.Calls())
	}
	clk.set(t0.Add(time.Minute))
	mustToken(t, c, "a")
}

func TestCache_FailedRefreshKeepsValidToken(t *testing.T) {
	src := &fakeSource{results: []result{{tok: tok("a", time.Hour)}, {err: &Error{Status: 503}}}}
	c, clk := newCache(src)
	mustToken(t, c, "a")
	clk.set(t0.Add(56 * time.Minute))
	mustToken(t, c, "a")
	waitFor(t, func() bool { return src.Calls() == 2 })
	waitFor(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.failErr != nil })
	mustToken(t, c, "a")
	// Too close to expiry to hand out: the error shows.
	clk.set(t0.Add(time.Hour - minValidity))
	if _, err := c.Token(context.Background()); err == nil {
		t.Fatal("a token about to expire must not be handed out")
	}
}

func TestCache_Invalidate(t *testing.T) {
	src := &fakeSource{results: []result{{tok: tok("a", time.Hour)}, {tok: tok("b", time.Hour)}}}
	c, _ := newCache(src)
	mustToken(t, c, "a")
	c.Invalidate(Token{AccessToken: "old"})
	mustToken(t, c, "a")
	c.Invalidate(tok("a", time.Hour))
	mustToken(t, c, "b")
	if src.Calls() != 2 {
		t.Fatalf("want 2 fetches, got %d", src.Calls())
	}
}

func TestCache_CallerCancellationDoesNotAbortTheFetch(t *testing.T) {
	src := &fakeSource{results: []result{{tok: tok("a", time.Hour)}}, block: make(chan struct{}), started: make(chan struct{}, 1)}
	c, _ := newCache(src)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := c.Token(ctx); errc <- err }()
	<-src.started
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	close(src.block)
	waitFor(t, func() bool { got, _ := c.Token(context.Background()); return got.AccessToken == "a" })
	if src.Calls() != 1 {
		t.Fatalf("the fetch must finish for the next caller, %d fetches", src.Calls())
	}
}

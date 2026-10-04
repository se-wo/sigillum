package oauth

import (
	"context"
	"sync"
	"time"
)

const (
	// refreshMargin is how long before expiry a token is replaced; tokens
	// that live less than twice as long are replaced at half their life.
	refreshMargin = 5 * time.Minute
	// minValidity is how long a token must still be valid to be handed
	// out, so it does not expire during the request that uses it.
	minValidity = 30 * time.Second
	// failureBackoff is how long a failed fetch is answered from memory,
	// so a wrong secret does not hit the token endpoint on every send.
	failureBackoff = 10 * time.Second
	fetchTimeout   = 30 * time.Second
)

// Cache hands out a Source's token until shortly before it expires.
//
//   - Concurrent callers share one fetch.
//   - From refreshMargin before expiry, callers still get the current token
//     while one fetch for the next runs in the background.
//   - If that fetch fails, the current token is used as long as it is
//     valid; only then do callers see the error.
//   - A failed fetch is remembered for failureBackoff (or the endpoint's
//     Retry-After, if longer) instead of being retried on every call.
type Cache struct {
	src Source
	now func() time.Time

	mu        sync.Mutex
	tok       Token
	refreshAt time.Time
	inflight  *fetch
	failErr   error
	failUntil time.Time
}

type fetch struct {
	done chan struct{}
	tok  Token
	err  error
}

// NewCache returns a Cache in front of src.
func NewCache(src Source) *Cache {
	return &Cache{src: src, now: time.Now}
}

// Token returns a token that is valid for at least minValidity.
func (c *Cache) Token(ctx context.Context) (Token, error) {
	c.mu.Lock()
	now := c.now()
	cur, usable := c.tok, c.usable(now)
	if usable && now.Before(c.refreshAt) {
		c.mu.Unlock()
		return cur, nil
	}
	if now.Before(c.failUntil) {
		err := c.failErr
		c.mu.Unlock()
		if usable {
			return cur, nil
		}
		return Token{}, err
	}
	f := c.inflight
	if f == nil {
		f = &fetch{done: make(chan struct{})}
		c.inflight = f
		// The fetch serves every waiting caller, so the first caller's
		// cancellation must not end it; its values (trace) carry over.
		go c.run(context.WithoutCancel(ctx), f)
	}
	c.mu.Unlock()
	if usable {
		return cur, nil
	}

	select {
	case <-f.done:
	case <-ctx.Done():
		return Token{}, ctx.Err()
	}
	if f.err != nil {
		return Token{}, f.err
	}
	return f.tok, nil
}

// Invalidate drops tok, for example after the upstream rejected it with
// 401, so the next Token call fetches a new one. A token other than the
// cached one is ignored: a late rejection cannot drop a fresher token.
func (c *Cache) Invalidate(tok Token) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if tok.AccessToken != "" && tok.AccessToken == c.tok.AccessToken {
		c.tok, c.refreshAt = Token{}, time.Time{}
	}
}

func (c *Cache) usable(now time.Time) bool {
	return c.tok.AccessToken != "" && now.Add(minValidity).Before(c.tok.Expiry)
}

func (c *Cache) run(ctx context.Context, f *fetch) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	tok, err := c.src.Token(ctx)

	c.mu.Lock()
	now := c.now()
	if err == nil {
		c.tok = tok
		lifetime := tok.Expiry.Sub(now)
		c.refreshAt = tok.Expiry.Add(-min(refreshMargin, lifetime/2))
		c.failErr, c.failUntil = nil, time.Time{}
	} else {
		c.failErr = err
		c.failUntil = now.Add(max(failureBackoff, retryAfterOf(err)))
	}
	c.inflight = nil
	c.mu.Unlock()

	f.tok, f.err = tok, err
	close(f.done)
}

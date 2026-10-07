package apiserver

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/sync/semaphore"
)

// bodyWait is how long a request waits for room in the body budget before
// it is answered 503.
const bodyWait = 10 * time.Second

// bodyBudget bounds the request bodies one api-server holds at once. A
// request keeps several copies of its body while it is decoded and sent
// (raw bytes, decoded strings and attachments, the assembled MIME message),
// about four times its size, so without a bound a few concurrent large
// requests exceed the pod's memory limit and every in-flight request is
// lost. Requests reserve their Content-Length, or the whole budget when
// the length is unknown; small requests never wait for each other.
type bodyBudget struct {
	sem  *semaphore.Weighted
	size int64
}

// newBodyBudget returns nil (no bound) for size <= 0.
func newBodyBudget(size int64) *bodyBudget {
	if size <= 0 {
		return nil
	}
	return &bodyBudget{sem: semaphore.NewWeighted(size), size: size}
}

// reserve waits up to bodyWait for room for r's body. It returns the
// function that gives the room back, or false when there was none.
func (b *bodyBudget) reserve(ctx context.Context, r *http.Request) (func(), bool) {
	if b == nil {
		return func() {}, true
	}
	n := r.ContentLength
	if n < 0 || n > b.size {
		n = b.size
	}
	if n == 0 {
		return func() {}, true
	}
	ctx, cancel := context.WithTimeout(ctx, bodyWait)
	defer cancel()
	if err := b.sem.Acquire(ctx, n); err != nil {
		return nil, false
	}
	return func() { b.sem.Release(n) }, true
}

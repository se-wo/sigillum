package gateway

import (
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// maxValidityEntries bounds validityCache; entries of deleted objects are
// not evicted otherwise.
const maxValidityEntries = 4096

// validityCache remembers whether a policy or backend passes the admission
// rules, per UID and generation. The result only changes with the spec, and
// re-checking every entry of a large policy for each message is wasted work
// on the hot path.
type validityCache struct {
	mu sync.Mutex
	m  map[types.UID]validity
}

type validity struct {
	generation int64
	err        error
}

// check returns validate's result for obj, from the cache when obj's
// generation is unchanged. Objects without a UID or generation (not read
// from the API server) are always validated.
func (c *validityCache) check(obj metav1.Object, validate func() error) error {
	uid, gen := obj.GetUID(), obj.GetGeneration()
	if uid == "" || gen == 0 {
		return validate()
	}
	c.mu.Lock()
	v, ok := c.m[uid]
	c.mu.Unlock()
	if ok && v.generation == gen {
		return v.err
	}
	err := validate()
	c.mu.Lock()
	if c.m == nil || len(c.m) >= maxValidityEntries {
		c.m = make(map[types.UID]validity)
	}
	c.m[uid] = validity{generation: gen, err: err}
	c.mu.Unlock()
	return err
}

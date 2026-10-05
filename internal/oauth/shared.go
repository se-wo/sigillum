package oauth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
)

// maxCaches bounds the shared caches. Each distinct application and secret
// gets one; a rotated secret leaves the old entry behind, so the map is
// reset when it grows past any plausible number of backends.
const maxCaches = 256

var (
	cachesMu sync.Mutex
	caches   = map[string]*Cache{}
)

// SharedCache returns the token cache of src's application. The gateway
// builds a driver per send, so a cache per driver would fetch a token for
// every message; one per token endpoint, client, secret and scope keeps a
// token for its lifetime and shares it between all sends and the health
// check. The secret is part of the key so a rotated secret takes effect at
// once, hashed so it is not kept in memory twice.
func SharedCache(src *ClientCredentials) *Cache {
	h := sha256.Sum256([]byte(strings.Join([]string{src.TokenURL, src.ClientID, src.ClientSecret,
		strings.Join(src.Scopes, " ")}, "\x00")))
	key := hex.EncodeToString(h[:])
	cachesMu.Lock()
	defer cachesMu.Unlock()
	if c, ok := caches[key]; ok {
		return c
	}
	if len(caches) >= maxCaches {
		caches = map[string]*Cache{}
	}
	c := NewCache(src)
	caches[key] = c
	return c
}

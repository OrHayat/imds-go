package httputil

import (
	"sync"
	"time"
)

// TokenCache is a thread-safe cache for IMDS auth tokens.
// Providers fetch tokens themselves and use this to cache them.
type TokenCache struct {
	mu      sync.Mutex
	token   string
	expires time.Time
}

// Get returns the cached token if valid.
func (c *TokenCache) Get() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires) {
		return c.token, true
	}
	return "", false
}

// Set stores a token with the given TTL.
func (c *TokenCache) Set(token string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
	c.expires = time.Now().Add(ttl)
}

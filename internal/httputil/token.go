package httputil

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// TokenManager handles token-based IMDS authentication (AWS IMDSv2, Linode, IBM, Alibaba).
// It caches the token and lazily refreshes when expired.
type TokenManager struct {
	client   *Client
	endpoint string
	method   string
	headers  map[string]string
	ttl      time.Duration

	mu      sync.Mutex
	token   string
	expires time.Time
}

// TokenConfig configures a TokenManager.
type TokenConfig struct {
	// Endpoint is the URL to fetch the token from.
	Endpoint string
	// Method is the HTTP method (typically PUT).
	Method string
	// Headers are sent with the token request (e.g. TTL headers).
	Headers map[string]string
	// TTL is how long the token is valid.
	TTL time.Duration
}

// NewTokenManager creates a token manager with the given config.
func NewTokenManager(client *Client, cfg TokenConfig) *TokenManager {
	if cfg.Method == "" {
		cfg.Method = http.MethodPut
	}
	if cfg.TTL == 0 {
		cfg.TTL = 6 * time.Hour
	}
	return &TokenManager{
		client:   client,
		endpoint: cfg.Endpoint,
		method:   cfg.Method,
		headers:  cfg.Headers,
		ttl:      cfg.TTL,
	}
}

// Token returns a valid token, fetching a new one if expired or not yet cached.
func (tm *TokenManager) Token(ctx context.Context) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.token != "" && time.Now().Before(tm.expires) {
		return tm.token, nil
	}

	resp, err := tm.client.Do(ctx, tm.method, tm.endpoint, tm.headers)
	if err != nil {
		return "", fmt.Errorf("token fetch: %w", err)
	}
	body, err := ReadBody(resp)
	if err != nil {
		return "", fmt.Errorf("token read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token fetch: status %d", resp.StatusCode)
	}

	tm.token = string(body)
	tm.expires = time.Now().Add(tm.ttl)
	return tm.token, nil
}

package httputil

import (
	"sync"
	"testing"
	"time"
)

func TestTokenCache_GetEmpty(t *testing.T) {
	var c TokenCache
	_, ok := c.Get()
	if ok {
		t.Fatal("expected empty cache")
	}
}

func TestTokenCache_SetAndGet(t *testing.T) {
	var c TokenCache
	c.Set("tok-123", 1*time.Hour)

	tok, ok := c.Get()
	if !ok || tok != "tok-123" {
		t.Fatalf("expected tok-123, got %q (ok=%v)", tok, ok)
	}
}

func TestTokenCache_Expiry(t *testing.T) {
	var c TokenCache
	c.Set("tok", 1*time.Millisecond)

	time.Sleep(5 * time.Millisecond)

	_, ok := c.Get()
	if ok {
		t.Fatal("expected expired token")
	}
}

func TestTokenCache_Overwrite(t *testing.T) {
	var c TokenCache
	c.Set("old", 1*time.Hour)
	c.Set("new", 1*time.Hour)

	tok, ok := c.Get()
	if !ok || tok != "new" {
		t.Fatalf("expected new, got %q", tok)
	}
}

func TestTokenCache_Concurrent(t *testing.T) {
	var c TokenCache
	var wg sync.WaitGroup

	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Set("tok", 1*time.Hour)
			c.Get()
		}()
	}
	wg.Wait()
}

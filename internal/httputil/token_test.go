package httputil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenManager_CachesToken(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte("token-123"))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), 2*time.Second)
	tm := NewTokenManager(c, TokenConfig{
		Endpoint: srv.URL,
		TTL:      1 * time.Hour,
	})

	tok1, err := tm.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := tm.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if tok1 != "token-123" || tok2 != "token-123" {
		t.Fatalf("got %q, %q", tok1, tok2)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 fetch call, got %d", calls.Load())
	}
}

func TestTokenManager_RefreshesExpired(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Write([]byte(http.StatusText(200) + "-" + string(rune('0'+n))))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), 2*time.Second)
	tm := NewTokenManager(c, TokenConfig{
		Endpoint: srv.URL,
		TTL:      1 * time.Millisecond,
	})

	_, err := tm.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(5 * time.Millisecond)

	_, err = tm.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if calls.Load() != 2 {
		t.Fatalf("expected 2 fetch calls, got %d", calls.Load())
	}
}

func TestTokenManager_SendsHeaders(t *testing.T) {
	var gotMethod string
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotHeader = r.Header.Get("X-Token-TTL")
		w.Write([]byte("tok"))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), 2*time.Second)
	tm := NewTokenManager(c, TokenConfig{
		Endpoint: srv.URL,
		Method:   http.MethodPut,
		Headers:  map[string]string{"X-Token-TTL": "21600"},
		TTL:      1 * time.Hour,
	})

	_, err := tm.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("method = %q, want PUT", gotMethod)
	}
	if gotHeader != "21600" {
		t.Fatalf("header = %q, want %q", gotHeader, "21600")
	}
}

func TestTokenManager_ConcurrentAccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(10 * time.Millisecond)
		w.Write([]byte("tok"))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), 2*time.Second)
	tm := NewTokenManager(c, TokenConfig{
		Endpoint: srv.URL,
		TTL:      1 * time.Hour,
	})

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := tm.Token(context.Background())
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	// With mutex, only first goroutine fetches; rest wait and get cached token.
	// But since they all block on the lock, we might get 1-2 fetches max.
	if calls.Load() > 2 {
		t.Fatalf("expected at most 2 fetch calls, got %d", calls.Load())
	}
}

func TestTokenManager_ErrorOnFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), 2*time.Second)
	tm := NewTokenManager(c, TokenConfig{
		Endpoint: srv.URL,
		TTL:      1 * time.Hour,
	})

	_, err := tm.Token(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

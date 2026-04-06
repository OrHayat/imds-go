package httputil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newReq(t *testing.T, ctx context.Context, method, url string, headers map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestDo_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), nil)
	resp, err := c.Do(newReq(t, context.Background(), http.MethodGet, srv.URL, nil))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := ReadBody(resp)
	if string(body) != "ok" {
		t.Fatalf("got %q, want %q", body, "ok")
	}
}

func TestDo_SetsHeaders(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Test")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), nil)
	_, err := c.Do(newReq(t, context.Background(), http.MethodGet, srv.URL, map[string]string{"X-Test": "hello"}))
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Fatalf("header X-Test = %q, want %q", got, "hello")
	}
}

func TestDo_RetriesOn5xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(500)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), nil)
	resp, err := c.Do(newReq(t, context.Background(), http.MethodGet, srv.URL, nil))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := ReadBody(resp)
	if string(body) != "ok" {
		t.Fatalf("got %q, want %q", body, "ok")
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 calls, got %d", calls.Load())
	}
}

func TestDo_RetriesOn429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 2 {
			w.WriteHeader(429)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), nil)
	resp, err := c.Do(newReq(t, context.Background(), http.MethodGet, srv.URL, nil))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := ReadBody(resp)
	if string(body) != "ok" {
		t.Fatalf("got %q, want %q", body, "ok")
	}
}

func TestDo_MaxRetriesExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), nil)
	_, err := c.Do(newReq(t, context.Background(), http.MethodGet, srv.URL, nil))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDo_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	c := NewClient(srv.Client(), nil)
	_, err := c.Do(newReq(t, ctx, http.MethodGet, srv.URL, nil))
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

func TestNewClient_DoesNotMutateUserClient(t *testing.T) {
	userClient := &http.Client{Timeout: 10 * time.Second}
	_ = NewClient(userClient, nil)
	if userClient.Timeout != 10*time.Second {
		t.Fatalf("expected timeout 10s, got %v", userClient.Timeout)
	}
	if userClient.Transport != nil {
		t.Fatal("expected nil transport, got non-nil")
	}
}

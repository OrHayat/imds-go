package httputil

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	return NewHTTPClient(srv.Client().Transport, nil)
}

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

	c := testClient(t, srv)
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

	c := testClient(t, srv)
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

	c := testClient(t, srv)
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

	c := testClient(t, srv)
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

	c := testClient(t, srv)
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

	c := testClient(t, srv)
	_, err := c.Do(newReq(t, ctx, http.MethodGet, srv.URL, nil))
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

func TestDefaultHTTPClient(t *testing.T) {
	c := DefaultHTTPClient()
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.Timeout != defaultTimeout {
		t.Fatalf("expected timeout %v, got %v", defaultTimeout, c.Timeout)
	}
}

func TestDo_MaxRetriesExceeded_ErrorTypes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	c := testClient(t, srv)
	_, err := c.Do(newReq(t, context.Background(), http.MethodGet, srv.URL, nil))

	var retryErr *RetryError
	if !errors.As(err, &retryErr) {
		t.Fatalf("expected RetryError, got %T: %v", err, err)
	}
	var statusErr *StatusError
	if !errors.As(retryErr.Err, &statusErr) {
		t.Fatalf("expected StatusError inside RetryError, got %T: %v", retryErr.Err, retryErr.Err)
	}
	if statusErr.Code != 503 {
		t.Fatalf("expected status 503, got %d", statusErr.Code)
	}
}

func TestDo_RetryWithBody(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if calls.Add(1) < 2 {
			w.WriteHeader(500)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	c := testClient(t, srv)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, srv.URL, strings.NewReader("hello"))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("hello")), nil
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := ReadBody(resp)
	if string(body) != "hello" {
		t.Fatalf("expected 'hello', got %q", body)
	}
}

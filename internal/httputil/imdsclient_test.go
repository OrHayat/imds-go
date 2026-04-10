package httputil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	imds "github.com/OrHayat/imds-go"
)

const testProvider imds.ID = "test"

func newTestClient(t *testing.T, opts ...ClientOption) *Client {
	t.Helper()
	c, err := NewClient(testProvider, opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestNewClientMissingBaseURL(t *testing.T) {
	_, err := NewClient(testProvider)
	if !errors.Is(err, ErrMissingBaseURL) {
		t.Fatalf("err = %v, want ErrMissingBaseURL", err)
	}
}

func TestNewClientMissingProviderID(t *testing.T) {
	_, err := NewClient("", WithBaseURL("http://example.com"))
	if !errors.Is(err, ErrMissingProviderID) {
		t.Fatalf("err = %v, want ErrMissingProviderID", err)
	}
}

func TestNewClientWithTokenSourceEmptyHeaderName(t *testing.T) {
	src := funcTokenSource(func(ctx context.Context) (string, error) { return "tok", nil })
	_, err := NewClient(testProvider,
		WithBaseURL("http://example.com"),
		WithTokenSource("", src),
	)
	if !errors.Is(err, ErrInvalidTokenSource) {
		t.Fatalf("err = %v, want ErrInvalidTokenSource", err)
	}
}

func TestNewClientWithTokenSourceNilSource(t *testing.T) {
	_, err := NewClient(testProvider,
		WithBaseURL("http://example.com"),
		WithTokenSource("Authorization", nil),
	)
	if !errors.Is(err, ErrInvalidTokenSource) {
		t.Fatalf("err = %v, want ErrInvalidTokenSource", err)
	}
}

func TestClientGet(t *testing.T) {
	var gotPath string
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		gotHeader = r.Header.Get("X-Test")
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithDefaultHeader("X-Test", "yes"),
	)

	body, err := c.Get(t.Context(), "/foo")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Errorf("body = %q", string(body))
	}
	if gotPath != "/foo" {
		t.Errorf("path = %q", gotPath)
	}
	if gotHeader != "yes" {
		t.Errorf("header = %q", gotHeader)
	}
}

func TestClientDefaultQuery(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithDefaultQuery("api-version", "2021-02-01"),
	)

	_, err := c.Get(t.Context(), "/metadata/instance")
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "api-version=2021-02-01" {
		t.Errorf("query = %q", gotQuery)
	}
}

func TestClientGetWithQueryOverridesDefault(t *testing.T) {
	var gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion = r.URL.Query().Get("api-version")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithDefaultQuery("api-version", "2021-02-01"),
	)

	_, err := c.GetWithQuery(t.Context(), "/metadata/scheduledevents",
		url.Values{"api-version": {"2020-07-01"}})
	if err != nil {
		t.Fatal(err)
	}
	if gotVersion != "2020-07-01" {
		t.Errorf("version = %q, want override", gotVersion)
	}
}

func TestClientGetWithQueryMergesWithDefault(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithDefaultQuery("api-version", "2021-02-01"),
	)

	_, err := c.GetWithQuery(t.Context(), "/metadata/instance/compute/vmId",
		url.Values{"format": {"text"}})
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery.Get("api-version") != "2021-02-01" {
		t.Errorf("api-version = %q, want default preserved", gotQuery.Get("api-version"))
	}
	if gotQuery.Get("format") != "text" {
		t.Errorf("format = %q, want extra added", gotQuery.Get("format"))
	}
}

func TestClientNon200WrapsMetadataError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
	)

	_, err := c.Get(t.Context(), "/missing")
	if err == nil {
		t.Fatal("expected error")
	}
	var me *imds.MetadataError
	if !errors.As(err, &me) {
		t.Fatalf("error type = %T, want *imds.MetadataError", err)
	}
	if me.Provider != testProvider {
		t.Errorf("provider = %q", me.Provider)
	}
	if me.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d", me.StatusCode)
	}
	if me.Path != "/missing" {
		t.Errorf("path = %q", me.Path)
	}
}

func TestClientRequestError(t *testing.T) {
	c := newTestClient(t,
		WithBaseURL("http://127.0.0.1:1"),
		WithTimeout(100*time.Millisecond),
	)
	_, err := c.Get(t.Context(), "/foo")
	if err == nil {
		t.Fatal("expected connection error")
	}
	var me *imds.MetadataError
	if errors.As(err, &me) {
		t.Fatalf("network error should not be *imds.MetadataError, got %v", err)
	}
}

// TestClientDrainsBodyReusesConnection verifies that after a non-200 response
// the body is fully drained, so the underlying TCP connection is returned to
// the pool and reused by the next request. We use httptrace to count how many
// new connections were dialed — if drain works, three requests share one
// connection.
func TestClientDrainsBodyReusesConnection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("some error body that must be drained for reuse"))
	}))
	defer srv.Close()

	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
	)

	var newConns, reusedConns int
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Reused {
				reusedConns++
			} else {
				newConns++
			}
		},
	})

	for i := 0; i < 3; i++ {
		_, err := c.Get(ctx, "/missing")
		if err == nil {
			t.Fatal("expected error")
		}
	}

	if newConns != 1 {
		t.Errorf("new connections = %d, want 1 (body not drained → no keep-alive reuse)", newConns)
	}
	if reusedConns != 2 {
		t.Errorf("reused connections = %d, want 2", reusedConns)
	}
}

func TestClientCancelContext(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)

	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
	)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	_, err := c.Get(ctx, "/slow")
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestClientTimeoutOptionClonesHTTPClient(t *testing.T) {
	shared := &http.Client{Timeout: 10 * time.Second}
	c := newTestClient(t,
		WithBaseURL("http://example.com"),
		WithHTTPClient(shared),
		WithTimeout(1*time.Second),
	)
	if shared.Timeout != 10*time.Second {
		t.Errorf("shared client timeout mutated: %v", shared.Timeout)
	}
	if c.http.Timeout != 1*time.Second {
		t.Errorf("client timeout = %v, want 1s", c.http.Timeout)
	}
}

func TestClientTimeoutOptionOrderIndependent(t *testing.T) {
	shared := &http.Client{Timeout: 10 * time.Second}
	c := newTestClient(t,
		WithBaseURL("http://example.com"),
		WithTimeout(1*time.Second),
		WithHTTPClient(shared),
	)
	if shared.Timeout != 10*time.Second {
		t.Errorf("shared client timeout mutated: %v", shared.Timeout)
	}
	if c.http.Timeout != 1*time.Second {
		t.Errorf("client timeout = %v, want 1s (option order should not matter)", c.http.Timeout)
	}
}

func TestClientBlocksRedirectsOnUserSuppliedHTTPClient(t *testing.T) {
	var target *httptest.Server
	target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, target.URL+"/elsewhere", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("should-not-reach"))
	}))
	defer target.Close()

	shared := &http.Client{}
	c := newTestClient(t,
		WithHTTPClient(shared),
		WithBaseURL(target.URL),
	)

	_, err := c.Get(t.Context(), "/redirect")
	if err == nil {
		t.Fatal("expected error for redirect response")
	}
	var me *imds.MetadataError
	if !errors.As(err, &me) {
		t.Fatalf("error type = %T, want *imds.MetadataError from non-200", err)
	}
	if me.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 (redirect not followed)", me.StatusCode)
	}
	if shared.CheckRedirect != nil {
		t.Error("shared client CheckRedirect mutated")
	}
}

func TestClientPathWithExistingQueryString(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithDefaultQuery("api-version", "2021-02-01"),
	)

	_, err := c.Get(t.Context(), "/metadata/instance/compute/vmId?format=text")
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery.Get("format") != "text" {
		t.Errorf("format = %q, want preserved from path", gotQuery.Get("format"))
	}
	if gotQuery.Get("api-version") != "2021-02-01" {
		t.Errorf("api-version = %q, want default merged", gotQuery.Get("api-version"))
	}
}

func TestClientPathWithoutLeadingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
	)

	_, err := c.Get(t.Context(), "foo/bar")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/foo/bar" {
		t.Errorf("path = %q, want /foo/bar (leading slash normalized)", gotPath)
	}
}

func TestClientBaseURLTrimsTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL+"/"),
	)

	_, err := c.Get(t.Context(), "/foo")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/foo" {
		t.Errorf("path = %q", gotPath)
	}
}

// ---- Do / RequestOption tests ----

func TestClientDoCustomMethodWithBody(t *testing.T) {
	var gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t, WithHTTPClient(srv.Client()), WithBaseURL(srv.URL))
	resp, err := c.Do(t.Context(), "/token",
		WithMethod(http.MethodPut),
		WithBody(strings.NewReader(`{"expires_in":3600}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if string(gotBody) != `{"expires_in":3600}` {
		t.Errorf("body = %q", gotBody)
	}
	if string(resp.Body) != "ok" {
		t.Errorf("resp body = %q", resp.Body)
	}
}

func TestClientDoPerRequestHeaderOverridesDefault(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Test")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithDefaultHeader("X-Test", "default"),
	)
	_, err := c.Do(t.Context(), "/foo", WithHeader("X-Test", "override"))
	if err != nil {
		t.Fatal(err)
	}
	if gotHeader != "override" {
		t.Errorf("header = %q, want override", gotHeader)
	}
}

func TestClientDoResponseHeaderAccessible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Metadata-Flavor", "Google")
		w.Header().Set("ETag", "abc-123")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t, WithHTTPClient(srv.Client()), WithBaseURL(srv.URL))
	resp, err := c.Do(t.Context(), "/foo")
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Header.Get("Metadata-Flavor"); got != "Google" {
		t.Errorf("Metadata-Flavor = %q", got)
	}
	if got := resp.Header.Get("ETag"); got != "abc-123" {
		t.Errorf("ETag = %q", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestClientDoQueryParamOverride(t *testing.T) {
	var gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion = r.URL.Query().Get("api-version")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithDefaultQuery("api-version", "2021-02-01"),
	)
	_, err := c.Do(t.Context(), "/foo", WithQueryParam("api-version", "2020-07-01"))
	if err != nil {
		t.Fatal(err)
	}
	if gotVersion != "2020-07-01" {
		t.Errorf("api-version = %q", gotVersion)
	}
}

// ---- Error body snippet ----

func TestClientNon200IncludesBodySnippet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("resource-not-found-details"))
	}))
	defer srv.Close()

	c := newTestClient(t, WithHTTPClient(srv.Client()), WithBaseURL(srv.URL))
	_, err := c.Get(t.Context(), "/missing")
	var me *imds.MetadataError
	if !errors.As(err, &me) {
		t.Fatalf("error type = %T, want *imds.MetadataError", err)
	}
	if me.Err == nil {
		t.Fatal("expected body snippet in Err")
	}
	if !strings.Contains(me.Err.Error(), "resource-not-found-details") {
		t.Errorf("Err = %q, want to contain body", me.Err.Error())
	}
}

func TestClientNon200BodySnippetCapped(t *testing.T) {
	big := strings.Repeat("x", 8192)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	c := newTestClient(t, WithHTTPClient(srv.Client()), WithBaseURL(srv.URL))
	_, err := c.Get(t.Context(), "/oops")
	var me *imds.MetadataError
	if !errors.As(err, &me) || me.Err == nil {
		t.Fatalf("expected MetadataError with Err, got %v", err)
	}
	// Tolerate the "response body snippet: " prefix and %q-quote overhead
	// around the capped 2 KiB payload.
	if got := len(me.Err.Error()); got > maxErrBodySnippet+64 {
		t.Errorf("snippet len = %d, want ≤ %d", got, maxErrBodySnippet+64)
	}
}

// ---- TokenSource ----

// funcTokenSource adapts a bare function to the TokenSource interface for
// compact test cases. Production code should prefer a concrete struct.
type funcTokenSource func(ctx context.Context) (string, error)

func (f funcTokenSource) Token(ctx context.Context) (string, error) { return f(ctx) }

// countingTokenSource returns a new "Bearer tok-N" on every call, counting
// invocations atomically. Used to verify cache + retry behavior.
type countingTokenSource struct {
	calls int32
}

func (s *countingTokenSource) Token(ctx context.Context) (string, error) {
	n := atomic.AddInt32(&s.calls, 1)
	return "Bearer tok-" + strconv.Itoa(int(n)), nil
}

func (s *countingTokenSource) Calls() int32 { return atomic.LoadInt32(&s.calls) }

func TestTokenSourceInjectsHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	src := &countingTokenSource{}
	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithTokenSource("Authorization", src),
	)
	_, err := c.Get(t.Context(), "/foo")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok-1" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if got := src.Calls(); got != 1 {
		t.Errorf("Token calls = %d, want 1", got)
	}
}

func TestTokenSourceCachesBetweenRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	src := &countingTokenSource{}
	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithTokenSource("Authorization", src),
	)
	for i := 0; i < 3; i++ {
		if _, err := c.Get(t.Context(), "/foo"); err != nil {
			t.Fatal(err)
		}
	}
	if got := src.Calls(); got != 1 {
		t.Errorf("Token calls = %d, want 1 (cached)", got)
	}
}

func TestTokenSourceRetriesOn401(t *testing.T) {
	var seenAuth []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenAuth = append(seenAuth, r.Header.Get("Authorization"))
		n := len(seenAuth)
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	src := &countingTokenSource{}
	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithTokenSource("Authorization", src),
	)
	body, err := c.Get(t.Context(), "/foo")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q", body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seenAuth) != 2 {
		t.Fatalf("requests = %d, want 2", len(seenAuth))
	}
	if seenAuth[0] != "Bearer tok-1" || seenAuth[1] != "Bearer tok-2" {
		t.Errorf("seenAuth = %v", seenAuth)
	}
}

func TestTokenSourceRetriesOn403(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	src := funcTokenSource(func(ctx context.Context) (string, error) { return "tok", nil })
	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithTokenSource("X-Token", src),
	)
	if _, err := c.Get(t.Context(), "/foo"); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("attempts = %d, want 2", atomic.LoadInt32(&attempts))
	}
}

func TestTokenSourceSecondFailureReturnsError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	src := funcTokenSource(func(ctx context.Context) (string, error) { return "tok", nil })
	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithTokenSource("X-Token", src),
	)
	_, err := c.Get(t.Context(), "/foo")
	var me *imds.MetadataError
	if !errors.As(err, &me) {
		t.Fatalf("err = %v, want *imds.MetadataError", err)
	}
	if me.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d", me.StatusCode)
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("attempts = %d, want 2 (no infinite loop)", atomic.LoadInt32(&attempts))
	}
}

func TestTokenSourceNoRetryOn404(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	src := funcTokenSource(func(ctx context.Context) (string, error) { return "tok", nil })
	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithTokenSource("X-Token", src),
	)
	_, _ = c.Get(t.Context(), "/foo")
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("attempts = %d, want 1 (404 is not a token issue)", got)
	}
}

func TestTokenSourceErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	srcErr := errors.New("token boom")
	src := funcTokenSource(func(ctx context.Context) (string, error) { return "", srcErr })
	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithTokenSource("X-Token", src),
	)
	_, err := c.Get(t.Context(), "/foo")
	if !errors.Is(err, srcErr) {
		t.Errorf("err = %v, want srcErr", err)
	}
}

// TestTokenSourceDoesNotSerializeRequestsBehindSlowFetch verifies that
// getToken releases tokenMu before calling TokenSource.Token, so a slow
// first fetch doesn't block a concurrent second request from making its
// own (separate) fetch. With the old mutex-held behavior, the second
// goroutine would deadlock behind the first for the duration of the
// slow Token() call.
func TestTokenSourceDoesNotSerializeRequestsBehindSlowFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var calls int32
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	src := funcTokenSource(func(ctx context.Context) (string, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			// Simulate a slow first fetch.
			close(firstStarted)
			<-releaseFirst
		}
		return "tok", nil
	})
	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithTokenSource("X-Token", src),
	)

	// Goroutine A starts the slow fetch.
	aDone := make(chan error, 1)
	go func() {
		_, err := c.Get(t.Context(), "/foo")
		aDone <- err
	}()
	<-firstStarted // A is now inside Token(), blocked on releaseFirst.

	// Goroutine B should be able to proceed: it acquires the mutex,
	// sees an empty cache, releases the mutex, and calls Token() — which
	// is the fast path on its own goroutine (calls > 1).
	bDone := make(chan error, 1)
	go func() {
		_, err := c.Get(t.Context(), "/bar")
		bDone <- err
	}()

	select {
	case err := <-bDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(releaseFirst)
		t.Fatal("second request blocked behind first's Token() call")
	}
	close(releaseFirst)
	if err := <-aDone; err != nil {
		t.Fatal(err)
	}
}

// TestNon200SnippetPreservesNonUTF8Bytes verifies that the error body
// snippet is formatted via %q on []byte (not on a string), preserving
// raw bytes instead of replacing invalid UTF-8 with U+FFFD.
func TestNon200SnippetPreservesNonUTF8Bytes(t *testing.T) {
	// \xff\xfe is not valid UTF-8; string conversion would mangle it.
	payload := []byte{0xff, 0xfe, 'x', 'y', 'z'}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	c := newTestClient(t, WithHTTPClient(srv.Client()), WithBaseURL(srv.URL))
	_, err := c.Get(t.Context(), "/oops")
	var me *imds.MetadataError
	if !errors.As(err, &me) || me.Err == nil {
		t.Fatalf("expected MetadataError with Err, got %v", err)
	}
	// fmt.Sprintf("%q", payload) quotes the raw bytes using \xff-style
	// escapes. A string conversion would render \ufffd instead.
	want := fmt.Sprintf("%q", payload)
	if !strings.Contains(me.Err.Error(), want) {
		t.Errorf("error = %q, want substring %q", me.Err.Error(), want)
	}
	if strings.Contains(me.Err.Error(), "\ufffd") {
		t.Errorf("error contains U+FFFD, raw bytes were lost: %q", me.Err.Error())
	}
}

// TestBuildURLInlineQueryParseErrorHasContext verifies that a malformed
// inline query produces an error that names the offending path, so
// callers can diagnose which request was invalid.
func TestBuildURLInlineQueryParseErrorHasContext(t *testing.T) {
	c := newTestClient(t, WithBaseURL("http://example.com"))
	// "%zz" is an invalid percent-encoded sequence — url.ParseQuery
	// returns an error.
	_, err := c.Get(t.Context(), "/foo?x=%zz")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "/foo") {
		t.Errorf("err = %v, want to contain '/foo'", err)
	}
	if !strings.Contains(err.Error(), "httputil") {
		t.Errorf("err = %v, want to contain 'httputil' package prefix", err)
	}
}

// ---- URL edge cases ----

func TestBuildURLEmptyInlineQueryDoesNotLeaveTrailingQuestionMark(t *testing.T) {
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t, WithHTTPClient(srv.Client()), WithBaseURL(srv.URL))
	_, err := c.Get(t.Context(), "/foo?")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(gotURL, "?") {
		t.Errorf("URL has trailing '?': %q", gotURL)
	}
	if gotURL != "/foo" {
		t.Errorf("URL = %q, want /foo", gotURL)
	}
}

// ---- retryTransport with buffered body ----

type fastRetryer struct{}

func (fastRetryer) MaxAttempts() int               { return 3 }
func (fastRetryer) BackoffDelay(int) time.Duration { return 0 }
func (fastRetryer) IsRetryable(code int) bool      { return code == http.StatusServiceUnavailable }

// TestRetryTransportReplaysBufferedBody exercises the production code path
// where Do hands a *bytes.Reader (via an io.Reader interface) to
// http.NewRequestWithContext, then retryTransport retries on 503. Stdlib
// auto-sets req.GetBody for *bytes.Reader inputs, so the retry transport
// can replay the body across attempts. Regression test for the concern
// that a buffered body wouldn't survive transport-level retries.
func TestRetryTransportReplaysBufferedBody(t *testing.T) {
	var bodies []string
	var mu sync.Mutex
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		if atomic.AddInt32(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Wrap httptest's default transport with our production retryTransport.
	httpc := NewHTTPClient(srv.Client().Transport, fastRetryer{})
	c := newTestClient(t, WithHTTPClient(httpc), WithBaseURL(srv.URL))

	_, err := c.Do(t.Context(), "/token",
		WithMethod(http.MethodPut),
		WithBody(strings.NewReader(`{"expires_in":3600}`)),
	)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 3 {
		t.Fatalf("bodies seen = %d, want 3", len(bodies))
	}
	for i, b := range bodies {
		if b != `{"expires_in":3600}` {
			t.Errorf("attempt %d body = %q", i, b)
		}
	}
}

// ---- Body reuse across retries ----

func TestDoBodyReplayedOnTokenRetry(t *testing.T) {
	var bodies []string
	var mu sync.Mutex
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	src := funcTokenSource(func(ctx context.Context) (string, error) { return "tok", nil })
	c := newTestClient(t,
		WithHTTPClient(srv.Client()),
		WithBaseURL(srv.URL),
		WithTokenSource("X-Token", src),
	)

	_, err := c.Do(t.Context(), "/token",
		WithMethod(http.MethodPut),
		WithBody(strings.NewReader(`{"expires_in":3600}`)),
	)
	if err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("bodies seen = %d, want 2", len(bodies))
	}
	if bodies[0] != bodies[1] {
		t.Errorf("body mismatch on retry:\n  first  = %q\n  second = %q", bodies[0], bodies[1])
	}
	if bodies[0] != `{"expires_in":3600}` {
		t.Errorf("body = %q", bodies[0])
	}
}

// ---- GetWithQuery multi-value preservation ----

func TestGetWithQueryPreservesMultiValue(t *testing.T) {
	var gotValues []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotValues = r.URL.Query()["tag"]
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t, WithHTTPClient(srv.Client()), WithBaseURL(srv.URL))
	_, err := c.GetWithQuery(t.Context(), "/foo",
		url.Values{"tag": {"a", "b", "c"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotValues) != 3 || gotValues[0] != "a" || gotValues[1] != "b" || gotValues[2] != "c" {
		t.Errorf("tag values = %v, want [a b c]", gotValues)
	}
}


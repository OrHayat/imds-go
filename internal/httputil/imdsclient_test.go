package httputil

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
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

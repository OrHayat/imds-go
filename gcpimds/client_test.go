package gcpimds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	imds "github.com/OrHayat/imds-go"
)

func newFakeServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// requireFlavor is called from httptest handlers which run in their own
// goroutine. Calling t.Fatalf from a non-test goroutine is unsafe (per
// testing docs), so instead the handler returns 400 on a missing header,
// which propagates as an error through the normal client-side assertion.
func requireFlavor(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get(flavorHeader) != flavorValue {
		http.Error(w, "missing "+flavorHeader+": "+flavorValue+" header", http.StatusBadRequest)
		return false
	}
	return true
}

func TestProbe_Success(t *testing.T) {
	srv := newFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !requireFlavor(w, r) {
			return
		}
		w.Header().Set(flavorHeader, flavorValue)
		w.WriteHeader(http.StatusOK)
	})

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected probe to succeed")
	}
}

func TestProbe_MissingFlavorHeader(t *testing.T) {
	srv := newFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected probe to fail without flavor header")
	}
}

func TestProbe_ConnectionError(t *testing.T) {
	c, err := New(WithBaseURL("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err == nil {
		t.Fatal("expected error on connection failure")
	}
	if ok {
		t.Fatal("expected probe to return false on connection error")
	}
}

func TestProbe_SendsFlavorHeader(t *testing.T) {
	var gotHeader string
	srv := newFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(flavorHeader)
		w.Header().Set(flavorHeader, flavorValue)
		w.WriteHeader(http.StatusOK)
	})

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Probe(t.Context())
	if gotHeader != flavorValue {
		t.Fatalf("expected %q header, got %q", flavorValue, gotHeader)
	}
}

func TestID(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if c.ID() != imds.ID("gcp") {
		t.Fatalf("expected gcp, got %s", c.ID())
	}
}

func fakeMetadataHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireFlavor(w, r) {
			return
		}
		responses := map[string]string{
			"/computeMetadata/v1/instance/id":           "123456",
			"/computeMetadata/v1/instance/machine-type":  "projects/123/machineTypes/n1-standard-1",
			"/computeMetadata/v1/instance/image":         "projects/123/global/images/my-image",
			"/computeMetadata/v1/instance/zone":          "projects/123/zones/us-central1-a",
			"/computeMetadata/v1/instance/hostname":      "my-host.internal",
			"/computeMetadata/v1/project/numeric-project-id": "999888",
			"/computeMetadata/v1/project/project-id":     "my-project",
			"/computeMetadata/v1/instance/scheduling/preemptible": "TRUE",
			"/computeMetadata/v1/instance/network-interfaces/": "0/\n",
			"/computeMetadata/v1/instance/network-interfaces/0/ip":      "10.0.0.1",
			"/computeMetadata/v1/instance/network-interfaces/0/mac":     "aa:bb:cc:dd:ee:ff",
			"/computeMetadata/v1/instance/network-interfaces/0/network": "projects/123/networks/default",
			"/computeMetadata/v1/instance/attributes/":                  "env\nteam\n",
			"/computeMetadata/v1/instance/attributes/env":               "prod",
			"/computeMetadata/v1/instance/attributes/team":              "infra",
		}
		resp, ok := responses[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, "not found")
			return
		}
		_, _ = fmt.Fprint(w, resp)
	}
}

func TestGetMetadata(t *testing.T) {
	srv := newFakeServer(t, fakeMetadataHandler(t))
	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if md.Provider != ProviderID {
		t.Fatalf("provider: got %s, want %s", md.Provider, ProviderID)
	}
	if md.Instance.ID != "123456" {
		t.Fatalf("instance id: got %s", md.Instance.ID)
	}
	if md.Instance.InstanceType != "n1-standard-1" {
		t.Fatalf("instance type: got %s", md.Instance.InstanceType)
	}
	if md.Instance.ImageID != "projects/123/global/images/my-image" {
		t.Fatalf("image: got %s", md.Instance.ImageID)
	}
	if md.Instance.Location.Zone != "us-central1-a" {
		t.Fatalf("zone: got %s", md.Instance.Location.Zone)
	}
	if md.Instance.Location.Region != "us-central1" {
		t.Fatalf("region: got %s", md.Instance.Location.Region)
	}
	if md.Instance.Hostname != "my-host.internal" {
		t.Fatalf("hostname: got %s", md.Instance.Hostname)
	}
	if md.Instance.AccountID != "999888" {
		t.Fatalf("account id: got %s", md.Instance.AccountID)
	}

	if len(md.Interfaces) != 1 {
		t.Fatalf("interfaces: got %d", len(md.Interfaces))
	}
	iface := md.Interfaces[0]
	if iface.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("mac: got %s", iface.MAC)
	}
	if len(iface.PrivateIPv4s) != 1 || iface.PrivateIPv4s[0] != "10.0.0.1" {
		t.Fatalf("private ipv4: got %v", iface.PrivateIPv4s)
	}
	if iface.VPCID != "default" {
		t.Fatalf("vpc: got %s", iface.VPCID)
	}

	if md.Tags["env"] != "prod" || md.Tags["team"] != "infra" {
		t.Fatalf("tags: got %v", md.Tags)
	}

	if md.AdditionalProperties["project-id"] != "my-project" {
		t.Fatalf("project-id: got %v", md.AdditionalProperties["project-id"])
	}
	if md.AdditionalProperties["scheduling/preemptible"] != "TRUE" {
		t.Fatalf("preemptible: got %v", md.AdditionalProperties["scheduling/preemptible"])
	}
}

func TestQuery(t *testing.T) {
	srv := newFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !requireFlavor(w, r) {
			return
		}
		_, _ = fmt.Fprint(w, "hello")
	})

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	data, err := c.Query(t.Context(), "/computeMetadata/v1/instance/id")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("got %s", data)
	}
}

func TestQuery_Error(t *testing.T) {
	srv := newFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "not found")
	})

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Query(t.Context(), "/bad/path")
	if err == nil {
		t.Fatal("expected error")
	}
	var mdErr *imds.MetadataError
	if !errors.As(err, &mdErr) {
		t.Fatalf("expected *imds.MetadataError, got %T: %v", err, err)
	}
	if mdErr.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", mdErr.StatusCode)
	}
	if mdErr.Path != "/bad/path" {
		t.Fatalf("expected path /bad/path, got %q", mdErr.Path)
	}
}

func TestWatch_EtagChange(t *testing.T) {
	var etag atomic.Value
	etag.Store("etag-1")

	var tagVal atomic.Value
	tagVal.Store("1")

	srv := newFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !requireFlavor(w, r) {
			return
		}

		if r.URL.Query().Get("wait_for_change") == "true" {
			lastEtag := r.URL.Query().Get("last_etag")
			currentEtag, _ := etag.Load().(string)
			if lastEtag == currentEtag {
				tagVal.Store("2")
				etag.Store("etag-2")
				currentEtag = "etag-2"
			}
			w.Header().Set("ETag", currentEtag)
			_, _ = fmt.Fprint(w, "{}")
			return
		}

		responses := map[string]string{
			"/computeMetadata/v1/instance/id":                          "123",
			"/computeMetadata/v1/instance/machine-type":                "n1-standard-1",
			"/computeMetadata/v1/instance/image":                       "",
			"/computeMetadata/v1/instance/zone":                        "us-central1-a",
			"/computeMetadata/v1/instance/hostname":                    "host",
			"/computeMetadata/v1/project/numeric-project-id":           "999",
			"/computeMetadata/v1/project/project-id":                   "proj",
			"/computeMetadata/v1/instance/scheduling/preemptible":      "FALSE",
			"/computeMetadata/v1/instance/network-interfaces/":         "",
			"/computeMetadata/v1/instance/attributes/":                 "v\n",
		}

		if r.URL.Path == "/computeMetadata/v1/instance/attributes/v" {
			v, _ := tagVal.Load().(string)
			_, _ = fmt.Fprint(w, v)
			return
		}

		resp, ok := responses[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprint(w, resp)
	})

	c, err := New(WithBaseURL(srv.URL), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	ch, err := c.Watch(ctx, imds.WatchConfig{})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-ch:
		if ev.Err != nil {
			t.Fatalf("unexpected error: %v", ev.Err)
		}
		if len(ev.Changed) == 0 {
			t.Fatal("expected changes")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for watch event")
	}
}

func TestWatch_ClosesOnCancel(t *testing.T) {
	srv := newFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("wait_for_change") == "true" {
			w.Header().Set("ETag", "e1")
			_, _ = fmt.Fprint(w, "{}")
			return
		}
		responses := map[string]string{
			"/computeMetadata/v1/instance/id":                     "1",
			"/computeMetadata/v1/instance/machine-type":           "t",
			"/computeMetadata/v1/instance/image":                  "",
			"/computeMetadata/v1/instance/zone":                   "z-a",
			"/computeMetadata/v1/instance/hostname":               "h",
			"/computeMetadata/v1/project/numeric-project-id":      "9",
			"/computeMetadata/v1/project/project-id":              "p",
			"/computeMetadata/v1/instance/scheduling/preemptible": "F",
			"/computeMetadata/v1/instance/network-interfaces/":    "",
			"/computeMetadata/v1/instance/attributes/":            "",
		}
		resp, ok := responses[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprint(w, resp)
	})

	c, err := New(WithBaseURL(srv.URL), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	ch, err := c.Watch(ctx, imds.WatchConfig{})
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	for ev := range ch {
		_ = ev
	}
}

func TestEndpointResolution(t *testing.T) {
	tests := []struct {
		name     string
		opts     options
		envHost  string
		expected string
	}{
		{"default", options{}, "", defaultDNSEndpoint},
		{"ipv4 mode", options{endpointMode: EndpointModeIPv4}, "", defaultIPv4Endpoint},
		{"ipv6 mode", options{endpointMode: EndpointModeIPv6}, "", defaultIPv6Endpoint},
		{"base url wins", options{baseURL: "http://custom:8080", endpointMode: EndpointModeIPv4}, "", "http://custom:8080"},
		{"env wins over mode", options{endpointMode: EndpointModeIPv4}, "myhost:8080", "http://myhost:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envHost != "" {
				t.Setenv("GCE_METADATA_HOST", tt.envHost)
			}
			got := resolveBaseURL(tt.opts)
			if got != tt.expected {
				t.Fatalf("got %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestProbe_4xx(t *testing.T) {
	srv := newFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatalf("expected no error on 4xx, got %v", err)
	}
	if ok {
		t.Fatal("expected false on 4xx")
	}
}

func TestProbe_5xx(t *testing.T) {
	srv := newFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err == nil {
		t.Fatal("expected error on 5xx")
	}
	if ok {
		t.Fatal("expected false on 5xx")
	}
}

func TestLastSegment(t *testing.T) {
	if got := lastSegment("projects/123/machineTypes/n1-standard-1"); got != "n1-standard-1" {
		t.Fatalf("got %s", got)
	}
	if got := lastSegment("simple"); got != "simple" {
		t.Fatalf("got %s", got)
	}
}

// Compile-time interface check
var _ imds.Provider = (*Client)(nil)

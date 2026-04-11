package vultrimds

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	imds "github.com/OrHayat/imds-go"
)

var _ imds.Provider = (*Client)(nil)

var sampleResponse = InstanceDocument{
	InstanceID: "abc-123",
	Region:     "ewr",
	Hostname:   "my-instance",
	Plan:       "vc2-1c-1gb",
	OS:         "Ubuntu 22.04",
	RAM:        "1024 MB",
	Tags:       []string{"env=prod", "team=infra", "standalone"},
	Interfaces: []Interface{
		{
			IPv4:        IPv4{Address: "203.0.113.5", Gateway: "203.0.113.1"},
			MAC:         "aa:bb:cc:dd:ee:01",
			NetworkType: "public",
		},
		{
			IPv4:        IPv4{Address: "10.0.0.5", Gateway: "10.0.0.1"},
			MAC:         "aa:bb:cc:dd:ee:02",
			NetworkType: "private",
		},
	},
}

func defaultHandler(doc InstanceDocument) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case metadataPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(doc)
		case instanceIDPath:
			_, _ = w.Write([]byte(doc.InstanceID))
		case regionPath:
			_, _ = w.Write([]byte(doc.Region))
		case hostnamePath:
			_, _ = w.Write([]byte(doc.Hostname))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	ts := newTestServer(t, handler)
	c, err := New(WithBaseURL(ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestID(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if c.ID() != ProviderID {
		t.Fatalf("got %q, want %q", c.ID(), ProviderID)
	}
}

func TestProbe_Success(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != metadataPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sampleResponse)
	})

	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected probe to succeed")
	}
}

func TestProbe_NotVultr(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected probe to fail")
	}
}

func TestProbe_InvalidJSON(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not json"))
	})

	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected probe to fail on invalid JSON")
	}
}

func TestProbe_ConnectionError(t *testing.T) {
	// Bind an ephemeral port and close it before probing — the OS
	// guarantees the next connection to that address is refused,
	// independent of anything that happens to be listening on
	// well-known ports in the test environment.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	c, err := New(
		WithBaseURL("http://"+addr),
		WithTimeout(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err == nil {
		t.Fatal("expected error on connection failure")
	}
	if ok {
		t.Fatal("expected probe to return false")
	}
}

func TestProbe_ServerError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	ok, err := c.Probe(t.Context())
	if err == nil {
		t.Fatal("expected error on 5xx response")
	}
	if ok {
		t.Fatal("expected probe to return false")
	}
}

func TestGetMetadata(t *testing.T) {
	c := newTestClient(t, defaultHandler(sampleResponse))

	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if md.Provider != ProviderID {
		t.Errorf("provider: got %q, want %q", md.Provider, ProviderID)
	}
	if md.Instance.ID != "abc-123" {
		t.Errorf("instance ID: got %q, want %q", md.Instance.ID, "abc-123")
	}
	if md.Instance.Location.Region != "ewr" {
		t.Errorf("region: got %q, want %q", md.Instance.Location.Region, "ewr")
	}
	if md.Instance.Hostname != "my-instance" {
		t.Errorf("hostname: got %q, want %q", md.Instance.Hostname, "my-instance")
	}

	if len(md.Interfaces) != 2 {
		t.Fatalf("interfaces: got %d, want 2", len(md.Interfaces))
	}
	pub := md.Interfaces[0]
	if len(pub.PublicIPv4s) != 1 || pub.PublicIPv4s[0] != "203.0.113.5" {
		t.Errorf("public ipv4: got %v", pub.PublicIPv4s)
	}
	if pub.MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("public mac: got %q", pub.MAC)
	}
	priv := md.Interfaces[1]
	if len(priv.PrivateIPv4s) != 1 || priv.PrivateIPv4s[0] != "10.0.0.5" {
		t.Errorf("private ipv4: got %v", priv.PrivateIPv4s)
	}

	if md.Tags["env"] != "prod" || md.Tags["team"] != "infra" || md.Tags["standalone"] != "" {
		t.Errorf("tags: got %v", md.Tags)
	}

	if md.Instance.InstanceType != "vc2-1c-1gb" {
		t.Errorf("instance type: got %v", md.Instance.InstanceType)
	}
	if md.AdditionalProperties["os"] != "Ubuntu 22.04" {
		t.Errorf("os: got %v", md.AdditionalProperties["os"])
	}
	if md.AdditionalProperties["ram"] != "1024 MB" {
		t.Errorf("ram: got %v", md.AdditionalProperties["ram"])
	}
}

func TestGetMetadata_NonRetryableError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	_, err := c.GetMetadata(t.Context())
	if err == nil {
		t.Fatal("expected error")
	}
	var me *imds.MetadataError
	if !errors.As(err, &me) {
		t.Fatalf("expected MetadataError, got %T", err)
	}
	if me.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d, want %d", me.StatusCode, http.StatusForbidden)
	}
}

func TestGetMetadata_RetryableError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := c.GetMetadata(t.Context())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetMetadata_BadJSON(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("{invalid"))
	})

	_, err := c.GetMetadata(t.Context())
	if err == nil {
		t.Fatal("expected error on bad JSON")
	}
}

func TestAccessors(t *testing.T) {
	c := newTestClient(t, defaultHandler(sampleResponse))
	ctx := t.Context()

	id, err := c.InstanceID(ctx)
	if err != nil {
		t.Fatalf("InstanceID: %v", err)
	}
	if id != "abc-123" {
		t.Errorf("InstanceID: got %q, want %q", id, "abc-123")
	}

	region, err := c.Region(ctx)
	if err != nil {
		t.Fatalf("Region: %v", err)
	}
	if region != "ewr" {
		t.Errorf("Region: got %q, want %q", region, "ewr")
	}

	hostname, err := c.Hostname(ctx)
	if err != nil {
		t.Fatalf("Hostname: %v", err)
	}
	if hostname != "my-instance" {
		t.Errorf("Hostname: got %q, want %q", hostname, "my-instance")
	}

	tags, err := c.Tags(ctx)
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if len(tags) != 3 {
		t.Errorf("Tags: got %d, want 3", len(tags))
	}

	ifaces, err := c.Interfaces(ctx)
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	if len(ifaces) != 2 {
		t.Errorf("Interfaces: got %d, want 2", len(ifaces))
	}
}

func TestAccessors_WhitespaceTrimmed(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case instanceIDPath:
			_, _ = w.Write([]byte("  abc-123\n"))
		case regionPath:
			_, _ = w.Write([]byte("  ewr \n"))
		case hostnamePath:
			_, _ = w.Write([]byte("\tmy-instance\t\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ctx := t.Context()

	id, err := c.InstanceID(ctx)
	if err != nil {
		t.Fatalf("InstanceID: %v", err)
	}
	if id != "abc-123" {
		t.Errorf("InstanceID: got %q, want %q", id, "abc-123")
	}
	region, err := c.Region(ctx)
	if err != nil {
		t.Fatalf("Region: %v", err)
	}
	if region != "ewr" {
		t.Errorf("Region: got %q, want %q", region, "ewr")
	}
	hostname, err := c.Hostname(ctx)
	if err != nil {
		t.Fatalf("Hostname: %v", err)
	}
	if hostname != "my-instance" {
		t.Errorf("Hostname: got %q, want %q", hostname, "my-instance")
	}
}

func TestWatch(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		resp := sampleResponse
		if calls > 1 {
			resp.Tags = []string{"env=staging"}
		}
		defaultHandler(resp)(w, r)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	ch, err := c.Watch(ctx, imds.WatchConfig{Interval: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}

	ev := <-ch
	if ev.Err != nil {
		t.Fatalf("watch event error: %v", ev.Err)
	}
	if len(ev.Changed) == 0 {
		t.Fatal("expected changed fields")
	}
}

func TestParseTags(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    map[string]string
		wantNil bool
	}{
		{"nil input", nil, nil, true},
		{"empty input", []string{}, nil, true},
		{"key=value", []string{"a=b"}, map[string]string{"a": "b"}, false},
		{"value contains equals", []string{"key=val=ue"}, map[string]string{"key": "val=ue"}, false},
		{"bare tag", []string{"bare"}, map[string]string{"bare": ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTags(tt.in)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %v", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("[%q]: got %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

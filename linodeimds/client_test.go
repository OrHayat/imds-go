package linodeimds

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	imds "github.com/OrHayat/imds-go"
)

var _ imds.Provider = (*Client)(nil)

func fakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("PUT /v1/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Token-Expiry-Seconds") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Write([]byte("test-token-abc"))
	})

	mux.HandleFunc("GET /v1/instance", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Token") != "test-token-abc" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(InstanceDocument{
			ID:       12345,
			Label:    "my-linode",
			Region:   "us-east",
			Type:     "g6-standard-2",
			HostUUID: "abc-def-123",
			Tags:     []string{"env=prod", "team=infra"},
			Backups:  struct{ Enabled bool `json:"enabled"` }{Enabled: true},
		})
	})

	mux.HandleFunc("GET /v1/network", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Token") != "test-token-abc" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(NetworkDocument{
			Interfaces: []NetworkInterfaceEntry{
				{
					IPv4:       NetworkIPv4Entry{Address: "203.0.113.10"},
					MACAddress: "aa:bb:cc:dd:ee:ff",
					Purpose:    "public",
				},
				{
					IPv4:       NetworkIPv4Entry{Address: "192.168.1.5"},
					MACAddress: "11:22:33:44:55:66",
					Purpose:    "private",
				},
			},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestClient(t *testing.T) (*Client, *httptest.Server) {
	t.Helper()
	srv := fakeServer(t)
	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
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

func TestProbe(t *testing.T) {
	c, _ := newTestClient(t)
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected probe to succeed")
	}
}

func TestProbeFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected probe to fail")
	}
}

func TestGetMetadata(t *testing.T) {
	c, _ := newTestClient(t)
	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if md.Provider != ProviderID {
		t.Errorf("provider: got %q, want %q", md.Provider, ProviderID)
	}
	if md.Instance.ID != "12345" {
		t.Errorf("id: got %q, want %q", md.Instance.ID, "12345")
	}
	if md.Instance.Hostname != "my-linode" {
		t.Errorf("hostname: got %q, want %q", md.Instance.Hostname, "my-linode")
	}
	if md.Instance.Location.Region != "us-east" {
		t.Errorf("region: got %q, want %q", md.Instance.Location.Region, "us-east")
	}
	if md.Instance.InstanceType != "g6-standard-2" {
		t.Errorf("type: got %q, want %q", md.Instance.InstanceType, "g6-standard-2")
	}

	if len(md.Interfaces) != 2 {
		t.Fatalf("interfaces: got %d, want 2", len(md.Interfaces))
	}
	pub := md.Interfaces[0]
	if len(pub.PublicIPv4s) != 1 || pub.PublicIPv4s[0] != "203.0.113.10" {
		t.Errorf("public ipv4: got %v", pub.PublicIPv4s)
	}
	priv := md.Interfaces[1]
	if len(priv.PrivateIPv4s) != 1 || priv.PrivateIPv4s[0] != "192.168.1.5" {
		t.Errorf("private ipv4: got %v", priv.PrivateIPv4s)
	}

	if len(md.Tags) != 2 {
		t.Errorf("tags: got %d, want 2", len(md.Tags))
	}
	if md.Tags["env"] != "prod" {
		t.Errorf("tags[env]: got %q, want %q", md.Tags["env"], "prod")
	}
	if md.Tags["team"] != "infra" {
		t.Errorf("tags[team]: got %q, want %q", md.Tags["team"], "infra")
	}

	if md.AdditionalProperties["host_uuid"] != "abc-def-123" {
		t.Errorf("host_uuid: got %v", md.AdditionalProperties["host_uuid"])
	}
	if md.AdditionalProperties["backups.enabled"] != true {
		t.Errorf("backups.enabled: got %v", md.AdditionalProperties["backups.enabled"])
	}
}

func TestTokenCaching(t *testing.T) {
	var callCount atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/token", func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Write([]byte("cached-token"))
	})
	mux.HandleFunc("GET /v1/instance", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InstanceDocument{ID: 1, Label: "x", Region: "r", Type: "t"})
	})
	mux.HandleFunc("GET /v1/network", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(NetworkDocument{})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()

	if _, err := c.GetMetadata(ctx); err != nil {
		t.Fatalf("first GetMetadata: %v", err)
	}
	if _, err := c.GetMetadata(ctx); err != nil {
		t.Fatalf("second GetMetadata: %v", err)
	}

	if n := callCount.Load(); n != 1 {
		t.Errorf("token fetched %d times, want 1", n)
	}
}

func TestWatch(t *testing.T) {
	var callCount atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/token", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tok"))
	})
	mux.HandleFunc("GET /v1/instance", func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		label := "host-a"
		if n > 1 {
			label = "host-b"
		}
		_ = json.NewEncoder(w).Encode(InstanceDocument{ID: 1, Label: label, Region: "r", Type: "t", Tags: []string{"v=" + label}})
	})
	mux.HandleFunc("GET /v1/network", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(NetworkDocument{})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	ch, err := c.Watch(ctx, imds.WatchConfig{Interval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	// Consume events until we see a real tags delta. Skip:
	//  1. events where ev.Old == nil — PollWatch synthesizes a
	//     "everything changed" event only when the initial fetch
	//     failed and a later poll succeeded, at which point
	//     DiffMetadata(nil, cur) reports every watched field as
	//     changed.
	//  2. events without any Changed fields.
	// Require "tags" to appear in ev.Changed so a broken
	// tag-mapping path would surface as a real failure instead of
	// sneaking through on a hostname change or similar.
	for {
		select {
		case <-ctx.Done():
			t.Fatal("expected watch event with tags change before timeout")
		case ev, ok := <-ch:
			// When ctx is cancelled, watchutil.PollWatch closes ch.
			// If both ctx.Done() and the closed channel are ready,
			// select can pick the channel receive and yield a zero
			// imds.Event{}, which would fail the ev.New == nil check
			// below. Treat !ok as termination instead of evaluating
			// the zero event.
			if !ok {
				t.Fatal("watch channel closed before tags change event")
			}
			if ev.Err != nil {
				t.Fatal(ev.Err)
			}
			if ev.New == nil {
				t.Fatal("expected non-nil New metadata")
			}
			if ev.Old == nil || len(ev.Changed) == 0 {
				continue
			}
			for _, field := range ev.Changed {
				if field == "tags" {
					return
				}
			}
		}
	}
}

func TestProbeServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err == nil {
		t.Fatal("expected error for 5xx")
	}
	if ok {
		t.Fatal("expected probe to fail")
	}
}

func TestAccessors(t *testing.T) {
	// Exercises every public accessor (InstanceID, Region, Hostname,
	// InstanceType, Tags, Interfaces) against the shared fake server
	// so regressions in instanceField + per-method mapping cannot
	// sneak through GetMetadata-only coverage.
	c, _ := newTestClient(t)
	ctx := t.Context()

	id, err := c.InstanceID(ctx)
	if err != nil {
		t.Fatalf("InstanceID: %v", err)
	}
	if id != "12345" {
		t.Errorf("InstanceID: got %q, want %q", id, "12345")
	}

	region, err := c.Region(ctx)
	if err != nil {
		t.Fatalf("Region: %v", err)
	}
	if region != "us-east" {
		t.Errorf("Region: got %q, want %q", region, "us-east")
	}

	hostname, err := c.Hostname(ctx)
	if err != nil {
		t.Fatalf("Hostname: %v", err)
	}
	if hostname != "my-linode" {
		t.Errorf("Hostname: got %q, want %q", hostname, "my-linode")
	}

	iType, err := c.InstanceType(ctx)
	if err != nil {
		t.Fatalf("InstanceType: %v", err)
	}
	if iType != "g6-standard-2" {
		t.Errorf("InstanceType: got %q, want %q", iType, "g6-standard-2")
	}

	tags, err := c.Tags(ctx)
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if len(tags) != 2 || tags["env"] != "prod" || tags["team"] != "infra" {
		t.Errorf("Tags: got %v, want {env:prod, team:infra}", tags)
	}

	ifaces, err := c.Interfaces(ctx)
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	if len(ifaces) != 2 {
		t.Fatalf("Interfaces: got %d, want 2", len(ifaces))
	}
	if len(ifaces[0].PublicIPv4s) != 1 || ifaces[0].PublicIPv4s[0] != "203.0.113.10" {
		t.Errorf("Interfaces[0].PublicIPv4s: got %v", ifaces[0].PublicIPv4s)
	}
	if ifaces[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("Interfaces[0].MAC: got %q", ifaces[0].MAC)
	}
	if len(ifaces[1].PrivateIPv4s) != 1 || ifaces[1].PrivateIPv4s[0] != "192.168.1.5" {
		t.Errorf("Interfaces[1].PrivateIPv4s: got %v", ifaces[1].PrivateIPv4s)
	}
}

func TestGetMetadataAdditionalPropertiesNil(t *testing.T) {
	// When the instance document has no host_uuid and backups are
	// disabled, GetMetadata must leave md.AdditionalProperties nil
	// (not an empty map). This distinction matters for JSON output
	// (`"additional_properties":null` vs `{}`) and for
	// reflect.DeepEqual in watchutil.DiffMetadata, which would
	// otherwise report a spurious AdditionalProperties change on
	// the first successful poll.
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/token", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tok"))
	})
	mux.HandleFunc("GET /v1/instance", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InstanceDocument{
			ID:     1,
			Label:  "bare-linode",
			Region: "us-east",
			Type:   "g6-standard-1",
		})
	})
	mux.HandleFunc("GET /v1/network", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(NetworkDocument{})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if md.AdditionalProperties != nil {
		t.Fatalf("AdditionalProperties: got %#v, want nil", md.AdditionalProperties)
	}
}

func TestGetMetadataTokenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetMetadata(t.Context())
	if err == nil {
		t.Fatal("expected error")
	}
}

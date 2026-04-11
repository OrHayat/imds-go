package hetznerimds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	imds "github.com/OrHayat/imds-go"
)

var _ imds.Provider = (*Client)(nil)

const testYAML = `instance-id: 12345
hostname: my-server
region: eu-central
availability-zone: fsn1-dc14
public-ipv4: 1.2.3.4
private-networks:
  - ip: 10.0.0.1
  - ip: 10.0.0.2
public-keys:
  - ssh-rsa AAAA...
`

func newTestServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

var individualFields = map[string]string{
	"/hetzner/v1/metadata/instance-id":       "12345",
	"/hetzner/v1/metadata/region":            "eu-central",
	"/hetzner/v1/metadata/availability-zone": "fsn1-dc14",
	"/hetzner/v1/metadata/hostname":          "my-server",
	"/hetzner/v1/metadata/public-ipv4":       "1.2.3.4",
}

func metadataHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/hetzner/v1/metadata" {
		w.Header().Set("Content-Type", "text/yaml")
		_, _ = w.Write([]byte(testYAML))
		return
	}
	if v, ok := individualFields[r.URL.Path]; ok {
		_, _ = w.Write([]byte(v))
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func TestProbe_Success(t *testing.T) {
	srv := newTestServer(metadataHandler)
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected probe to succeed")
	}
}

func TestProbe_NotHetzner(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected probe to fail")
	}
}

func TestProbe_ConnectionError(t *testing.T) {
	c, err := New(
		WithBaseURL("http://127.0.0.1:1"),
		WithTimeout(100*time.Millisecond),
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
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err == nil {
		t.Fatal("expected error on 5xx response")
	}
	if ok {
		t.Fatal("expected probe to return false")
	}
}

func TestGetMetadataDocument(t *testing.T) {
	srv := newTestServer(metadataHandler)
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := c.GetMetadataDocument(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.InstanceID != 12345 {
		t.Errorf("instance ID = %d, want 12345", doc.InstanceID)
	}
	if doc.Hostname != "my-server" {
		t.Errorf("hostname = %q, want %q", doc.Hostname, "my-server")
	}
	if doc.Region != "eu-central" {
		t.Errorf("region = %q, want %q", doc.Region, "eu-central")
	}
	if doc.AvailabilityZone != "fsn1-dc14" {
		t.Errorf("zone = %q, want %q", doc.AvailabilityZone, "fsn1-dc14")
	}
	if doc.PublicIPv4 != "1.2.3.4" {
		t.Errorf("public ipv4 = %q, want %q", doc.PublicIPv4, "1.2.3.4")
	}
	if len(doc.PrivateNetworks) != 2 {
		t.Fatalf("private networks count = %d, want 2", len(doc.PrivateNetworks))
	}
}

func TestInstanceID(t *testing.T) {
	srv := newTestServer(metadataHandler)
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.InstanceID(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "12345" {
		t.Errorf("InstanceID = %q, want %q", id, "12345")
	}
}

func TestRegion(t *testing.T) {
	srv := newTestServer(metadataHandler)
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Region(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "eu-central" {
		t.Errorf("Region = %q, want %q", v, "eu-central")
	}
}

func TestZone(t *testing.T) {
	srv := newTestServer(metadataHandler)
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Zone(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "fsn1-dc14" {
		t.Errorf("Zone = %q, want %q", v, "fsn1-dc14")
	}
}

func TestHostname(t *testing.T) {
	srv := newTestServer(metadataHandler)
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Hostname(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "my-server" {
		t.Errorf("Hostname = %q, want %q", v, "my-server")
	}
}

func TestPublicIPv4(t *testing.T) {
	srv := newTestServer(metadataHandler)
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.PublicIPv4(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "1.2.3.4" {
		t.Errorf("PublicIPv4 = %q, want %q", v, "1.2.3.4")
	}
}

func TestGetMetadata(t *testing.T) {
	srv := newTestServer(metadataHandler)
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if md.Provider != ProviderID {
		t.Errorf("provider = %q, want %q", md.Provider, ProviderID)
	}
	if md.Instance.ID != "12345" {
		t.Errorf("instance ID = %q, want %q", md.Instance.ID, "12345")
	}
	if md.Instance.Hostname != "my-server" {
		t.Errorf("hostname = %q, want %q", md.Instance.Hostname, "my-server")
	}
	if md.Instance.Location.Region != "eu-central" {
		t.Errorf("region = %q, want %q", md.Instance.Location.Region, "eu-central")
	}
	if md.Instance.Location.Zone != "fsn1-dc14" {
		t.Errorf("zone = %q, want %q", md.Instance.Location.Zone, "fsn1-dc14")
	}
	if len(md.Interfaces) != 1 {
		t.Fatalf("interfaces count = %d, want 1", len(md.Interfaces))
	}
	iface := md.Interfaces[0]
	if len(iface.PublicIPv4s) != 1 || iface.PublicIPv4s[0] != "1.2.3.4" {
		t.Errorf("public ipv4s = %v", iface.PublicIPv4s)
	}
	if len(iface.PrivateIPv4s) != 2 {
		t.Errorf("private ipv4s = %v", iface.PrivateIPv4s)
	}
	keys, ok := md.AdditionalProperties["public-keys"].([]string)
	if !ok || len(keys) != 1 {
		t.Errorf("public-keys = %v", md.AdditionalProperties["public-keys"])
	}
}

func TestGetMetadata_ServerError(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetMetadata(t.Context())
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
}

func TestGetMetadata_InvalidYAML(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(":::invalid"))
	})
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetMetadata(t.Context())
	if err == nil {
		t.Fatal("expected error on invalid YAML")
	}
}

func TestGetMetadata_NoInterfaces(t *testing.T) {
	// Hetzner document with no public-ipv4 and no private-networks.
	// GetMetadata should leave md.Interfaces nil rather than emit a
	// 1-element slice containing an empty NetworkInterface (which
	// would produce noise in watchutil.DiffMetadata).
	noIfaceYAML := `instance-id: 99999
hostname: bare-server
region: eu-central
availability-zone: fsn1-dc14
`
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(noIfaceYAML))
	})
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if md.Interfaces != nil {
		t.Errorf("expected nil Interfaces when no IPs, got %v", md.Interfaces)
	}
	if md.Instance.ID != "99999" {
		t.Errorf("instance ID: got %q, want %q", md.Instance.ID, "99999")
	}
}

func TestWatch(t *testing.T) {
	callCount := 0
	srv := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		// Only the full metadata path is valid for this test; fail
		// any other path so a future code change that targets a
		// different endpoint surfaces as a test failure instead of
		// silently returning the stub YAML.
		if r.URL.Path != metadataPath {
			t.Errorf("TestWatch: unexpected request path %q, want %q", r.URL.Path, metadataPath)
			http.NotFound(w, r)
			return
		}
		callCount++
		if callCount == 1 {
			_, _ = w.Write([]byte(testYAML))
		} else {
			// Keep private-networks and public-keys identical to
			// testYAML so the only delta is the public-ipv4 change.
			// Otherwise a broken public-ipv4 → interface mapping
			// could still make this test pass via an
			// additional_properties diff.
			_, _ = w.Write([]byte(`instance-id: 12345
hostname: my-server
region: eu-central
availability-zone: fsn1-dc14
public-ipv4: 5.6.7.8
private-networks:
  - ip: 10.0.0.1
  - ip: 10.0.0.2
public-keys:
  - ssh-rsa AAAA...
`))
		}
	})
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	ch, err := c.Watch(ctx, imds.WatchConfig{Interval: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for ev := range ch {
		if ev.Err != nil {
			continue
		}
		// Skip the synthetic "everything changed" event PollWatch
		// emits when its initial fetch failed and a subsequent poll
		// then succeeded (DiffMetadata(nil, cur) reports all
		// watched fields as changed). We're interested in the real
		// public-ipv4 delta between call 1 and call 2+.
		if ev.Old == nil {
			continue
		}
		// Require "interfaces" specifically — the public-ipv4 delta
		// should surface as an interfaces change. A loose
		// len(Changed) > 0 check could be satisfied by noise in
		// other fields if the public-ipv4 → interface mapping ever
		// regressed.
		for _, f := range ev.Changed {
			if f == "interfaces" {
				cancel()
				return
			}
		}
	}
	t.Fatal("timed out waiting for interfaces change event")
}

func TestID(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if c.ID() != ProviderID {
		t.Errorf("ID() = %q, want %q", c.ID(), ProviderID)
	}
}

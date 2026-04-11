package doimds

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	imds "github.com/OrHayat/imds-go"
)

var _ imds.Provider = (*Client)(nil)

const sampleMetadataJSON = `{
	"droplet_id": 12345,
	"hostname": "test-droplet",
	"region": "nyc3",
	"tags": ["web", "prod"],
	"features": ["virtio", "metadata"],
	"floating_ip": {"active": true, "ipv4_address": "203.0.113.1"},
	"interfaces": {
		"public": [{"ipv4": {"ip_address": "192.0.2.10"}, "mac": "aa:bb:cc:dd:ee:ff"}],
		"private": [{"ipv4": {"ip_address": "10.132.0.2"}, "mac": "aa:bb:cc:dd:ee:ff"}]
	}
}`

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metadata/v1/id":
			w.Write([]byte("12345"))
		case "/metadata/v1/region":
			w.Write([]byte("nyc3"))
		case "/metadata/v1/hostname":
			w.Write([]byte("test-droplet"))
		case "/metadata/v1/tags":
			w.Write([]byte("web\nprod"))
		case "/metadata/v1.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(sampleMetadataJSON))
		default:
			http.NotFound(w, r)
		}
	}))
}

func newClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	// Use srv.Client() for tests: it's the standard httptest pattern,
	// wired directly to the fake server's transport. This avoids two
	// problems at once:
	//  1. http.DefaultClient honors ProxyFromEnvironment, which could
	//     route localhost requests through a proxy on runners with
	//     HTTP_PROXY set.
	//  2. doimds's default http.Client wraps a retrying transport
	//     (httputil/retry.go) that exhausts attempts on repeated 5xx
	//     and returns a *httputil.RetryError wrapping a *StatusError
	//     — not the single-shot *imds.MetadataError that
	//     TestGetMetadataError wants to assert. srv.Client() has no
	//     retry wrapper, so the 500 surfaces through send() and is
	//     translated into *imds.MetadataError.
	c, err := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
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

func TestProbe(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	c := newClient(t, srv)

	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected probe to succeed")
	}
}

func TestProbeNonNumeric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not-a-number"))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected probe to fail for non-numeric response")
	}
}

func TestProbeConnectionError(t *testing.T) {
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

func TestProbe404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := newClient(t, srv)

	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatalf("expected nil error for 404, got %v", err)
	}
	if ok {
		t.Fatal("expected probe to return false")
	}
}

func TestProbe500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newClient(t, srv)

	ok, err := c.Probe(t.Context())
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if ok {
		t.Fatal("expected probe to return false")
	}
}

func TestGetMetadata(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	c := newClient(t, srv)

	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if md.Provider != ProviderID {
		t.Errorf("provider: got %q, want %q", md.Provider, ProviderID)
	}
	if md.Instance.ID != "12345" {
		t.Errorf("instance ID: got %q, want %q", md.Instance.ID, "12345")
	}
	if md.Instance.Hostname != "test-droplet" {
		t.Errorf("hostname: got %q, want %q", md.Instance.Hostname, "test-droplet")
	}
	if md.Instance.Location.Region != "nyc3" {
		t.Errorf("region: got %q, want %q", md.Instance.Location.Region, "nyc3")
	}
	if len(md.Tags) != 2 || md.Tags["web"] != "web" || md.Tags["prod"] != "prod" {
		t.Errorf("tags: got %v", md.Tags)
	}
	if len(md.Interfaces) != 1 {
		t.Fatalf("interfaces: got %d, want 1", len(md.Interfaces))
	}
	iface := md.Interfaces[0]
	if len(iface.PublicIPv4s) != 1 || iface.PublicIPv4s[0] != "192.0.2.10" {
		t.Errorf("public IPs: got %v", iface.PublicIPv4s)
	}
	if len(iface.PrivateIPv4s) != 1 || iface.PrivateIPv4s[0] != "10.132.0.2" {
		t.Errorf("private IPs: got %v", iface.PrivateIPv4s)
	}
	if iface.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC: got %q", iface.MAC)
	}
	if features, ok := md.AdditionalProperties["features"]; !ok {
		t.Error("missing features in additional properties")
	} else if fs, ok := features.([]string); !ok || len(fs) != 2 {
		t.Errorf("features: got %v", features)
	}
	if _, ok := md.AdditionalProperties["floating_ip"]; !ok {
		t.Error("missing floating_ip in additional properties")
	}
}

func TestGetMetadataEmptyAdditionalProperties(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"droplet_id":1,"hostname":"h","region":"r","interfaces":{"public":[],"private":[]}}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if md.AdditionalProperties != nil {
		t.Errorf("expected nil AdditionalProperties, got %v", md.AdditionalProperties)
	}
}

func TestGetMetadataError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newClient(t, srv)

	_, err := c.GetMetadata(t.Context())
	if err == nil {
		t.Fatal("expected error")
	}
	var me *imds.MetadataError
	if !errors.As(err, &me) {
		t.Fatalf("expected MetadataError, got %T", err)
	}
	if me.StatusCode != 500 {
		t.Errorf("status: got %d, want 500", me.StatusCode)
	}
}

func TestQuery(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	c := newClient(t, srv)

	body, err := c.Query(t.Context(), "/metadata/v1/id")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "12345" {
		t.Errorf("got %q, want %q", body, "12345")
	}
}

func TestQuery404(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	c := newClient(t, srv)

	_, err := c.Query(t.Context(), "/metadata/v1/nonexistent")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestWatch(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		md := DropletDocument{
			DropletID: 12345,
			Hostname:  "test-droplet",
			Region:    "nyc3",
			Interfaces: DOInterfaces{
				Public: []DOInterface{{IPv4: DOIPv4{IPAddress: "192.0.2.10"}, MAC: "aa:bb:cc:dd:ee:ff"}},
			},
		}
		if calls > 2 {
			md.Tags = []string{"new-tag"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(md)
	}))
	defer srv.Close()
	c := newClient(t, srv)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	ch, err := c.Watch(ctx, imds.WatchConfig{Interval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	// Assert the watch loop actually detects the tag change in the
	// fetched doc. Two defensive filters:
	//   1. Skip events where ev.Old == nil. PollWatch does not emit a
	//      ChangeEvent after the very first successful fetch; ev.Old
	//      is nil only when the initial fetch failed and a subsequent
	//      poll then succeeds, at which point DiffMetadata(nil, cur)
	//      reports every watched field as changed — including "tags"
	//      — regardless of whether the tag set actually changed. A
	//      naive "Changed contains 'tags'" check would pass on that
	//      synthetic event.
	//   2. Assert the new tag is actually present in ev.New.Tags,
	//      not just that the Changed slice mentions "tags".
	var tagChangeSeen bool
	for ev := range ch {
		if ev.Err != nil {
			continue
		}
		if ev.Old == nil {
			continue
		}
		if _, ok := ev.New.Tags["new-tag"]; ok {
			tagChangeSeen = true
			cancel()
			break
		}
	}
	if !tagChangeSeen {
		t.Error("expected a tags change event with new-tag in ev.New.Tags")
	}
}

func TestGetDropletDocument(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	c := newClient(t, srv)

	doc, err := c.GetDropletDocument(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if doc.DropletID != 12345 {
		t.Errorf("droplet_id: got %d, want 12345", doc.DropletID)
	}
	if doc.Hostname != "test-droplet" {
		t.Errorf("hostname: got %q, want %q", doc.Hostname, "test-droplet")
	}
	if doc.Region != "nyc3" {
		t.Errorf("region: got %q, want %q", doc.Region, "nyc3")
	}
}

func TestDropletID(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	c := newClient(t, srv)

	id, err := c.DropletID(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if id != 12345 {
		t.Errorf("got %d, want 12345", id)
	}
}

func TestRegion(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	c := newClient(t, srv)

	region, err := c.Region(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if region != "nyc3" {
		t.Errorf("got %q, want %q", region, "nyc3")
	}
}

func TestHostname(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	c := newClient(t, srv)

	hostname, err := c.Hostname(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if hostname != "test-droplet" {
		t.Errorf("got %q, want %q", hostname, "test-droplet")
	}
}

func TestTags(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	c := newClient(t, srv)

	tags, err := c.Tags(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags["web"] != "web" || tags["prod"] != "prod" {
		t.Errorf("got %v, want {web:web, prod:prod}", tags)
	}
}

func TestBuildInterfacesMultiMAC(t *testing.T) {
	// VPC / anchor-IP droplets expose two physical NICs with distinct
	// MACs. buildInterfaces must surface them as two separate
	// NetworkInterface values rather than silently merging IPs across
	// MACs (which was the pre-fix behavior).
	in := DOInterfaces{
		Public: []DOInterface{
			{IPv4: DOIPv4{IPAddress: "192.0.2.10"}, MAC: "aa:bb:cc:dd:ee:01"},
			{IPv4: DOIPv4{IPAddress: "198.51.100.7"}, MAC: "aa:bb:cc:dd:ee:02"},
		},
		Private: []DOInterface{
			{IPv4: DOIPv4{IPAddress: "10.132.0.2"}, MAC: "aa:bb:cc:dd:ee:01"},
			{IPv4: DOIPv4{IPAddress: "10.132.0.3"}, MAC: "aa:bb:cc:dd:ee:02"},
		},
	}
	out := buildInterfaces(in)
	if len(out) != 2 {
		t.Fatalf("interfaces: got %d, want 2", len(out))
	}
	// Insertion order is public list first, so MAC :01 must come before
	// MAC :02.
	if out[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("out[0].MAC: got %q, want aa:bb:cc:dd:ee:01", out[0].MAC)
	}
	if len(out[0].PublicIPv4s) != 1 || out[0].PublicIPv4s[0] != "192.0.2.10" {
		t.Errorf("out[0].PublicIPv4s: got %v", out[0].PublicIPv4s)
	}
	if len(out[0].PrivateIPv4s) != 1 || out[0].PrivateIPv4s[0] != "10.132.0.2" {
		t.Errorf("out[0].PrivateIPv4s: got %v", out[0].PrivateIPv4s)
	}
	if out[1].MAC != "aa:bb:cc:dd:ee:02" {
		t.Errorf("out[1].MAC: got %q, want aa:bb:cc:dd:ee:02", out[1].MAC)
	}
	if len(out[1].PublicIPv4s) != 1 || out[1].PublicIPv4s[0] != "198.51.100.7" {
		t.Errorf("out[1].PublicIPv4s: got %v", out[1].PublicIPv4s)
	}
	if len(out[1].PrivateIPv4s) != 1 || out[1].PrivateIPv4s[0] != "10.132.0.3" {
		t.Errorf("out[1].PrivateIPv4s: got %v", out[1].PrivateIPv4s)
	}
}

func TestBuildInterfacesEmptyMAC(t *testing.T) {
	// Entries with an empty MAC are grouped into a single "unknown"
	// NetworkInterface with MAC="". Their IPs must not be dropped, and
	// they must not fan out into one NetworkInterface per empty-MAC
	// entry.
	in := DOInterfaces{
		Public: []DOInterface{
			{IPv4: DOIPv4{IPAddress: "192.0.2.10"}, MAC: ""},
		},
		Private: []DOInterface{
			{IPv4: DOIPv4{IPAddress: "10.132.0.2"}, MAC: ""},
			{IPv4: DOIPv4{IPAddress: "10.132.0.3"}, MAC: ""},
		},
	}
	out := buildInterfaces(in)
	if len(out) != 1 {
		t.Fatalf("interfaces: got %d, want 1", len(out))
	}
	if out[0].MAC != "" {
		t.Errorf("MAC: got %q, want empty", out[0].MAC)
	}
	if len(out[0].PublicIPv4s) != 1 || out[0].PublicIPv4s[0] != "192.0.2.10" {
		t.Errorf("PublicIPv4s: got %v", out[0].PublicIPv4s)
	}
	if len(out[0].PrivateIPv4s) != 2 ||
		out[0].PrivateIPv4s[0] != "10.132.0.2" ||
		out[0].PrivateIPv4s[1] != "10.132.0.3" {
		t.Errorf("PrivateIPv4s: got %v", out[0].PrivateIPv4s)
	}
}

func TestBuildInterfacesMixedEmptyAndNamedMAC(t *testing.T) {
	// Mixed case: one entry has a MAC, another has none. They must
	// remain separate (two NetworkInterface entries), and the empty-MAC
	// bucket must not absorb the named entry's IPs.
	in := DOInterfaces{
		Public: []DOInterface{
			{IPv4: DOIPv4{IPAddress: "192.0.2.10"}, MAC: "aa:bb:cc:dd:ee:01"},
			{IPv4: DOIPv4{IPAddress: "198.51.100.7"}, MAC: ""},
		},
	}
	out := buildInterfaces(in)
	if len(out) != 2 {
		t.Fatalf("interfaces: got %d, want 2", len(out))
	}
	if out[0].MAC != "aa:bb:cc:dd:ee:01" || len(out[0].PublicIPv4s) != 1 || out[0].PublicIPv4s[0] != "192.0.2.10" {
		t.Errorf("out[0]: %+v", out[0])
	}
	if out[1].MAC != "" || len(out[1].PublicIPv4s) != 1 || out[1].PublicIPv4s[0] != "198.51.100.7" {
		t.Errorf("out[1]: %+v", out[1])
	}
}

func TestInterfaces(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	c := newClient(t, srv)

	ifaces, err := c.Interfaces(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(ifaces) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(ifaces))
	}
	if len(ifaces[0].PublicIPv4s) != 1 || ifaces[0].PublicIPv4s[0] != "192.0.2.10" {
		t.Errorf("public IPs: got %v", ifaces[0].PublicIPv4s)
	}
	if len(ifaces[0].PrivateIPv4s) != 1 || ifaces[0].PrivateIPv4s[0] != "10.132.0.2" {
		t.Errorf("private IPs: got %v", ifaces[0].PrivateIPv4s)
	}
	if ifaces[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC: got %q", ifaces[0].MAC)
	}
}

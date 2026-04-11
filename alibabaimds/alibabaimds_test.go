package alibabaimds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	imds "github.com/OrHayat/imds-go"
)

var _ imds.Provider = (*Client)(nil)

func fakeServer(responses map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := responses[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprint(w, body)
	}))
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

func TestProbeSuccess(t *testing.T) {
	srv := fakeServer(map[string]string{
		"/latest/meta-data/instance-id": "i-abc123",
	})
	defer srv.Close()

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

func TestProbeFailure(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

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

func TestProbe5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err == nil {
		t.Fatal("expected error on 5xx")
	}
	if ok {
		t.Fatal("expected probe to fail")
	}
}

func TestProbeNetworkError(t *testing.T) {
	c, err := New(WithBaseURL("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err == nil {
		t.Fatal("expected error on network failure")
	}
	if ok {
		t.Fatal("expected probe to fail")
	}
}

func TestProbeEmptyBody(t *testing.T) {
	srv := fakeServer(map[string]string{
		"/latest/meta-data/instance-id": "",
	})
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected probe to fail on empty body")
	}
}

func TestGetMetadata(t *testing.T) {
	srv := fakeServer(map[string]string{
		"/latest/meta-data/instance-id":              "i-abc123",
		"/latest/meta-data/instance/instance-type":   "ecs.g6.large",
		"/latest/meta-data/image-id":                 "m-img001",
		"/latest/meta-data/region-id":                "cn-hangzhou",
		"/latest/meta-data/zone-id":                  "cn-hangzhou-b",
		"/latest/meta-data/hostname":                 "myhost",
		"/latest/meta-data/owner-account-id":         "123456789",
		"/latest/meta-data/serial-number":            "serial-001",
		"/latest/meta-data/private-ipv4":             "10.0.0.5",
		"/latest/meta-data/network/interfaces/macs/": "00:16:3e:aa:bb:cc/\n",
		"/latest/meta-data/network/interfaces/macs/00:16:3e:aa:bb:cc/primary-ip-address":   "10.0.0.5",
		"/latest/meta-data/network/interfaces/macs/00:16:3e:aa:bb:cc/public-ip-address":    "47.1.2.3",
		"/latest/meta-data/network/interfaces/macs/00:16:3e:aa:bb:cc/mac":                  "00:16:3e:aa:bb:cc",
		"/latest/meta-data/network/interfaces/macs/00:16:3e:aa:bb:cc/network-interface-id": "eni-001",
		"/latest/meta-data/network/interfaces/macs/00:16:3e:aa:bb:cc/vpc-id":               "vpc-001",
	})
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if md.Provider != ProviderID {
		t.Errorf("provider: got %q, want %q", md.Provider, ProviderID)
	}
	if md.Instance.ID != "i-abc123" {
		t.Errorf("instance id: got %q", md.Instance.ID)
	}
	if md.Instance.InstanceType != "ecs.g6.large" {
		t.Errorf("instance type: got %q", md.Instance.InstanceType)
	}
	if md.Instance.ImageID != "m-img001" {
		t.Errorf("image id: got %q", md.Instance.ImageID)
	}
	if md.Instance.Location.Region != "cn-hangzhou" {
		t.Errorf("region: got %q", md.Instance.Location.Region)
	}
	if md.Instance.Location.Zone != "cn-hangzhou-b" {
		t.Errorf("zone: got %q", md.Instance.Location.Zone)
	}
	if md.Instance.Hostname != "myhost" {
		t.Errorf("hostname: got %q", md.Instance.Hostname)
	}
	if md.Instance.AccountID != "123456789" {
		t.Errorf("account id: got %q", md.Instance.AccountID)
	}
	if md.AdditionalProperties["serial-number"] != "serial-001" {
		t.Errorf("serial-number: got %v", md.AdditionalProperties["serial-number"])
	}
	if md.AdditionalProperties["private-ipv4"] != "10.0.0.5" {
		t.Errorf("private-ipv4: got %v", md.AdditionalProperties["private-ipv4"])
	}

	if len(md.Interfaces) != 1 {
		t.Fatalf("interfaces: got %d, want 1", len(md.Interfaces))
	}
	iface := md.Interfaces[0]
	if iface.ID != "eni-001" {
		t.Errorf("interface id: got %q", iface.ID)
	}
	if iface.MAC != "00:16:3e:aa:bb:cc" {
		t.Errorf("mac: got %q", iface.MAC)
	}
	if iface.VPCID != "vpc-001" {
		t.Errorf("vpc id: got %q", iface.VPCID)
	}
	if len(iface.PrivateIPv4s) != 1 || iface.PrivateIPv4s[0] != "10.0.0.5" {
		t.Errorf("private ips: got %v", iface.PrivateIPv4s)
	}
	if len(iface.PublicIPv4s) != 1 || iface.PublicIPv4s[0] != "47.1.2.3" {
		t.Errorf("public ips: got %v", iface.PublicIPv4s)
	}
}

func TestQuery(t *testing.T) {
	srv := fakeServer(map[string]string{
		"/latest/meta-data/instance-id": "i-test",
	})
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	body, err := c.Query(t.Context(), "/latest/meta-data/instance-id")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "i-test" {
		t.Errorf("got %q, want %q", string(body), "i-test")
	}
}

func TestQueryError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Query(t.Context(), "/latest/meta-data/instance-id")
	if err == nil {
		t.Fatal("expected error")
	}
	var me *imds.MetadataError
	if !errors.As(err, &me) {
		t.Fatalf("expected *imds.MetadataError, got %T: %v", err, err)
	}
	if me.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", me.StatusCode)
	}
	if me.Path != "/latest/meta-data/instance-id" {
		t.Errorf("expected path /latest/meta-data/instance-id, got %q", me.Path)
	}
}

func TestGetMetadataInstanceIDError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetMetadata(t.Context())
	if err == nil {
		t.Fatal("expected error when instance-id fails")
	}
}

func TestGetMetadataSpot5xxTolerant(t *testing.T) {
	// Spot termination failures (including 5xx) should NOT fail the
	// whole GetMetadata call — they follow the same best-effort
	// contract as the other optional fields. SpotTerminating should
	// just stay at its zero value (false).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest/meta-data/instance/spot/termination-time" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/latest/meta-data/instance-id" {
			_, _ = fmt.Fprint(w, "i-abc123")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatalf("spot 5xx should be tolerated, got error: %v", err)
	}
	if md.SpotTerminating {
		t.Fatal("expected SpotTerminating = false when endpoint 500s")
	}
}

func TestGetMetadataSpotTerminating(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/meta-data/instance-id":
			_, _ = fmt.Fprint(w, "i-spot1")
		case "/latest/meta-data/instance/spot/termination-time":
			_, _ = fmt.Fprint(w, "2026-04-11T12:00:00Z")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !md.SpotTerminating {
		t.Fatal("expected SpotTerminating = true")
	}
}

func TestGetMetadataNoAdditionalProperties(t *testing.T) {
	srv := fakeServer(map[string]string{
		"/latest/meta-data/instance-id": "i-abc123",
	})
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if md.AdditionalProperties != nil {
		t.Errorf("expected nil AdditionalProperties, got %v", md.AdditionalProperties)
	}
}

func TestWatch(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest/meta-data/instance-id" {
			_, _ = fmt.Fprint(w, "i-watch")
			return
		}
		if r.URL.Path == "/latest/meta-data/serial-number" {
			callCount++
			_, _ = fmt.Fprintf(w, "serial-%d", callCount)
			return
		}
		if r.URL.Path == "/latest/meta-data/network/interfaces/macs/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprint(w, "static")
	}))
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	ch, err := c.Watch(ctx, imds.WatchConfig{Interval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	ev := <-ch
	if ev.Err != nil {
		t.Fatalf("unexpected error event: %v", ev.Err)
	}
	if len(ev.Changed) == 0 {
		t.Fatal("expected changed fields")
	}
}

func TestWithHTTPClient(t *testing.T) {
	srv := fakeServer(map[string]string{
		"/latest/meta-data/instance-id": "i-custom",
	})
	defer srv.Close()

	custom := &http.Client{Timeout: 5 * time.Second}
	c, err := New(WithBaseURL(srv.URL), WithHTTPClient(custom))
	if err != nil {
		t.Fatal(err)
	}
	body, err := c.Query(t.Context(), "/latest/meta-data/instance-id")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "i-custom" {
		t.Errorf("got %q", string(body))
	}
}

package ibmimds

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	imds "github.com/OrHayat/imds-go"
)

var _ imds.Provider = (*Client)(nil)

func newFakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/instance_identity/v1/token":
			if r.Header.Get("Metadata-Flavor") != "ibm" {
				http.Error(w, "missing flavor", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "test-token"})

		case r.Method == http.MethodGet && r.URL.Path == "/metadata/v1/instance":
			if r.Header.Get("Authorization") != "Bearer test-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(InstanceDocument{
				ID:   "i-123",
				Name: "my-instance",
				CRN:  "crn:v1:bluemix:public:is:us-south-1:a/acc123::instance:i-123",
				Profile: struct {
					Name string `json:"name"`
				}{Name: "bx2-2x8"},
				Zone: struct {
					Name string `json:"name"`
				}{Name: "us-south-1"},
				Image: struct {
					ID string `json:"id"`
				}{ID: "img-456"},
				VPC: struct {
					ID string `json:"id"`
				}{ID: "vpc-789"},
				ResourceGroup: struct {
					ID string `json:"id"`
				}{ID: "rg-abc"},
				PrimaryNetworkInterface: NetworkInterfaceResponse{
					ID:          "nic-1",
					Name:        "eth0",
					PrimaryIPv4: "10.0.0.5",
					FloatingIP: &struct {
						Address string `json:"address"`
					}{Address: "52.1.2.3"},
					Subnet: struct {
						ID string `json:"id"`
					}{ID: "subnet-1"},
				},
				NetworkInterfaces: []NetworkInterfaceResponse{
					{
						ID:          "nic-1",
						Name:        "eth0",
						PrimaryIPv4: "10.0.0.5",
						Subnet: struct {
							ID string `json:"id"`
						}{ID: "subnet-1"},
					},
					{
						ID:          "nic-2",
						Name:        "eth1",
						PrimaryIPv4: "10.0.1.5",
						Subnet: struct {
							ID string `json:"id"`
						}{ID: "subnet-2"},
					},
				},
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func TestProbeSuccess(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	c, err := New(imds.WithBaseURL(srv.URL), imds.WithHTTPClient(srv.Client()))
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

func TestProbeNotIBM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	c, err := New(imds.WithBaseURL(srv.URL), imds.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatalf("4xx should return false, nil; got %v", err)
	}
	if ok {
		t.Fatal("expected probe to return false")
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	// Bind to an ephemeral port and close the listener before probing.
	// The OS guarantees a connection attempt to that address is refused,
	// independent of whatever happens to be listening on well-known
	// ports in the environment.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	c, err := New(imds.WithBaseURL("http://"+addr), imds.WithHTTPClient(&http.Client{Timeout: time.Second}))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	// Transport failures surface as errors so Detect() error
	// aggregation can explain why a probe sequence didn't converge.
	if err == nil {
		t.Fatal("expected error on connection refused")
	}
	if ok {
		t.Fatal("expected probe to return false on connection refused")
	}
}

func TestGetMetadata(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	c, err := New(imds.WithBaseURL(srv.URL), imds.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if m.Provider != ProviderID {
		t.Errorf("provider = %q, want %q", m.Provider, ProviderID)
	}
	if m.Instance.ID != "i-123" {
		t.Errorf("id = %q, want %q", m.Instance.ID, "i-123")
	}
	if m.Instance.Hostname != "my-instance" {
		t.Errorf("hostname = %q, want %q", m.Instance.Hostname, "my-instance")
	}
	if m.Instance.InstanceType != "bx2-2x8" {
		t.Errorf("instance_type = %q, want %q", m.Instance.InstanceType, "bx2-2x8")
	}
	if m.Instance.ImageID != "img-456" {
		t.Errorf("image_id = %q, want %q", m.Instance.ImageID, "img-456")
	}
	if m.Instance.Location.Zone != "us-south-1" {
		t.Errorf("zone = %q, want %q", m.Instance.Location.Zone, "us-south-1")
	}
	if m.Instance.Location.Region != "us-south" {
		t.Errorf("region = %q, want %q", m.Instance.Location.Region, "us-south")
	}

	if len(m.Interfaces) != 2 {
		t.Fatalf("interfaces len = %d, want 2", len(m.Interfaces))
	}
	if m.Interfaces[0].PrivateIPv4s[0] != "10.0.0.5" {
		t.Errorf("private ip = %q", m.Interfaces[0].PrivateIPv4s[0])
	}
	if m.Interfaces[0].PublicIPv4s[0] != "52.1.2.3" {
		t.Errorf("public ip = %q", m.Interfaces[0].PublicIPv4s[0])
	}
	if m.Interfaces[1].ID != "nic-2" {
		t.Errorf("second nic id = %q", m.Interfaces[1].ID)
	}

	if m.AdditionalProperties["vpc_id"] != "vpc-789" {
		t.Errorf("vpc_id = %v", m.AdditionalProperties["vpc_id"])
	}
	if m.AdditionalProperties["resource_group_id"] != "rg-abc" {
		t.Errorf("resource_group_id = %v", m.AdditionalProperties["resource_group_id"])
	}
}

func TestTokenCaching(t *testing.T) {
	var tokenCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/instance_identity/v1/token":
			tokenCalls.Add(1)
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "cached-token"})
		case r.Method == http.MethodGet && r.URL.Path == "/metadata/v1/instance":
			_ = json.NewEncoder(w).Encode(InstanceDocument{ID: "i-1", Zone: struct {
				Name string `json:"name"`
			}{Name: "us-south-1"}})
		}
	}))
	defer srv.Close()

	c, err := New(imds.WithBaseURL(srv.URL), imds.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}

	for range 3 {
		if _, err := c.GetMetadata(t.Context()); err != nil {
			t.Fatal(err)
		}
	}

	if n := tokenCalls.Load(); n != 1 {
		t.Errorf("token fetched %d times, want 1", n)
	}
}

func TestGetMetadataUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/instance_identity/v1/token":
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "bad-token"})
		case r.Method == http.MethodGet && r.URL.Path == "/metadata/v1/instance":
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	c, err := New(imds.WithBaseURL(srv.URL), imds.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetMetadata(t.Context())
	if err == nil {
		t.Fatal("expected error")
	}
	var me *imds.MetadataError
	if !errors.As(err, &me) {
		t.Fatalf("expected MetadataError, got %T", err)
	}
	if me.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", me.StatusCode)
	}
}

func TestWatch(t *testing.T) {
	callCount := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/instance_identity/v1/token":
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "tok"})
		case r.Method == http.MethodGet && r.URL.Path == "/metadata/v1/instance":
			n := callCount.Add(1)
			resp := InstanceDocument{
				ID:   "i-1",
				Name: "host-1",
				Zone: struct {
					Name string `json:"name"`
				}{Name: "us-south-1"},
			}
			if n > 1 {
				resp.PrimaryNetworkInterface = NetworkInterfaceResponse{
					ID:          "nic-new",
					Name:        "eth0",
					PrimaryIPv4: "10.0.0.99",
					Subnet: struct {
						ID string `json:"id"`
					}{ID: "subnet-1"},
				}
			}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer srv.Close()

	c, err := New(imds.WithBaseURL(srv.URL), imds.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	ch, err := c.Watch(ctx, imds.WatchConfig{Interval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	ev := <-ch
	if ev.Err != nil {
		t.Fatal(ev.Err)
	}
	if len(ev.Changed) == 0 {
		t.Fatal("expected changed fields")
	}
}

func TestID(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if c.ID() != "ibm" {
		t.Errorf("ID() = %q, want %q", c.ID(), "ibm")
	}
}

func TestParseRegion(t *testing.T) {
	tests := []struct {
		zone, want string
	}{
		{"us-south-1", "us-south"},
		{"eu-de-2", "eu-de"},
		{"jp-tok-3", "jp-tok"},
		{"single", "single"},
	}
	for _, tt := range tests {
		if got := parseRegion(tt.zone); got != tt.want {
			t.Errorf("parseRegion(%q) = %q, want %q", tt.zone, got, tt.want)
		}
	}
}

package ociimds

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

func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	return srv, c
}

func TestID(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if c.ID() != "oci" {
		t.Fatalf("got %q, want %q", c.ID(), "oci")
	}
}

func TestProbeSuccess(t *testing.T) {
	srv, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != basePath+"instance/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer Oracle" {
			t.Errorf("missing auth header")
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected probe to succeed")
	}
}

func TestProbeFailure(t *testing.T) {
	srv, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer srv.Close()

	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected probe to fail")
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	// Bind to an ephemeral port and close the listener before probing.
	// The OS guarantees a connection attempt to that address is refused,
	// independent of whatever happens to be listening on well-known ports.
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
		WithTimeout(500*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Probe(t.Context())
	if err == nil {
		t.Fatal("expected error on connection refused")
	}
	if ok {
		t.Fatal("expected probe to return false")
	}
}

func TestProbeServerError(t *testing.T) {
	srv, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	ok, err := c.Probe(t.Context())
	if err == nil {
		t.Fatal("expected error on 5xx")
	}
	if ok {
		t.Fatal("expected probe to return false")
	}
}

var testInstance = InstanceDocument{
	ID:                 "ocid1.instance.oc1.test",
	Shape:              "VM.Standard.E4.Flex",
	Region:             "us-ashburn-1",
	AvailabilityDomain: "AD-1",
	ImageID:            "ocid1.image.oc1.test",
	CompartmentID:      "ocid1.compartment.oc1.test",
	Hostname:           "test-host",
	DisplayName:        "my-instance",
	FaultDomain:        "FAULT-DOMAIN-1",
	FreeformTags:       map[string]string{"env": "test"},
}

var testVnics = []VNIC{
	{
		VnicID:           "ocid1.vnic.oc1.test",
		PrivateIP:        "10.0.0.5",
		PublicIP:         "129.213.1.1",
		MACAddress:       "00:00:17:01:AB:CD",
		SubnetCIDRBlock:  "10.0.0.0/24",
		VirtualNetworkID: "ocid1.vcn.oc1.test",
	},
}

func metadataHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer Oracle" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case basePath + "instance/":
			_ = json.NewEncoder(w).Encode(testInstance)
		case basePath + "instance/id":
			w.Write([]byte(testInstance.ID))
		case basePath + "instance/region":
			w.Write([]byte(testInstance.Region))
		case basePath + "instance/availabilityDomain":
			w.Write([]byte(testInstance.AvailabilityDomain))
		case basePath + "instance/shape":
			w.Write([]byte(testInstance.Shape))
		case basePath + "instance/imageId":
			w.Write([]byte(testInstance.ImageID))
		case basePath + "instance/compartmentId":
			w.Write([]byte(testInstance.CompartmentID))
		case basePath + "instance/hostname":
			w.Write([]byte(testInstance.Hostname))
		case basePath + "instance/freeformTags":
			_ = json.NewEncoder(w).Encode(testInstance.FreeformTags)
		case basePath + "vnics/":
			_ = json.NewEncoder(w).Encode(testVnics)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestGetMetadata(t *testing.T) {
	srv, c := newTestServer(t, metadataHandler(t))
	defer srv.Close()

	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if md.Provider != ProviderID {
		t.Errorf("provider: got %q, want %q", md.Provider, ProviderID)
	}
	if md.Instance.ID != testInstance.ID {
		t.Errorf("instance ID: got %q, want %q", md.Instance.ID, testInstance.ID)
	}
	if md.Instance.InstanceType != testInstance.Shape {
		t.Errorf("instance type: got %q, want %q", md.Instance.InstanceType, testInstance.Shape)
	}
	if md.Instance.Location.Region != testInstance.Region {
		t.Errorf("region: got %q, want %q", md.Instance.Location.Region, testInstance.Region)
	}
	if md.Instance.Location.Zone != testInstance.AvailabilityDomain {
		t.Errorf("zone: got %q, want %q", md.Instance.Location.Zone, testInstance.AvailabilityDomain)
	}
	if md.Instance.ImageID != testInstance.ImageID {
		t.Errorf("image ID: got %q, want %q", md.Instance.ImageID, testInstance.ImageID)
	}
	if md.Instance.AccountID != testInstance.CompartmentID {
		t.Errorf("account ID: got %q, want %q", md.Instance.AccountID, testInstance.CompartmentID)
	}
	if md.Instance.Hostname != testInstance.Hostname {
		t.Errorf("hostname: got %q, want %q", md.Instance.Hostname, testInstance.Hostname)
	}
	if md.Tags["env"] != "test" {
		t.Errorf("tags: got %v, want env=test", md.Tags)
	}
	if md.AdditionalProperties["displayName"] != testInstance.DisplayName {
		t.Errorf("displayName: got %v", md.AdditionalProperties["displayName"])
	}
	if md.Instance.Location.FaultDomain != testInstance.FaultDomain {
		t.Errorf("faultDomain: got %q, want %q", md.Instance.Location.FaultDomain, testInstance.FaultDomain)
	}

	if len(md.Interfaces) != 1 {
		t.Fatalf("interfaces: got %d, want 1", len(md.Interfaces))
	}
	iface := md.Interfaces[0]
	if iface.ID != testVnics[0].VnicID {
		t.Errorf("vnic ID: got %q, want %q", iface.ID, testVnics[0].VnicID)
	}
	if iface.MAC != testVnics[0].MACAddress {
		t.Errorf("mac: got %q, want %q", iface.MAC, testVnics[0].MACAddress)
	}
	if len(iface.PrivateIPv4s) != 1 || iface.PrivateIPv4s[0] != testVnics[0].PrivateIP {
		t.Errorf("private IP: got %v", iface.PrivateIPv4s)
	}
	if len(iface.PublicIPv4s) != 1 || iface.PublicIPv4s[0] != testVnics[0].PublicIP {
		t.Errorf("public IP: got %v", iface.PublicIPv4s)
	}
	if iface.VPCID != testVnics[0].VirtualNetworkID {
		t.Errorf("VPC ID: got %q, want %q", iface.VPCID, testVnics[0].VirtualNetworkID)
	}
	if iface.SubnetID != testVnics[0].SubnetCIDRBlock {
		t.Errorf("subnet ID: got %q, want %q", iface.SubnetID, testVnics[0].SubnetCIDRBlock)
	}
}

func TestQuery(t *testing.T) {
	srv, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == basePath+"instance/metadata/" {
			w.Write([]byte(`{"userdata":"hello"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	})
	defer srv.Close()

	data, err := c.Query(t.Context(), "instance/metadata/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != `{"userdata":"hello"}` {
		t.Errorf("got %q", data)
	}

	_, err = c.Query(t.Context(), "nonexistent/")
	if err == nil {
		t.Fatal("expected error for 404")
	}
	var me *imds.MetadataError
	if !errors.As(err, &me) {
		t.Fatalf("expected MetadataError, got %T", err)
	}
	if me.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", me.StatusCode)
	}
}

func TestAccessors(t *testing.T) {
	srv, c := newTestServer(t, metadataHandler(t))
	defer srv.Close()

	ctx := t.Context()

	id, err := c.InstanceID(ctx)
	if err != nil {
		t.Fatalf("InstanceID: %v", err)
	}
	if id != testInstance.ID {
		t.Errorf("InstanceID: got %q, want %q", id, testInstance.ID)
	}

	region, err := c.Region(ctx)
	if err != nil {
		t.Fatalf("Region: %v", err)
	}
	if region != testInstance.Region {
		t.Errorf("Region: got %q, want %q", region, testInstance.Region)
	}

	zone, err := c.Zone(ctx)
	if err != nil {
		t.Fatalf("Zone: %v", err)
	}
	if zone != testInstance.AvailabilityDomain {
		t.Errorf("Zone: got %q, want %q", zone, testInstance.AvailabilityDomain)
	}

	shape, err := c.Shape(ctx)
	if err != nil {
		t.Fatalf("Shape: %v", err)
	}
	if shape != testInstance.Shape {
		t.Errorf("Shape: got %q, want %q", shape, testInstance.Shape)
	}

	imageID, err := c.ImageID(ctx)
	if err != nil {
		t.Fatalf("ImageID: %v", err)
	}
	if imageID != testInstance.ImageID {
		t.Errorf("ImageID: got %q, want %q", imageID, testInstance.ImageID)
	}

	compartmentID, err := c.CompartmentID(ctx)
	if err != nil {
		t.Fatalf("CompartmentID: %v", err)
	}
	if compartmentID != testInstance.CompartmentID {
		t.Errorf("CompartmentID: got %q, want %q", compartmentID, testInstance.CompartmentID)
	}

	hostname, err := c.Hostname(ctx)
	if err != nil {
		t.Fatalf("Hostname: %v", err)
	}
	if hostname != testInstance.Hostname {
		t.Errorf("Hostname: got %q, want %q", hostname, testInstance.Hostname)
	}

	tags, err := c.Tags(ctx)
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if tags["env"] != "test" {
		t.Errorf("Tags: got %v, want env=test", tags)
	}
}

func TestGetMetadataServerError(t *testing.T) {
	srv, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer srv.Close()

	_, err := c.GetMetadata(t.Context())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestWatch(t *testing.T) {
	instanceCalls := 0
	srv, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer Oracle" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case basePath + "instance/":
			inst := testInstance
			if instanceCalls > 0 {
				inst.FreeformTags = map[string]string{"env": "prod"}
			}
			instanceCalls++
			_ = json.NewEncoder(w).Encode(inst)
		case basePath + "vnics/":
			_ = json.NewEncoder(w).Encode(testVnics)
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	ch, err := c.Watch(ctx, imds.WatchConfig{Interval: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case ev := <-ch:
		if ev.Err != nil {
			t.Fatalf("unexpected error event: %v", ev.Err)
		}
		if ev.New == nil {
			t.Fatal("expected new metadata")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for watch event")
	}
}

func TestEndpointModes(t *testing.T) {
	c4, err := New(WithEndpointMode(EndpointModeIPv4))
	if err != nil {
		t.Fatal(err)
	}
	if c4.baseURL != defaultIPv4 {
		t.Errorf("IPv4: got %q, want %q", c4.baseURL, defaultIPv4)
	}

	c6, err := New(WithEndpointMode(EndpointModeIPv6))
	if err != nil {
		t.Fatal(err)
	}
	if c6.baseURL != defaultIPv6 {
		t.Errorf("IPv6: got %q, want %q", c6.baseURL, defaultIPv6)
	}

	custom, err := New(WithBaseURL("http://custom:8080"))
	if err != nil {
		t.Fatal(err)
	}
	if custom.baseURL != "http://custom:8080" {
		t.Errorf("custom: got %q", custom.baseURL)
	}

	trailing, err := New(WithBaseURL("http://custom:8080/"))
	if err != nil {
		t.Fatal(err)
	}
	if trailing.baseURL != "http://custom:8080" {
		t.Errorf("trailing slash: got %q, want %q", trailing.baseURL, "http://custom:8080")
	}
}

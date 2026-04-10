package awsimds

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"

	imdspkg "github.com/OrHayat/imds-go"
)

var _ imdspkg.Provider = (*Client)(nil)

func fakeIMDS(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

const testToken = "test-token-value"

// imdsHandler handles the IMDSv2 token flow and routes metadata requests.
func imdsHandler(routes map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// IMDSv2 token endpoint
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(testToken))
			return
		}
		if v, ok := routes[r.URL.Path]; ok {
			w.Write([]byte(v))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

func fullRoutes() map[string]string {
	identityDoc, _ := json.Marshal(map[string]any{
		"instanceId":       "i-abc123",
		"instanceType":     "t3.micro",
		"imageId":          "ami-deadbeef",
		"region":           "us-east-1",
		"availabilityZone": "us-east-1a",
		"accountId":        "123456789012",
		"privateIp":        "10.0.0.1",
		"architecture":     "x86_64",
	})

	return map[string]string{
		"/latest/meta-data/instance-id":        "i-abc123",
		"/latest/meta-data/hostname":           "ip-10-0-0-1.ec2.internal",
		"/latest/meta-data/placement/partition-number": "2",
		"/latest/meta-data/spot/termination-time":      "2026-04-08T12:00:00Z",
		"/latest/meta-data/network/interfaces/macs/":   "0a:1b:2c:3d:4e:5f/\n",
		"/latest/meta-data/network/interfaces/macs/0a:1b:2c:3d:4e:5f/interface-id":  "eni-abc123",
		"/latest/meta-data/network/interfaces/macs/0a:1b:2c:3d:4e:5f/local-ipv4s":   "10.0.0.1",
		"/latest/meta-data/network/interfaces/macs/0a:1b:2c:3d:4e:5f/public-ipv4s":  "54.1.2.3",
		"/latest/meta-data/network/interfaces/macs/0a:1b:2c:3d:4e:5f/ipv6s":         "2600:1f18::1",
		"/latest/meta-data/network/interfaces/macs/0a:1b:2c:3d:4e:5f/subnet-id":     "subnet-abc",
		"/latest/meta-data/network/interfaces/macs/0a:1b:2c:3d:4e:5f/vpc-id":        "vpc-xyz",
		"/latest/meta-data/tags/instance/":     "Name\nEnv\n",
		"/latest/meta-data/tags/instance/Name": "my-instance",
		"/latest/meta-data/tags/instance/Env":  "prod",
		"/latest/meta-data/events/maintenance/scheduled": `[{"Code":"system-reboot","State":"active","NotBefore":"2026-04-10T00:00:00Z","Description":"scheduled reboot"}]`,
		"/latest/dynamic/instance-identity/document": string(identityDoc),
	}
}

func newTestClient(t *testing.T, routes map[string]string) *Client {
	t.Helper()
	ts := fakeIMDS(t, imdsHandler(routes))
	return New(imds.Options{}, func(o *imds.Options) {
		o.Endpoint = ts.URL
	})
}

func TestProbeSuccess(t *testing.T) {
	c := newTestClient(t, fullRoutes())
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected probe to succeed")
	}
}

func TestProbeFailure(t *testing.T) {
	ts := fakeIMDS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	c := New(imds.Options{}, func(o *imds.Options) {
		o.Endpoint = ts.URL
	})
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected probe to fail")
	}
}

func TestGetMetadata(t *testing.T) {
	c := newTestClient(t, fullRoutes())

	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if md.Provider != ProviderID {
		t.Fatalf("provider = %q", md.Provider)
	}
	if md.Instance.ID != "i-abc123" {
		t.Fatalf("instance id = %q", md.Instance.ID)
	}
	if md.Instance.InstanceType != "t3.micro" {
		t.Fatalf("instance type = %q", md.Instance.InstanceType)
	}
	if md.Instance.ImageID != "ami-deadbeef" {
		t.Fatalf("image id = %q", md.Instance.ImageID)
	}
	if md.Instance.Location.Region != "us-east-1" {
		t.Fatalf("region = %q", md.Instance.Location.Region)
	}
	if md.Instance.Location.Zone != "us-east-1a" {
		t.Fatalf("zone = %q", md.Instance.Location.Zone)
	}
	if md.Instance.Hostname != "ip-10-0-0-1.ec2.internal" {
		t.Fatalf("hostname = %q", md.Instance.Hostname)
	}
	if md.Instance.AccountID != "123456789012" {
		t.Fatalf("account id = %q", md.Instance.AccountID)
	}

	if len(md.Interfaces) != 1 {
		t.Fatalf("interfaces = %d", len(md.Interfaces))
	}
	iface := md.Interfaces[0]
	if iface.MAC != "0a:1b:2c:3d:4e:5f" {
		t.Fatalf("mac = %q", iface.MAC)
	}
	if len(iface.PrivateIPv4s) != 1 || iface.PrivateIPv4s[0] != "10.0.0.1" {
		t.Fatalf("private ips = %v", iface.PrivateIPv4s)
	}
	if iface.SubnetID != "subnet-abc" {
		t.Fatalf("subnet = %q", iface.SubnetID)
	}

	if md.Tags["Name"] != "my-instance" {
		t.Fatalf("tag Name = %q", md.Tags["Name"])
	}
	if md.Tags["Env"] != "prod" {
		t.Fatalf("tag Env = %q", md.Tags["Env"])
	}

	if md.Instance.Architecture != "amd64" {
		t.Fatalf("architecture = %q, want amd64", md.Instance.Architecture)
	}
	if md.Instance.Location.FaultDomain != "2" {
		t.Fatalf("fault domain = %q, want 2", md.Instance.Location.FaultDomain)
	}
	if !md.SpotTerminating {
		t.Fatal("expected SpotTerminating = true")
	}
	if len(md.MaintenanceEvents) != 1 {
		t.Fatalf("maintenance events = %d, want 1", len(md.MaintenanceEvents))
	}
	if md.MaintenanceEvents[0].Type != imdspkg.EventTypeReboot {
		t.Fatalf("event type = %q", md.MaintenanceEvents[0].Type)
	}
	if md.MaintenanceEvents[0].ProviderType != "system-reboot" {
		t.Fatalf("event provider type = %q", md.MaintenanceEvents[0].ProviderType)
	}
	if md.MaintenanceEvents[0].Status != imdspkg.EventStatusStarted {
		t.Fatalf("event status = %q", md.MaintenanceEvents[0].Status)
	}

	if iface.ID != "eni-abc123" {
		t.Fatalf("interface id = %q", iface.ID)
	}
	if iface.VPCID != "vpc-xyz" {
		t.Fatalf("vpc = %q", iface.VPCID)
	}
	if len(iface.PublicIPv4s) != 1 || iface.PublicIPv4s[0] != "54.1.2.3" {
		t.Fatalf("public ips = %v", iface.PublicIPv4s)
	}
	if len(iface.IPv6s) != 1 || iface.IPv6s[0] != "2600:1f18::1" {
		t.Fatalf("ipv6s = %v", iface.IPv6s)
	}
}

func TestGetIdentityDocument(t *testing.T) {
	c := newTestClient(t, fullRoutes())
	doc, err := c.GetIdentityDocument(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if doc.InstanceID != "i-abc123" {
		t.Fatalf("instance id = %q", doc.InstanceID)
	}
	if doc.Region != "us-east-1" {
		t.Fatalf("region = %q", doc.Region)
	}
	if doc.AccountID != "123456789012" {
		t.Fatalf("account id = %q", doc.AccountID)
	}
}

func TestQuery(t *testing.T) {
	c := newTestClient(t, fullRoutes())
	b, err := c.Query(t.Context(), "instance-id")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "i-abc123" {
		t.Fatalf("query = %q", string(b))
	}
}

func TestWatch(t *testing.T) {
	var callCount atomic.Int32
	routes := fullRoutes()

	ts := fakeIMDS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			w.Write([]byte(testToken))
			return
		}
		if r.URL.Path == "/latest/meta-data/tags/instance/" {
			n := callCount.Add(1)
			if n <= 1 {
				w.Write([]byte("Name\n"))
			} else {
				w.Write([]byte("Name\nNewTag\n"))
			}
			return
		}
		if r.URL.Path == "/latest/meta-data/tags/instance/NewTag" {
			w.Write([]byte("new-value"))
			return
		}
		if v, ok := routes[r.URL.Path]; ok {
			w.Write([]byte(v))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	c := New(imds.Options{}, func(o *imds.Options) {
		o.Endpoint = ts.URL
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	ch, err := c.Watch(ctx, imdspkg.WatchConfig{Interval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	got := false
	for ev := range ch {
		if ev.Err != nil {
			continue
		}
		if len(ev.Changed) > 0 {
			got = true
			cancel()
		}
	}
	if !got {
		t.Fatal("expected at least one change event")
	}
}

func TestID(t *testing.T) {
	c := New(imds.Options{})
	if c.ID() != ProviderID {
		t.Fatalf("id = %q", c.ID())
	}
}

func TestQuery404(t *testing.T) {
	c := newTestClient(t, fullRoutes())
	_, err := c.Query(t.Context(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for 404 path")
	}
}

func TestSpotTerminating(t *testing.T) {
	c := newTestClient(t, fullRoutes())
	spot, err := c.SpotTerminating(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !spot {
		t.Fatal("expected spot terminating")
	}
}

func TestSpotNotTerminating(t *testing.T) {
	routes := fullRoutes()
	delete(routes, "/latest/meta-data/spot/termination-time")
	c := newTestClient(t, routes)
	spot, err := c.SpotTerminating(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if spot {
		t.Fatal("expected not spot terminating")
	}
}

func TestMaintenanceEvents(t *testing.T) {
	c := newTestClient(t, fullRoutes())
	events, err := c.MaintenanceEvents(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d", len(events))
	}
	if events[0].Type != imdspkg.EventTypeReboot {
		t.Fatalf("type = %q", events[0].Type)
	}
	if events[0].ProviderType != "system-reboot" {
		t.Fatalf("provider type = %q", events[0].ProviderType)
	}
}

func TestMaintenanceEventsNone(t *testing.T) {
	routes := fullRoutes()
	delete(routes, "/latest/meta-data/events/maintenance/scheduled")
	c := newTestClient(t, routes)
	_, err := c.MaintenanceEvents(t.Context())
	if err == nil {
		t.Fatal("expected error when no maintenance events endpoint")
	}
}

func TestRegion(t *testing.T) {
	c := newTestClient(t, fullRoutes())
	region, err := c.Region(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if region != "us-east-1" {
		t.Fatalf("region = %q", region)
	}
}

func TestGetMetadataNoTags(t *testing.T) {
	routes := fullRoutes()
	delete(routes, "/latest/meta-data/tags/instance/")
	c := newTestClient(t, routes)
	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if md.Tags != nil {
		t.Fatalf("expected nil tags, got %v", md.Tags)
	}
}

func TestGetMetadataNoFaultDomain(t *testing.T) {
	routes := fullRoutes()
	delete(routes, "/latest/meta-data/placement/partition-number")
	c := newTestClient(t, routes)
	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if md.Instance.Location.FaultDomain != "" {
		t.Fatalf("expected empty fault domain, got %q", md.Instance.Location.FaultDomain)
	}
}

package azureimds

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

func fakeResponse() InstanceDocument {
	return InstanceDocument{
		Compute: Compute{
			VMID:                 "vm-123",
			Location:             "eastus",
			Zone:                 "1",
			VMSize:               "Standard_D2s_v3",
			SubscriptionID:       "sub-456",
			Name:                 "my-vm",
			PlatformFaultDomain:  "0",
			PlatformUpdateDomain: "0",
			ResourceGroupName:    "my-rg",
			VMScaleSetName:       "my-vmss",
			StorageProfile: Storage{
				ImageReference: ImageRef{
					Offer:   "UbuntuServer",
					SKU:     "18.04-LTS",
					Version: "latest",
				},
			},
			TagsList: []Tag{
				{Name: "env", Value: "prod"},
			},
		},
		Network: Network{
			Interfaces: []Interface{
				{
					MACAddress: "00:0D:3A:12:34:56",
					IPv4: IPFamily{
						IPAddress: []IPAddress{
							{PrivateIPAddress: "10.0.0.4", PublicIPAddress: "52.1.2.3"},
						},
						Subnet: []Subnet{
							{Address: "10.0.0.0", Prefix: "24"},
						},
					},
				},
			},
		},
	}
}

func fakeScheduledEvents() scheduledEventsResponse {
	return scheduledEventsResponse{
		Events: []scheduledEvent{
			{
				EventType:   "Preempt",
				EventStatus: "Scheduled",
				NotBefore:   "2026-04-08T12:00:00Z",
			},
			{
				EventType:   "Reboot",
				EventStatus: "Scheduled",
				NotBefore:   "2026-04-09T06:00:00Z",
			},
		},
	}
}

func newFakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return newFakeServerWithEvents(t, fakeScheduledEvents())
}

func newFakeServerWithEvents(t *testing.T, events scheduledEventsResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			http.Error(w, "missing Metadata header", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("api-version") == "" {
			http.Error(w, "missing api-version", http.StatusBadRequest)
			return
		}
		resp := fakeResponse()
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/metadata/scheduledevents" {
			_ = json.NewEncoder(w).Encode(events)
			return
		}

		textRoutes := map[string]string{
			"/metadata/instance/compute/vmId":            resp.Compute.VMID,
			"/metadata/instance/compute/location":        resp.Compute.Location,
			"/metadata/instance/compute/zone":            resp.Compute.Zone,
			"/metadata/instance/compute/vmSize":          resp.Compute.VMSize,
			"/metadata/instance/compute/subscriptionId":  resp.Compute.SubscriptionID,
			"/metadata/instance/compute/name":            resp.Compute.Name,
		}
		if v, ok := textRoutes[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(v))
			return
		}
		if r.URL.Path == "/metadata/instance/compute/tagsList" {
			_ = json.NewEncoder(w).Encode(resp.Compute.TagsList)
			return
		}
		if r.URL.Path == "/metadata/instance/network/interface" {
			_ = json.NewEncoder(w).Encode(resp.Network.Interfaces)
			return
		}

		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestProbeSuccess(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if !ok {
		t.Fatal("expected probe to succeed")
	}
}

func TestProbeFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	ok, err := c.Probe(t.Context())
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if ok {
		t.Fatal("expected probe to fail")
	}
}

func TestProbeServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	ok, err := c.Probe(t.Context())
	if err == nil {
		t.Fatal("expected error for 5xx")
	}
	if ok {
		t.Fatal("expected probe to fail")
	}
}

func TestSpotTerminating(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	spot, err := c.SpotTerminating(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !spot {
		t.Fatal("expected SpotTerminating = true")
	}
}

func TestSpotTerminatingFalse(t *testing.T) {
	srv := newFakeServerWithEvents(t, scheduledEventsResponse{
		Events: []scheduledEvent{{EventType: "Reboot", EventStatus: "Scheduled"}},
	})
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	spot, err := c.SpotTerminating(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if spot {
		t.Fatal("expected SpotTerminating = false")
	}
}

func TestMaintenanceEvents(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	events, err := c.MaintenanceEvents(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[0].ProviderType != "preempt" {
		t.Errorf("event[0].ProviderType = %q", events[0].ProviderType)
	}
	if events[0].Type != imds.EventTypeTerminate {
		t.Errorf("event[0].Type = %q, want %q", events[0].Type, imds.EventTypeTerminate)
	}
	if events[0].Status != imds.EventStatusScheduled {
		t.Errorf("event[0].Status = %q, want %q", events[0].Status, imds.EventStatusScheduled)
	}
	if events[1].ProviderType != "reboot" {
		t.Errorf("event[1].ProviderType = %q", events[1].ProviderType)
	}
	if events[1].Type != imds.EventTypeReboot {
		t.Errorf("event[1].Type = %q, want %q", events[1].Type, imds.EventTypeReboot)
	}
	if events[1].Status != imds.EventStatusScheduled {
		t.Errorf("event[1].Status = %q, want %q", events[1].Status, imds.EventStatusScheduled)
	}
}

func TestAzureEventTypeMapping(t *testing.T) {
	cases := []struct {
		in   string
		want imds.EventType
	}{
		{"Freeze", imds.EventTypePause},
		{"Reboot", imds.EventTypeReboot},
		{"Redeploy", imds.EventTypeMigrate},
		{"Preempt", imds.EventTypeTerminate},
		{"Terminate", imds.EventTypeTerminate},
		{"Unknown", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := azureEventType(tc.in); got != tc.want {
			t.Errorf("azureEventType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAzureEventStatusMapping(t *testing.T) {
	cases := []struct {
		in   string
		want imds.EventStatus
	}{
		{"Scheduled", imds.EventStatusScheduled},
		{"Started", imds.EventStatusStarted},
		{"Completed", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := azureEventStatus(tc.in); got != tc.want {
			t.Errorf("azureEventStatus(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGetMetadataSpotAndMaintenance(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !md.SpotTerminating {
		t.Fatal("expected SpotTerminating = true")
	}
	if len(md.MaintenanceEvents) != 2 {
		t.Fatalf("maintenance events = %d, want 2", len(md.MaintenanceEvents))
	}
}

func TestGetMetadata(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	md, err := c.GetMetadata(t.Context())
	if err != nil {
		t.Fatalf("get metadata: %v", err)
	}

	if md.Provider != ProviderID {
		t.Errorf("provider = %q, want %q", md.Provider, ProviderID)
	}
	if md.Instance.ID != "vm-123" {
		t.Errorf("instance ID = %q, want %q", md.Instance.ID, "vm-123")
	}
	if md.Instance.Location.Region != "eastus" {
		t.Errorf("region = %q, want %q", md.Instance.Location.Region, "eastus")
	}
	if md.Instance.Location.Zone != "1" {
		t.Errorf("zone = %q, want %q", md.Instance.Location.Zone, "1")
	}
	if md.Instance.InstanceType != "Standard_D2s_v3" {
		t.Errorf("instance type = %q, want %q", md.Instance.InstanceType, "Standard_D2s_v3")
	}
	if md.Instance.ImageID != "UbuntuServer:18.04-LTS:latest" {
		t.Errorf("image ID = %q, want %q", md.Instance.ImageID, "UbuntuServer:18.04-LTS:latest")
	}
	if md.Instance.AccountID != "sub-456" {
		t.Errorf("account ID = %q, want %q", md.Instance.AccountID, "sub-456")
	}
	if md.Instance.Hostname != "my-vm" {
		t.Errorf("hostname = %q, want %q", md.Instance.Hostname, "my-vm")
	}
	if len(md.Interfaces) != 1 {
		t.Fatalf("interfaces len = %d, want 1", len(md.Interfaces))
	}
	iface := md.Interfaces[0]
	if iface.MAC != "00:0D:3A:12:34:56" {
		t.Errorf("mac = %q", iface.MAC)
	}
	if len(iface.PrivateIPv4s) != 1 || iface.PrivateIPv4s[0] != "10.0.0.4" {
		t.Errorf("private IPs = %v", iface.PrivateIPv4s)
	}
	if len(iface.PublicIPv4s) != 1 || iface.PublicIPv4s[0] != "52.1.2.3" {
		t.Errorf("public IPs = %v", iface.PublicIPv4s)
	}
	if iface.SubnetID != "10.0.0.0/24" {
		t.Errorf("subnet = %q", iface.SubnetID)
	}
	if md.Tags["env"] != "prod" {
		t.Errorf("tags = %v", md.Tags)
	}
	if md.AdditionalProperties["resourceGroupName"] != "my-rg" {
		t.Errorf("additional = %v", md.AdditionalProperties)
	}
}

func TestGetInstanceDocument(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	doc, err := c.GetInstanceDocument(t.Context())
	if err != nil {
		t.Fatalf("get instance document: %v", err)
	}
	if doc.Compute.VMID != "vm-123" {
		t.Errorf("vmId = %q", doc.Compute.VMID)
	}
	if doc.Compute.Location != "eastus" {
		t.Errorf("location = %q", doc.Compute.Location)
	}
	if doc.Compute.VMSize != "Standard_D2s_v3" {
		t.Errorf("vmSize = %q", doc.Compute.VMSize)
	}
}

func TestAccessorMethods(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	ctx := t.Context()

	vmid, err := c.VMID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if vmid != "vm-123" {
		t.Errorf("VMID = %q", vmid)
	}

	region, err := c.Region(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if region != "eastus" {
		t.Errorf("Region = %q", region)
	}

	zone, err := c.Zone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if zone != "1" {
		t.Errorf("Zone = %q", zone)
	}

	vmSize, err := c.VMSize(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if vmSize != "Standard_D2s_v3" {
		t.Errorf("VMSize = %q", vmSize)
	}

	subID, err := c.SubscriptionID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if subID != "sub-456" {
		t.Errorf("SubscriptionID = %q", subID)
	}

	hostname, err := c.Hostname(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hostname != "my-vm" {
		t.Errorf("Hostname = %q", hostname)
	}

	tags, err := c.Tags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tags["env"] != "prod" {
		t.Errorf("Tags = %v", tags)
	}

	ifaces, err := c.Interfaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ifaces) != 1 {
		t.Fatalf("Interfaces len = %d", len(ifaces))
	}
	if ifaces[0].MAC != "00:0D:3A:12:34:56" {
		t.Errorf("MAC = %q", ifaces[0].MAC)
	}
}

func TestQuery(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	body, err := c.Query(t.Context(), "/metadata/instance")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var doc InstanceDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Compute.VMID != "vm-123" {
		t.Errorf("vmId = %q", doc.Compute.VMID)
	}
}

func TestMissingMetadataHeader(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/metadata/instance?api-version=2021-02-01")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestNon200Status(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	_, err := c.Query(t.Context(), "/metadata/instance")
	if err == nil {
		t.Fatal("expected error")
	}
	var me *imds.MetadataError
	if !errors.As(err, &me) {
		t.Fatalf("error type = %T, want *imds.MetadataError", err)
	}
	if me.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d", me.StatusCode)
	}
}

func TestWatch(t *testing.T) {
	instanceCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			http.Error(w, "missing Metadata header", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/metadata/scheduledevents" {
			_ = json.NewEncoder(w).Encode(scheduledEventsResponse{})
			return
		}
		resp := fakeResponse()
		instanceCalls++
		if instanceCalls > 2 {
			resp.Compute.TagsList = append(resp.Compute.TagsList, Tag{Name: "new", Value: "tag"})
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	ch, err := c.Watch(ctx, imds.WatchConfig{Interval: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}

	for ev := range ch {
		if ev.Err != nil {
			continue
		}
		if ev.New != nil && ev.New.Tags["new"] == "tag" {
			cancel()
			return
		}
	}
	t.Fatal("timed out waiting for change event")
}

func TestID(t *testing.T) {
	c := New()
	if c.ID() != ProviderID {
		t.Errorf("ID = %q, want %q", c.ID(), ProviderID)
	}
}

func TestWithAPIVersion(t *testing.T) {
	var gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion = r.URL.Query().Get("api-version")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fakeResponse())
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithAPIVersion("2023-07-01"))
	_, _ = c.Query(t.Context(), "/metadata/instance")
	if gotVersion != "2023-07-01" {
		t.Errorf("api-version = %q, want %q", gotVersion, "2023-07-01")
	}
}

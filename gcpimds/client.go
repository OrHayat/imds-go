package gcpimds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	imds "github.com/OrHayat/imds-go"
	"github.com/OrHayat/imds-go/internal/httputil"
	"github.com/OrHayat/imds-go/internal/watchutil"
)

const (
	ProviderID = imds.ID("gcp")

	defaultDNSEndpoint  = "http://metadata.google.internal"
	defaultIPv4Endpoint = "http://169.254.169.254"
	defaultIPv6Endpoint = "http://[fd20:ce::254]"

	flavorHeader = "Metadata-Flavor"
	flavorValue  = "Google"

	// longPollTimeoutSec is the server-side wait bound for wait_for_change
	// long polls. longPollClientTimeout adds slack on top so the HTTP client
	// does not cut the connection before the server responds.
	longPollTimeoutSec    = 60
	longPollClientTimeout = 120 * time.Second
)

type EndpointMode int

const (
	EndpointModeDNS EndpointMode = iota
	EndpointModeIPv4
	EndpointModeIPv6
)

type options struct {
	httpClient   *http.Client
	timeout      time.Duration
	baseURL      string
	endpointMode EndpointMode
}

type Option func(*options)

func WithTimeout(d time.Duration) Option {
	return func(o *options) { o.timeout = d }
}

func WithHTTPClient(c *http.Client) Option {
	return func(o *options) { o.httpClient = c }
}

func WithBaseURL(u string) Option {
	return func(o *options) { o.baseURL = u }
}

func WithEndpointMode(m EndpointMode) Option {
	return func(o *options) { o.endpointMode = m }
}

type Client struct {
	http     *httputil.Client
	httpLong *httputil.Client
	baseURL  string
}

func New(opts ...Option) (*Client, error) {
	o := options{
		timeout: 2 * time.Second,
	}
	for _, fn := range opts {
		fn(&o)
	}

	base := resolveBaseURL(o)

	shortOpts := []httputil.ClientOption{
		httputil.WithBaseURL(base),
		httputil.WithDefaultHeader(flavorHeader, flavorValue),
	}
	if o.httpClient != nil {
		shortOpts = append(shortOpts, httputil.WithHTTPClient(o.httpClient))
	}
	if o.timeout > 0 {
		shortOpts = append(shortOpts, httputil.WithTimeout(o.timeout))
	}
	short, err := httputil.NewClient(ProviderID, shortOpts...)
	if err != nil {
		return nil, fmt.Errorf("gcpimds: build short-timeout client: %w", err)
	}

	// The long-poll client honors WithTimeout, with a floor of
	// longPollClientTimeout (server wait + slack) so wait_for_change
	// requests are never truncated below the server's own window.
	longTimeout := longPollClientTimeout
	if o.timeout > longTimeout {
		longTimeout = o.timeout
	}
	longOpts := []httputil.ClientOption{
		httputil.WithBaseURL(base),
		httputil.WithDefaultHeader(flavorHeader, flavorValue),
		httputil.WithTimeout(longTimeout),
	}
	if o.httpClient != nil {
		longOpts = append(longOpts, httputil.WithHTTPClient(o.httpClient))
	}
	long, err := httputil.NewClient(ProviderID, longOpts...)
	if err != nil {
		return nil, fmt.Errorf("gcpimds: build long-poll client: %w", err)
	}

	return &Client{http: short, httpLong: long, baseURL: base}, nil
}

// resolveBaseURL: WithBaseURL > GCE_METADATA_HOST env > WithEndpointMode > default DNS.
func resolveBaseURL(o options) string {
	if o.baseURL != "" {
		return strings.TrimRight(o.baseURL, "/")
	}
	if host := os.Getenv("GCE_METADATA_HOST"); host != "" {
		return "http://" + host
	}
	switch o.endpointMode {
	case EndpointModeIPv4:
		return defaultIPv4Endpoint
	case EndpointModeIPv6:
		return defaultIPv6Endpoint
	default:
		return defaultDNSEndpoint
	}
}

func (c *Client) ID() imds.ID {
	return ProviderID
}

// Probe does not delegate to Query because GCP identification requires
// checking the Metadata-Flavor response header, which Query discards.
func (c *Client) Probe(ctx context.Context) (bool, error) {
	resp, err := c.http.Do(ctx, "/computeMetadata/v1/")
	if err != nil {
		var me *imds.MetadataError
		if errors.As(err, &me) {
			if me.StatusCode >= 400 && me.StatusCode < 500 {
				return false, nil
			}
			return false, me
		}
		return false, err
	}
	if resp.Header.Get(flavorHeader) != flavorValue {
		return false, nil
	}
	return true, nil
}

func (c *Client) getString(ctx context.Context, path string) (string, error) {
	b, err := c.Query(ctx, path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *Client) InstanceID(ctx context.Context) (string, error) {
	return c.getString(ctx, "/computeMetadata/v1/instance/id")
}

func (c *Client) MachineType(ctx context.Context) (string, error) {
	raw, err := c.getString(ctx, "/computeMetadata/v1/instance/machine-type")
	if err != nil {
		return "", err
	}
	return lastSegment(raw), nil
}

func (c *Client) ImageID(ctx context.Context) (string, error) {
	return c.getString(ctx, "/computeMetadata/v1/instance/image")
}

func (c *Client) Zone(ctx context.Context) (string, error) {
	raw, err := c.getString(ctx, "/computeMetadata/v1/instance/zone")
	if err != nil {
		return "", err
	}
	return lastSegment(raw), nil
}

func (c *Client) Region(ctx context.Context) (string, error) {
	zone, err := c.Zone(ctx)
	if err != nil {
		return "", err
	}
	if i := strings.LastIndex(zone, "-"); i > 0 {
		return zone[:i], nil
	}
	return zone, nil
}

func (c *Client) Hostname(ctx context.Context) (string, error) {
	return c.getString(ctx, "/computeMetadata/v1/instance/hostname")
}

func (c *Client) NumericProjectID(ctx context.Context) (string, error) {
	return c.getString(ctx, "/computeMetadata/v1/project/numeric-project-id")
}

// Deprecated: ProjectID returns the numeric GCP project number. Use
// NumericProjectID for clarity; a future release will repurpose ProjectID
// to return the string project ID from /project/project-id.
func (c *Client) ProjectID(ctx context.Context) (string, error) {
	return c.NumericProjectID(ctx)
}

func (c *Client) Tags(ctx context.Context) (map[string]string, error) {
	return c.fetchTags(ctx)
}

// Deprecated: use Tags. Attributes is kept for backward compatibility.
func (c *Client) Attributes(ctx context.Context) (map[string]string, error) {
	return c.Tags(ctx)
}

func (c *Client) Interfaces(ctx context.Context) ([]imds.NetworkInterface, error) {
	return c.fetchInterfaces(ctx)
}

func (c *Client) SpotTerminating(ctx context.Context) (bool, error) {
	val, err := c.getString(ctx, "/computeMetadata/v1/instance/preempted")
	if err != nil {
		return false, err
	}
	return val == "TRUE", nil
}

func (c *Client) MaintenanceEvents(ctx context.Context) ([]imds.MaintenanceEvent, error) {
	val, err := c.getString(ctx, "/computeMetadata/v1/instance/maintenance-event")
	if err != nil {
		return nil, err
	}
	return gcpMaintenanceEvents(val), nil
}

func (c *Client) GetMetadata(ctx context.Context) (*imds.InstanceMetadata, error) {
	id, err := c.InstanceID(ctx)
	if err != nil {
		return nil, err
	}

	machineType, _ := c.MachineType(ctx)
	image, _ := c.ImageID(ctx)
	zone, _ := c.Zone(ctx)
	region := zone
	if i := strings.LastIndex(zone, "-"); i > 0 {
		region = zone[:i]
	}
	hostname, _ := c.Hostname(ctx)
	accountID, _ := c.NumericProjectID(ctx)

	ifaces, _ := c.Interfaces(ctx)
	tags, _ := c.Tags(ctx)

	projectID, _ := c.getString(ctx, "/computeMetadata/v1/project/project-id")
	preemptible, _ := c.getString(ctx, "/computeMetadata/v1/instance/scheduling/preemptible")
	preempted, _ := c.getString(ctx, "/computeMetadata/v1/instance/preempted")
	maintenanceEvent, _ := c.getString(ctx, "/computeMetadata/v1/instance/maintenance-event")

	var additional map[string]any
	if projectID != "" || preemptible != "" {
		additional = map[string]any{}
		if projectID != "" {
			additional["project-id"] = projectID
		}
		if preemptible != "" {
			additional["scheduling/preemptible"] = preemptible
		}
	}

	return &imds.InstanceMetadata{
		Provider: ProviderID,
		Instance: imds.InstanceInfo{
			ID:           id,
			Location:     imds.Location{Region: region, Zone: zone},
			InstanceType: machineType,
			ImageID:      image,
			AccountID:    accountID,
			Hostname:     hostname,
			Architecture: imds.RuntimeArchitecture(),
		},
		SpotTerminating:      preempted == "TRUE",
		MaintenanceEvents:    gcpMaintenanceEvents(maintenanceEvent),
		Interfaces:           ifaces,
		Tags:                 tags,
		AdditionalProperties: additional,
	}, nil
}

func (c *Client) Query(ctx context.Context, path string) ([]byte, error) {
	return c.http.Get(ctx, path)
}

func (c *Client) fetchInterfaces(ctx context.Context) ([]imds.NetworkInterface, error) {
	data, err := c.Query(ctx, "/computeMetadata/v1/instance/network-interfaces/")
	if err != nil {
		return nil, err
	}

	indices := strings.Split(strings.TrimSpace(string(data)), "\n")
	var ifaces []imds.NetworkInterface
	for _, idx := range indices {
		idx = strings.TrimRight(idx, "/")
		if idx == "" {
			continue
		}
		prefix := "/computeMetadata/v1/instance/network-interfaces/" + idx

		ipRaw, _ := c.Query(ctx, prefix+"/ip")
		macRaw, _ := c.Query(ctx, prefix+"/mac")
		networkRaw, _ := c.Query(ctx, prefix+"/network")
		subnetworkRaw, _ := c.Query(ctx, prefix+"/subnetwork")
		externalIPRaw, _ := c.Query(ctx, prefix+"/access-configs/0/external-ip")

		ip := strings.TrimSpace(string(ipRaw))
		mac := strings.TrimSpace(string(macRaw))
		network := strings.TrimSpace(string(networkRaw))
		subnetwork := strings.TrimSpace(string(subnetworkRaw))
		externalIP := strings.TrimSpace(string(externalIPRaw))

		iface := imds.NetworkInterface{
			ID:  idx,
			MAC: mac,
		}
		if ip != "" {
			iface.PrivateIPv4s = []string{ip}
		}
		if externalIP != "" {
			iface.PublicIPv4s = []string{externalIP}
		}
		if network != "" {
			iface.VPCID = lastSegment(network)
		}
		if subnetwork != "" {
			iface.SubnetID = lastSegment(subnetwork)
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

func (c *Client) fetchTags(ctx context.Context) (map[string]string, error) {
	data, err := c.Query(ctx, "/computeMetadata/v1/instance/attributes/")
	if err != nil {
		return nil, err
	}

	keys := strings.Split(strings.TrimSpace(string(data)), "\n")
	tags := make(map[string]string, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		val, err := c.Query(ctx, "/computeMetadata/v1/instance/attributes/"+key)
		if err != nil {
			continue
		}
		tags[key] = strings.TrimSpace(string(val))
	}
	return tags, nil
}

// Watch starts a long-poll watch loop against the GCP metadata server.
// cfg.Interval is interpreted as the long-poll wait window passed to GCP
// as timeout_sec, and also as the error backoff between transient
// failures. Both the wait window and the backoff are truncated to
// longPollTimeoutSec (the GCP server's wait cap). Zero (the default)
// means use longPollTimeoutSec for the wait and 1s for the backoff.
// Negative values are rejected.
func (c *Client) Watch(ctx context.Context, cfg imds.WatchConfig) (<-chan imds.Event, error) {
	if cfg.Interval < 0 {
		return nil, fmt.Errorf("gcpimds: invalid poll interval %v", cfg.Interval)
	}
	ch := make(chan imds.Event, 32)
	go c.watchLoop(ctx, ch, cfg)
	return ch, nil
}

func (c *Client) watchLoop(ctx context.Context, ch chan imds.Event, cfg imds.WatchConfig) {
	defer close(ch)

	// Translate cfg.Interval to a long-poll timeout and error backoff.
	// Both are capped at longPollTimeoutSec (the GCP server's wait cap)
	// to keep the documented contract honest. Zero means defaults.
	pollTimeoutSec := longPollTimeoutSec
	errBackoff := time.Second
	maxInterval := time.Duration(longPollTimeoutSec) * time.Second
	if cfg.Interval > 0 {
		capped := cfg.Interval
		if capped > maxInterval {
			capped = maxInterval
		}
		secs := int(capped / time.Second)
		if secs < 1 {
			secs = 1
		}
		pollTimeoutSec = secs
		errBackoff = capped
	}

	var old *imds.InstanceMetadata
	var lastEtag string

	if m, err := c.GetMetadata(ctx); err != nil {
		watchutil.Send(ctx, ch, watchutil.ErrorEvent(err))
	} else {
		old = m
	}

	// Get initial etag
	etag, err := c.longPollEtag(ctx, "", pollTimeoutSec)
	if err == nil {
		lastEtag = etag
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		newEtag, err := c.longPollEtag(ctx, lastEtag, pollTimeoutSec)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			watchutil.Send(ctx, ch, watchutil.ErrorEvent(err))
			// ctx-aware backoff so cancellation isn't delayed.
			timer := time.NewTimer(errBackoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}

		if newEtag == lastEtag {
			continue
		}
		lastEtag = newEtag

		cur, err := c.GetMetadata(ctx)
		if err != nil {
			watchutil.Send(ctx, ch, watchutil.ErrorEvent(err))
			continue
		}

		changed := watchutil.DiffMetadata(old, cur)
		if len(changed) > 0 {
			watchutil.Send(ctx, ch, watchutil.ChangeEvent(old, cur, changed))
		}
		old = cur
	}
}

// longPollEtag issues a GCP wait_for_change long poll and returns the ETag
// header. It deliberately does NOT request recursive=true: we only care
// about whether the ETag changed (the actual metadata is fetched separately
// via GetMetadata). This keeps each long-poll response tiny — empty body
// plus an ETag header — instead of pulling the full recursive JSON tree
// every poll cycle.
func (c *Client) longPollEtag(ctx context.Context, lastEtag string, timeoutSec int) (string, error) {
	opts := []httputil.RequestOption{
		httputil.WithQueryParam("wait_for_change", "true"),
		httputil.WithQueryParam("timeout_sec", fmt.Sprintf("%d", timeoutSec)),
	}
	if lastEtag != "" {
		opts = append(opts, httputil.WithQueryParam("last_etag", lastEtag))
	}
	resp, err := c.httpLong.Do(ctx, "/computeMetadata/v1/", opts...)
	if err != nil {
		return "", err
	}
	return resp.Header.Get("ETag"), nil
}

func gcpMaintenanceEvents(event string) []imds.MaintenanceEvent {
	if event == "" || event == "NONE" {
		return nil
	}
	var eventType imds.EventType
	switch strings.ToUpper(event) {
	case "MIGRATE_ON_HOST_MAINTENANCE", "MIGRATE":
		eventType = imds.EventTypeMigrate
	case "TERMINATE_ON_HOST_MAINTENANCE", "TERMINATE", "SHUTDOWN_ON_HOST_MAINTENANCE":
		eventType = imds.EventTypeTerminate
	case "REBOOT":
		eventType = imds.EventTypeReboot
	}
	return []imds.MaintenanceEvent{{
		Type:   eventType,
		Status: imds.EventStatusScheduled,
	}}
}

func lastSegment(s string) string {
	s = strings.TrimRight(s, "/")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}


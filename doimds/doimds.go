package doimds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	imds "github.com/OrHayat/imds-go"
	"github.com/OrHayat/imds-go/internal/httputil"
	"github.com/OrHayat/imds-go/internal/watchutil"
)

const ProviderID imds.ID = "digitalocean"

const defaultEndpoint = "http://169.254.169.254"

type options struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
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

type Client struct {
	http *httputil.Client
}

func New(opts ...Option) (*Client, error) {
	o := options{
		baseURL: defaultEndpoint,
	}
	for _, fn := range opts {
		fn(&o)
	}
	if o.baseURL == "" {
		o.baseURL = defaultEndpoint
	}

	clientOpts := []httputil.ClientOption{
		httputil.WithBaseURL(o.baseURL),
	}
	if o.httpClient != nil {
		clientOpts = append(clientOpts, httputil.WithHTTPClient(o.httpClient))
	}
	if o.timeout > 0 {
		clientOpts = append(clientOpts, httputil.WithTimeout(o.timeout))
	}

	hc, err := httputil.NewClient(ProviderID, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("doimds: %w", err)
	}
	return &Client{http: hc}, nil
}

func (c *Client) ID() imds.ID { return ProviderID }

func (c *Client) Probe(ctx context.Context) (bool, error) {
	body, err := c.Query(ctx, "/metadata/v1/id")
	if err != nil {
		var me *imds.MetadataError
		if errors.As(err, &me) && me.StatusCode < 500 {
			return false, nil
		}
		return false, err
	}
	// Use ParseInt(..., 64) so we stay correct on 32-bit platforms where
	// DigitalOcean droplet IDs could exceed int range.
	_, parseErr := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	return parseErr == nil, nil
}

func (c *Client) GetDropletDocument(ctx context.Context) (*DropletDocument, error) {
	body, err := c.Query(ctx, "/metadata/v1.json")
	if err != nil {
		return nil, err
	}

	var doc DropletDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("doimds: unmarshal metadata: %w", err)
	}
	return &doc, nil
}

func (c *Client) GetMetadata(ctx context.Context) (*imds.InstanceMetadata, error) {
	raw, err := c.GetDropletDocument(ctx)
	if err != nil {
		return nil, err
	}

	md := &imds.InstanceMetadata{
		Provider: ProviderID,
		Instance: imds.InstanceInfo{
			ID:           strconv.FormatInt(raw.DropletID, 10),
			Hostname:     raw.Hostname,
			Architecture: imds.RuntimeArchitecture(),
			Location:     imds.Location{Region: raw.Region},
		},
		Interfaces: buildInterfaces(raw.Interfaces),
	}

	// Only allocate md.Tags when there are actually tags, so droplets
	// with no tags get a nil map rather than a non-nil empty one. Keeps
	// the shape consistent with Tags(ctx), which returns nil on empty.
	if len(raw.Tags) > 0 {
		md.Tags = make(map[string]string, len(raw.Tags))
		for _, t := range raw.Tags {
			md.Tags[t] = t
		}
	}

	var additional map[string]any
	if len(raw.Features) > 0 {
		additional = make(map[string]any)
		additional["features"] = raw.Features
	}
	if raw.FloatingIP.Active {
		if additional == nil {
			additional = make(map[string]any)
		}
		additional["floating_ip"] = raw.FloatingIP
	}
	if additional != nil {
		md.AdditionalProperties = additional
	}

	return md, nil
}

func (c *Client) queryString(ctx context.Context, path string) (string, error) {
	body, err := c.Query(ctx, path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func (c *Client) DropletID(ctx context.Context) (int64, error) {
	s, err := c.queryString(ctx, "/metadata/v1/id")
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(s, 10, 64)
}

func (c *Client) Region(ctx context.Context) (string, error) {
	return c.queryString(ctx, "/metadata/v1/region")
}

func (c *Client) Hostname(ctx context.Context) (string, error) {
	return c.queryString(ctx, "/metadata/v1/hostname")
}

// Tags returns the DigitalOcean droplet tags as a map[string]string,
// matching the shape of Tags() on other provider clients. DigitalOcean
// tags are a list of bare labels (not key=value pairs), so each label
// is stored with itself as both key and value in the returned map.
// This preserves uniqueness, keeps the public API consistent across
// providers, and matches how GetMetadata maps tags into
// InstanceMetadata.Tags. Returns nil when there are no tags.
func (c *Client) Tags(ctx context.Context) (map[string]string, error) {
	s, err := c.queryString(ctx, "/metadata/v1/tags")
	if err != nil {
		return nil, err
	}
	if s == "" {
		return nil, nil
	}
	labels := strings.Split(s, "\n")
	tags := make(map[string]string, len(labels))
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label == "" {
			continue
		}
		tags[label] = label
	}
	if len(tags) == 0 {
		return nil, nil
	}
	return tags, nil
}

func (c *Client) Interfaces(ctx context.Context) ([]imds.NetworkInterface, error) {
	doc, err := c.GetDropletDocument(ctx)
	if err != nil {
		return nil, err
	}
	return buildInterfaces(doc.Interfaces), nil
}

// buildInterfaces groups DigitalOcean public/private interface entries
// by MAC address and returns one NetworkInterface per unique MAC. On
// most droplets, public and private entries share a single physical
// NIC and therefore the same MAC, so the common case collapses to one
// interface. VPC droplets and anchor-IP setups can expose multiple
// distinct MACs, and we surface those as separate NetworkInterface
// values rather than silently merging their IPs under a single MAC.
//
// Entries with an empty MAC are grouped together under an empty-key
// "unknown" bucket so their IPs are not lost, but they are emitted as
// a single interface with MAC="". Order is deterministic: iteration
// follows the order of first appearance of each MAC across the public
// list first, then the private list.
func buildInterfaces(ifaces DOInterfaces) []imds.NetworkInterface {
	// Map from MAC to the interface being built, plus an ordered list
	// of MACs to preserve insertion order across the output.
	byMAC := make(map[string]*imds.NetworkInterface)
	var order []string
	get := func(mac string) *imds.NetworkInterface {
		if existing, ok := byMAC[mac]; ok {
			return existing
		}
		ni := &imds.NetworkInterface{MAC: mac}
		byMAC[mac] = ni
		order = append(order, mac)
		return ni
	}

	for _, pub := range ifaces.Public {
		ni := get(pub.MAC)
		if pub.IPv4.IPAddress != "" {
			ni.PublicIPv4s = append(ni.PublicIPv4s, pub.IPv4.IPAddress)
		}
	}
	for _, priv := range ifaces.Private {
		ni := get(priv.MAC)
		if priv.IPv4.IPAddress != "" {
			ni.PrivateIPv4s = append(ni.PrivateIPv4s, priv.IPv4.IPAddress)
		}
	}

	out := make([]imds.NetworkInterface, 0, len(order))
	for _, mac := range order {
		out = append(out, *byMAC[mac])
	}
	return out
}

func (c *Client) Watch(ctx context.Context, cfg imds.WatchConfig) (<-chan imds.Event, error) {
	return watchutil.PollWatch(ctx, cfg, c.GetMetadata)
}

func (c *Client) Query(ctx context.Context, path string) ([]byte, error) {
	return c.http.Get(ctx, path)
}

type DropletDocument struct {
	DropletID  int64        `json:"droplet_id"`
	Hostname   string       `json:"hostname"`
	Region     string       `json:"region"`
	Tags       []string     `json:"tags"`
	Features   []string     `json:"features"`
	FloatingIP FloatingIP   `json:"floating_ip"`
	Interfaces DOInterfaces `json:"interfaces"`
}

type FloatingIP struct {
	Active      bool   `json:"active"`
	IPv4Address string `json:"ipv4_address,omitempty"`
}

type DOInterfaces struct {
	Public  []DOInterface `json:"public"`
	Private []DOInterface `json:"private"`
}

type DOInterface struct {
	IPv4 DOIPv4 `json:"ipv4"`
	MAC  string `json:"mac"`
}

type DOIPv4 struct {
	IPAddress string `json:"ip_address"`
}

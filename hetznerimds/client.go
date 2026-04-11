package hetznerimds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	imds "github.com/OrHayat/imds-go"
	"github.com/OrHayat/imds-go/internal/httputil"
	"github.com/OrHayat/imds-go/internal/watchutil"
	"gopkg.in/yaml.v3"
)

const ProviderID imds.ID = "hetzner"

const (
	defaultBaseURL = "http://169.254.169.254"
	metadataPath   = "/hetzner/v1/metadata"
)

type options struct {
	httpClient *http.Client
	timeout    time.Duration
	baseURL    string
}

type Option func(*options)

func WithHTTPClient(c *http.Client) Option {
	return func(o *options) { o.httpClient = c }
}

func WithTimeout(d time.Duration) Option {
	return func(o *options) { o.timeout = d }
}

func WithBaseURL(u string) Option {
	return func(o *options) { o.baseURL = u }
}

type Client struct {
	http *httputil.Client
}

func New(opts ...Option) (*Client, error) {
	o := options{
		baseURL: defaultBaseURL,
	}
	for _, fn := range opts {
		fn(&o)
	}
	if o.baseURL == "" {
		o.baseURL = defaultBaseURL
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
		return nil, fmt.Errorf("hetznerimds: %w", err)
	}
	return &Client{http: hc}, nil
}

func (c *Client) ID() imds.ID { return ProviderID }

func (c *Client) Probe(ctx context.Context) (bool, error) {
	_, err := c.Query(ctx, metadataPath+"/instance-id")
	if err == nil {
		return true, nil
	}
	var me *imds.MetadataError
	if errors.As(err, &me) && me.StatusCode < 500 {
		return false, nil
	}
	return false, err
}

func (c *Client) Query(ctx context.Context, path string) ([]byte, error) {
	return c.http.Get(ctx, path)
}

type PrivateNetwork struct {
	IP string `yaml:"ip"`
}

type MetadataDocument struct {
	// Typed as int64 so parsing is deterministic across 32-bit and
	// 64-bit platforms; Hetzner instance IDs are unlikely to exceed
	// int32 range today but int was platform-dependent.
	InstanceID       int64            `yaml:"instance-id"`
	Hostname         string           `yaml:"hostname"`
	Region           string           `yaml:"region"`
	AvailabilityZone string           `yaml:"availability-zone"`
	PublicIPv4       string           `yaml:"public-ipv4"`
	PrivateNetworks  []PrivateNetwork `yaml:"private-networks"`
	PublicKeys       []string         `yaml:"public-keys"`
}

func (c *Client) GetMetadataDocument(ctx context.Context) (*MetadataDocument, error) {
	body, err := c.Query(ctx, metadataPath)
	if err != nil {
		return nil, err
	}

	var doc MetadataDocument
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("hetznerimds: parse metadata: %w", err)
	}
	return &doc, nil
}

func (c *Client) queryString(ctx context.Context, path string) (string, error) {
	body, err := c.Query(ctx, path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func (c *Client) InstanceID(ctx context.Context) (string, error) {
	return c.queryString(ctx, metadataPath+"/instance-id")
}

func (c *Client) Region(ctx context.Context) (string, error) {
	return c.queryString(ctx, metadataPath+"/region")
}

func (c *Client) Zone(ctx context.Context) (string, error) {
	return c.queryString(ctx, metadataPath+"/availability-zone")
}

func (c *Client) Hostname(ctx context.Context) (string, error) {
	return c.queryString(ctx, metadataPath+"/hostname")
}

func (c *Client) PublicIPv4(ctx context.Context) (string, error) {
	return c.queryString(ctx, metadataPath+"/public-ipv4")
}

func (c *Client) GetMetadata(ctx context.Context) (*imds.InstanceMetadata, error) {
	raw, err := c.GetMetadataDocument(ctx)
	if err != nil {
		return nil, err
	}

	iface := imds.NetworkInterface{}
	if raw.PublicIPv4 != "" {
		iface.PublicIPv4s = []string{raw.PublicIPv4}
	}
	for _, pn := range raw.PrivateNetworks {
		if pn.IP != "" {
			iface.PrivateIPv4s = append(iface.PrivateIPv4s, pn.IP)
		}
	}

	md := &imds.InstanceMetadata{
		Provider: ProviderID,
		Instance: imds.InstanceInfo{
			ID: strconv.FormatInt(raw.InstanceID, 10),
			Location: imds.Location{
				Region: raw.Region,
				Zone:   raw.AvailabilityZone,
			},
			Hostname:     raw.Hostname,
			Architecture: imds.RuntimeArchitecture(),
		},
	}
	// Only surface an interface if the Hetzner document actually has
	// network data. An always-1-element slice with all zero fields
	// creates noise in watchutil diffs and disagrees with how other
	// providers expose "no networks".
	if len(iface.PublicIPv4s) > 0 || len(iface.PrivateIPv4s) > 0 {
		md.Interfaces = []imds.NetworkInterface{iface}
	}

	if len(raw.PublicKeys) > 0 {
		md.AdditionalProperties = map[string]any{
			"public-keys": raw.PublicKeys,
		}
	}

	return md, nil
}

func (c *Client) Watch(ctx context.Context, cfg imds.WatchConfig) (<-chan imds.Event, error) {
	return watchutil.PollWatch(ctx, cfg, c.GetMetadata)
}

package vultrimds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	imds "github.com/OrHayat/imds-go"
	"github.com/OrHayat/imds-go/internal/httputil"
	"github.com/OrHayat/imds-go/internal/watchutil"
)

const ProviderID imds.ID = "vultr"

const (
	defaultBaseURL     = "http://169.254.169.254"
	metadataPath       = "/v1.json"
	instanceIDPath     = "/v1/instance-v2-id"
	regionPath         = "/v1/region/regioncode"
	hostnamePath       = "/v1/hostname"
)

type options struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
}

// Option configures a vultrimds Client at construction time.
type Option func(*options)

// WithBaseURL overrides the IMDS base URL. The default is
// http://169.254.169.254. Trailing slashes are trimmed.
func WithBaseURL(u string) Option {
	return func(o *options) { o.baseURL = u }
}

// WithHTTPClient overrides the underlying *http.Client. When set, the
// client's Timeout field is used as-is and WithTimeout has no effect.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) { o.httpClient = c }
}

// WithTimeout sets a request timeout on the from-scratch HTTP client.
// Ignored when WithHTTPClient is also set (the supplied client's
// Timeout is the source of truth in that case).
func WithTimeout(d time.Duration) Option {
	return func(o *options) { o.timeout = d }
}

type Client struct {
	http *httputil.Client
}

func New(opts ...Option) (*Client, error) {
	o := options{baseURL: defaultBaseURL}
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
	} else if o.timeout > 0 {
		clientOpts = append(clientOpts, httputil.WithTimeout(o.timeout))
	}

	hc, err := httputil.NewClient(ProviderID, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("vultrimds: %w", err)
	}
	return &Client{http: hc}, nil
}

func (c *Client) ID() imds.ID { return ProviderID }

func (c *Client) Probe(ctx context.Context) (bool, error) {
	body, err := c.Query(ctx, metadataPath)
	if err == nil {
		// Require a non-empty instance id so that unrelated JSON
		// payloads (e.g. `{}` or another provider's document) don't
		// produce a false positive match.
		var doc InstanceDocument
		if json.Unmarshal(body, &doc) != nil || doc.InstanceID == "" {
			return false, nil
		}
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

type InstanceDocument struct {
	InstanceID string      `json:"instanceid"`
	Region     string      `json:"region"`
	Hostname   string      `json:"hostname"`
	Plan       string      `json:"plan"`
	OS         string      `json:"os"`
	RAM        string      `json:"ram"`
	Tags       []string    `json:"tags"`
	Interfaces []Interface `json:"interfaces"`
}

type Interface struct {
	IPv4        IPv4   `json:"ipv4"`
	MAC         string `json:"mac"`
	NetworkType string `json:"network-type"`
}

type IPv4 struct {
	Address string `json:"address"`
	Gateway string `json:"gateway"`
}

func (c *Client) GetInstanceDocument(ctx context.Context) (*InstanceDocument, error) {
	body, err := c.Query(ctx, metadataPath)
	if err != nil {
		return nil, err
	}

	var doc InstanceDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("vultrimds: parsing JSON: %w", err)
	}

	return &doc, nil
}

func (c *Client) GetMetadata(ctx context.Context) (*imds.InstanceMetadata, error) {
	doc, err := c.GetInstanceDocument(ctx)
	if err != nil {
		return nil, err
	}

	md := &imds.InstanceMetadata{
		Provider: ProviderID,
		Instance: imds.InstanceInfo{
			ID:           doc.InstanceID,
			Hostname:     doc.Hostname,
			InstanceType: doc.Plan,
			Architecture: imds.RuntimeArchitecture(),
			Location: imds.Location{
				Region: doc.Region,
			},
		},
		Tags: parseTags(doc.Tags),
	}

	extra := make(map[string]any)
	if doc.OS != "" {
		extra["os"] = doc.OS
	}
	if doc.RAM != "" {
		extra["ram"] = doc.RAM
	}
	if len(extra) > 0 {
		md.AdditionalProperties = extra
	}

	md.Interfaces = convertInterfaces(doc.Interfaces)

	return md, nil
}

func (c *Client) queryString(ctx context.Context, path string) (string, error) {
	body, err := c.Query(ctx, path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func (c *Client) InstanceID(ctx context.Context) (string, error) {
	return c.queryString(ctx, instanceIDPath)
}

func (c *Client) Region(ctx context.Context) (string, error) {
	return c.queryString(ctx, regionPath)
}

func (c *Client) Hostname(ctx context.Context) (string, error) {
	return c.queryString(ctx, hostnamePath)
}

// Tags returns the Vultr instance tags as a map[string]string, matching
// the shape exposed by other provider clients (awsimds, azureimds,
// gcpimds, ociimds) and by imds.InstanceMetadata.Tags. Vultr tags
// follow the same key=value / bare-label convention used by parseTags,
// so this accessor reuses parseTags directly — tags like "env=prod"
// round-trip as {"env":"prod"}, bare labels like "web" round-trip as
// {"web":""}. Returns nil when the document has no tags.
func (c *Client) Tags(ctx context.Context) (map[string]string, error) {
	doc, err := c.GetInstanceDocument(ctx)
	if err != nil {
		return nil, err
	}
	return parseTags(doc.Tags), nil
}

func (c *Client) Interfaces(ctx context.Context) ([]imds.NetworkInterface, error) {
	doc, err := c.GetInstanceDocument(ctx)
	if err != nil {
		return nil, err
	}
	return convertInterfaces(doc.Interfaces), nil
}

func (c *Client) Watch(ctx context.Context, cfg imds.WatchConfig) (<-chan imds.Event, error) {
	return watchutil.PollWatch(ctx, cfg, c.GetMetadata)
}

func convertInterfaces(ifaces []Interface) []imds.NetworkInterface {
	out := make([]imds.NetworkInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		ni := imds.NetworkInterface{
			MAC: iface.MAC,
		}
		if iface.IPv4.Address != "" {
			switch iface.NetworkType {
			case "public":
				ni.PublicIPv4s = []string{iface.IPv4.Address}
			default:
				ni.PrivateIPv4s = []string{iface.IPv4.Address}
			}
		}
		out = append(out, ni)
	}
	return out
}

func parseTags(tags []string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		if key, val, ok := strings.Cut(t, "="); ok {
			m[key] = val
		} else {
			m[t] = ""
		}
	}
	return m
}

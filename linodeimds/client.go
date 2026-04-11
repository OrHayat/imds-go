package linodeimds

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

const ProviderID imds.ID = "linode"

const (
	defaultBaseURL = "http://169.254.169.254"
	tokenTTL       = 3600
)

type options struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
}

// Option configures a linodeimds Client at construction time.
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

type linodeTokenSource struct {
	http *httputil.Client
	ttl  int
}

func (s *linodeTokenSource) Token(ctx context.Context) (string, error) {
	resp, err := s.http.Do(ctx, "/v1/token",
		httputil.WithMethod(http.MethodPut),
		httputil.WithHeader("Metadata-Token-Expiry-Seconds", strconv.Itoa(s.ttl)),
	)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(resp.Body))
	if token == "" {
		// An empty token would otherwise be cached and the auth header
		// silently dropped, surfacing later as a confusing 401/403 from
		// /v1/instance instead of a clear token-fetch failure.
		return "", fmt.Errorf("linodeimds: empty token response from /v1/token")
	}
	return token, nil
}

func New(opts ...Option) (*Client, error) {
	o := options{baseURL: defaultBaseURL}
	for _, fn := range opts {
		fn(&o)
	}
	if o.baseURL == "" {
		o.baseURL = defaultBaseURL
	}

	tokenOpts := []httputil.ClientOption{httputil.WithBaseURL(o.baseURL)}
	// When the caller supplies their own *http.Client, we trust its
	// Timeout field as-is and ignore WithTimeout. Only apply
	// WithTimeout when we're building the underlying HTTP client from
	// scratch. Matches ibmimds.New and avoids silently overwriting a
	// caller-configured timeout.
	if o.httpClient != nil {
		tokenOpts = append(tokenOpts, httputil.WithHTTPClient(o.httpClient))
	} else if o.timeout > 0 {
		tokenOpts = append(tokenOpts, httputil.WithTimeout(o.timeout))
	}
	tokenHTTP, err := httputil.NewClient(ProviderID, tokenOpts...)
	if err != nil {
		return nil, fmt.Errorf("linodeimds: build token client: %w", err)
	}

	ts := &linodeTokenSource{http: tokenHTTP, ttl: tokenTTL}

	mainOpts := []httputil.ClientOption{
		httputil.WithBaseURL(o.baseURL),
		httputil.WithTokenSource("Metadata-Token", ts),
	}
	if o.httpClient != nil {
		mainOpts = append(mainOpts, httputil.WithHTTPClient(o.httpClient))
	} else if o.timeout > 0 {
		mainOpts = append(mainOpts, httputil.WithTimeout(o.timeout))
	}
	mainHTTP, err := httputil.NewClient(ProviderID, mainOpts...)
	if err != nil {
		return nil, fmt.Errorf("linodeimds: build main client: %w", err)
	}

	return &Client{http: mainHTTP}, nil
}

func (c *Client) ID() imds.ID { return ProviderID }

func (c *Client) Probe(ctx context.Context) (bool, error) {
	// Do a raw GET against /v1/instance rather than going through
	// GetInstanceDocument. Probe's job is to classify "is this a
	// Linode IMDS endpoint at all" — a 200 response is proof enough.
	// Using GetInstanceDocument would reject a valid 200 with a
	// slightly-different body as "not this provider" due to a JSON
	// unmarshal failure, which is the wrong classification.
	_, err := c.http.Get(ctx, "/v1/instance")
	if err == nil {
		return true, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	var me *imds.MetadataError
	if errors.As(err, &me) && me.StatusCode < 500 {
		return false, nil
	}
	return false, err
}

func (c *Client) GetMetadata(ctx context.Context) (*imds.InstanceMetadata, error) {
	inst, err := c.GetInstanceDocument(ctx)
	if err != nil {
		return nil, err
	}

	netDoc, err := c.GetNetworkDocument(ctx)
	if err != nil {
		return nil, err
	}

	md := &imds.InstanceMetadata{
		Provider: ProviderID,
		Instance: imds.InstanceInfo{
			ID:           strconv.Itoa(inst.ID),
			Hostname:     inst.Label,
			InstanceType: inst.Type,
			Architecture: imds.RuntimeArchitecture(),
			Location:     imds.Location{Region: inst.Region},
		},
		Interfaces: convertInterfaces(netDoc),
		Tags:       parseTags(inst.Tags),
	}

	// Only allocate AdditionalProperties if there's something to put in
	// it. On the common path (no host UUID, backups disabled) this is a
	// zero-cost GetMetadata.
	var extra map[string]any
	if inst.HostUUID != "" {
		extra = map[string]any{"host_uuid": inst.HostUUID}
	}
	if inst.Backups.Enabled {
		if extra == nil {
			extra = map[string]any{}
		}
		extra["backups.enabled"] = true
	}
	if extra != nil {
		md.AdditionalProperties = extra
	}

	return md, nil
}

func (c *Client) Watch(ctx context.Context, cfg imds.WatchConfig) (<-chan imds.Event, error) {
	return watchutil.PollWatch(ctx, cfg, c.GetMetadata)
}

type InstanceDocument struct {
	ID       int      `json:"id"`
	Label    string   `json:"label"`
	Region   string   `json:"region"`
	Type     string   `json:"type"`
	HostUUID string   `json:"host_uuid"`
	Tags     []string `json:"tags"`
	Backups  struct {
		Enabled bool `json:"enabled"`
	} `json:"backups"`
}

type NetworkDocument struct {
	Interfaces []NetworkInterfaceEntry `json:"interfaces"`
}

type NetworkInterfaceEntry struct {
	IPv4       NetworkIPv4Entry `json:"ipv4"`
	MACAddress string           `json:"mac_address"`
	Purpose    string           `json:"purpose"`
}

type NetworkIPv4Entry struct {
	Address string `json:"address"`
}

func (c *Client) GetInstanceDocument(ctx context.Context) (*InstanceDocument, error) {
	body, err := c.http.Get(ctx, "/v1/instance")
	if err != nil {
		return nil, err
	}
	var out InstanceDocument
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("linodeimds: unmarshal /v1/instance: %w", err)
	}
	return &out, nil
}

func (c *Client) GetNetworkDocument(ctx context.Context) (*NetworkDocument, error) {
	body, err := c.http.Get(ctx, "/v1/network")
	if err != nil {
		return nil, err
	}
	var out NetworkDocument
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("linodeimds: unmarshal /v1/network: %w", err)
	}
	return &out, nil
}

func instanceField[T any](c *Client, ctx context.Context, fn func(*InstanceDocument) T) (T, error) {
	doc, err := c.GetInstanceDocument(ctx)
	if err != nil {
		var zero T
		return zero, err
	}
	return fn(doc), nil
}

// InstanceID returns the Linode instance ID as a string, matching the
// shape of InstanceID() on other provider clients (awsimds, azureimds,
// vultrimds, ibmimds, etc.) and the normalized md.Instance.ID value.
func (c *Client) InstanceID(ctx context.Context) (string, error) {
	return instanceField(c, ctx, func(d *InstanceDocument) string {
		return strconv.Itoa(d.ID)
	})
}

func (c *Client) Region(ctx context.Context) (string, error) {
	return instanceField(c, ctx, func(d *InstanceDocument) string { return d.Region })
}

// Hostname returns the Linode instance label. Linode exposes this as
// the "label" field in its metadata document, but the accessor is
// named Hostname to match the convention used by other provider
// clients and by md.Instance.Hostname.
func (c *Client) Hostname(ctx context.Context) (string, error) {
	return instanceField(c, ctx, func(d *InstanceDocument) string { return d.Label })
}

func (c *Client) InstanceType(ctx context.Context) (string, error) {
	return instanceField(c, ctx, func(d *InstanceDocument) string { return d.Type })
}

// Tags returns the Linode instance tags as a map[string]string,
// matching the shape exposed by other provider clients and by
// imds.InstanceMetadata.Tags. Linode tags follow the same key=value /
// bare-label convention used by parseTags, so "env=prod" round-trips
// as {"env":"prod"} and bare labels round-trip as {"web":""}. Returns
// nil when the document has no tags.
func (c *Client) Tags(ctx context.Context) (map[string]string, error) {
	return instanceField(c, ctx, func(d *InstanceDocument) map[string]string {
		return parseTags(d.Tags)
	})
}

func (c *Client) Interfaces(ctx context.Context) ([]imds.NetworkInterface, error) {
	doc, err := c.GetNetworkDocument(ctx)
	if err != nil {
		return nil, err
	}
	return convertInterfaces(doc), nil
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

func convertInterfaces(doc *NetworkDocument) []imds.NetworkInterface {
	ifaces := make([]imds.NetworkInterface, 0, len(doc.Interfaces))
	for _, iface := range doc.Interfaces {
		ni := imds.NetworkInterface{
			MAC: iface.MACAddress,
		}
		if iface.IPv4.Address != "" {
			switch iface.Purpose {
			case "public":
				ni.PublicIPv4s = []string{iface.IPv4.Address}
			default:
				ni.PrivateIPv4s = []string{iface.IPv4.Address}
			}
		}
		ifaces = append(ifaces, ni)
	}
	return ifaces
}

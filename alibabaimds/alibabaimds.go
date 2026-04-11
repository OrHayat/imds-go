package alibabaimds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	imds "github.com/OrHayat/imds-go"
	"github.com/OrHayat/imds-go/internal/httputil"
	"github.com/OrHayat/imds-go/internal/watchutil"
)

const ProviderID imds.ID = "alibaba"

const defaultURL = "http://100.100.100.200"

type options struct {
	httpClient *http.Client
	timeout    time.Duration
	baseURL    string
}

type Option func(*options)

func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		o.timeout = d
	}
}

func WithHTTPClient(c *http.Client) Option {
	return func(o *options) {
		o.httpClient = c
	}
}

func WithBaseURL(u string) Option {
	return func(o *options) {
		o.baseURL = u
	}
}

type Client struct {
	http *httputil.Client
}

func New(opts ...Option) (*Client, error) {
	o := options{
		baseURL: defaultURL,
	}
	for _, fn := range opts {
		fn(&o)
	}
	if o.baseURL == "" {
		o.baseURL = defaultURL
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
		return nil, fmt.Errorf("alibabaimds: %w", err)
	}
	return &Client{http: hc}, nil
}

func (c *Client) ID() imds.ID {
	return ProviderID
}

func (c *Client) Probe(ctx context.Context) (bool, error) {
	body, err := c.Query(ctx, "/latest/meta-data/instance-id")
	if err != nil {
		if isNonServerError(err) {
			return false, nil
		}
		return false, err
	}
	// Whitespace-only responses don't count as a valid instance-id.
	return len(strings.TrimSpace(string(body))) > 0, nil
}

// isNonServerError returns true if the error represents a non-5xx HTTP
// response (any status < 500). Used by Probe to distinguish "not this
// provider" / "endpoint missing" from real server failures, matching the
// pattern used by other provider Probe implementations.
func isNonServerError(err error) bool {
	var me *imds.MetadataError
	if errors.As(err, &me) {
		return me.StatusCode < 500
	}
	return false
}

func (c *Client) getString(ctx context.Context, path string) (string, error) {
	b, err := c.Query(ctx, path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *Client) InstanceID(ctx context.Context) (string, error) {
	return c.getString(ctx, "/latest/meta-data/instance-id")
}

func (c *Client) InstanceType(ctx context.Context) (string, error) {
	return c.getString(ctx, "/latest/meta-data/instance/instance-type")
}

func (c *Client) ImageID(ctx context.Context) (string, error) {
	return c.getString(ctx, "/latest/meta-data/image-id")
}

func (c *Client) Region(ctx context.Context) (string, error) {
	return c.getString(ctx, "/latest/meta-data/region-id")
}

func (c *Client) Zone(ctx context.Context) (string, error) {
	return c.getString(ctx, "/latest/meta-data/zone-id")
}

func (c *Client) Hostname(ctx context.Context) (string, error) {
	return c.getString(ctx, "/latest/meta-data/hostname")
}

func (c *Client) AccountID(ctx context.Context) (string, error) {
	return c.getString(ctx, "/latest/meta-data/owner-account-id")
}

func (c *Client) Interfaces(ctx context.Context) ([]imds.NetworkInterface, error) {
	macsRaw, err := c.getString(ctx, "/latest/meta-data/network/interfaces/macs/")
	if err != nil {
		return nil, err
	}

	var ifaces []imds.NetworkInterface
	for _, mac := range strings.Split(macsRaw, "\n") {
		mac = strings.TrimSuffix(strings.TrimSpace(mac), "/")
		if mac == "" {
			continue
		}

		prefix := fmt.Sprintf("/latest/meta-data/network/interfaces/macs/%s/", mac)
		primaryIP, _ := c.getString(ctx, prefix+"primary-ip-address")
		publicIP, _ := c.getString(ctx, prefix+"public-ip-address")
		ifaceID, _ := c.getString(ctx, prefix+"network-interface-id")
		vpcID, _ := c.getString(ctx, prefix+"vpc-id")

		// Default MAC to the listing value (the directory name that led
		// us to this interface). Only override if the dedicated /mac
		// endpoint returns something non-empty — matches awsimds and
		// prevents a missing /mac endpoint from producing an interface
		// with an empty MAC field even though we had it from the listing.
		iface := imds.NetworkInterface{
			ID:    ifaceID,
			MAC:   mac,
			VPCID: vpcID,
		}
		if macAddr, err := c.getString(ctx, prefix+"mac"); err == nil && macAddr != "" {
			iface.MAC = macAddr
		}
		if primaryIP != "" {
			iface.PrivateIPv4s = []string{primaryIP}
		}
		if publicIP != "" {
			iface.PublicIPv4s = []string{publicIP}
		}
		ifaces = append(ifaces, iface)
	}

	return ifaces, nil
}

func (c *Client) GetMetadata(ctx context.Context) (*imds.InstanceMetadata, error) {
	instanceID, err := c.InstanceID(ctx)
	if err != nil {
		return nil, err
	}

	instanceType, _ := c.InstanceType(ctx)
	imageID, _ := c.ImageID(ctx)
	region, _ := c.Region(ctx)
	zone, _ := c.Zone(ctx)
	hostname, _ := c.Hostname(ctx)
	accountID, _ := c.AccountID(ctx)
	serialNumber, _ := c.getString(ctx, "/latest/meta-data/serial-number")
	privateIPv4, _ := c.getString(ctx, "/latest/meta-data/private-ipv4")

	md := &imds.InstanceMetadata{
		Provider: ProviderID,
		Instance: imds.InstanceInfo{
			ID:           instanceID,
			InstanceType: instanceType,
			ImageID:      imageID,
			AccountID:    accountID,
			Hostname:     hostname,
			Architecture: imds.RuntimeArchitecture(),
			Location: imds.Location{
				Region: region,
				Zone:   zone,
			},
		},
	}

	extra := map[string]any{}
	if serialNumber != "" {
		extra["serial-number"] = serialNumber
	}
	if privateIPv4 != "" {
		extra["private-ipv4"] = privateIPv4
	}
	if len(extra) > 0 {
		md.AdditionalProperties = extra
	}

	ifaces, err := c.Interfaces(ctx)
	if err == nil {
		md.Interfaces = ifaces
	}

	// Spot termination endpoint follows the same best-effort contract as
	// the other optional fields above — missing or failing endpoints
	// leave SpotTerminating at false rather than failing the whole
	// GetMetadata call.
	if _, spotErr := c.getString(ctx, "/latest/meta-data/instance/spot/termination-time"); spotErr == nil {
		md.SpotTerminating = true
	}

	return md, nil
}

func (c *Client) Watch(ctx context.Context, cfg imds.WatchConfig) (<-chan imds.Event, error) {
	return watchutil.PollWatch(ctx, cfg, c.GetMetadata)
}

func (c *Client) Query(ctx context.Context, path string) ([]byte, error) {
	return c.http.Get(ctx, path)
}

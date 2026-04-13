package ibmimds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	imds "github.com/OrHayat/imds-go"
	"github.com/OrHayat/imds-go/internal/httputil"
	"github.com/OrHayat/imds-go/internal/watchutil"
)

const ProviderID imds.ID = "ibm"

const (
	defaultBaseURL = "http://api.metadata.cloud.ibm.com"
	apiVersion     = "2022-03-01"
	tokenTTL       = 3600
)

type Client struct {
	http     *httputil.Client
	tokenSrc *ibmTokenSource
}

func New(opts ...imds.Option) (*Client, error) {
	o := imds.Apply(opts...)

	baseURL := defaultBaseURL
	if o.BaseURL != "" {
		baseURL = o.BaseURL
	}

	tokenOpts := []httputil.ClientOption{
		httputil.WithBaseURL(baseURL),
	}
	// When the caller supplies their own *http.Client, we trust its
	// Timeout field as-is — imds.Apply's default 2s would otherwise
	// silently overwrite whatever the caller configured. Only apply
	// WithTimeout when we're constructing the underlying HTTP client
	// from scratch (i.e. o.HTTPClient == nil).
	if o.HTTPClient != nil {
		tokenOpts = append(tokenOpts, httputil.WithHTTPClient(o.HTTPClient))
	} else if o.Timeout > 0 {
		tokenOpts = append(tokenOpts, httputil.WithTimeout(o.Timeout))
	}
	tokenClient, err := httputil.NewClient(ProviderID, tokenOpts...)
	if err != nil {
		return nil, fmt.Errorf("ibmimds: build token client: %w", err)
	}

	src := &ibmTokenSource{http: tokenClient}

	mainOpts := []httputil.ClientOption{
		httputil.WithBaseURL(baseURL),
		httputil.WithTokenSource("Authorization", src),
	}
	if o.HTTPClient != nil {
		mainOpts = append(mainOpts, httputil.WithHTTPClient(o.HTTPClient))
	} else if o.Timeout > 0 {
		mainOpts = append(mainOpts, httputil.WithTimeout(o.Timeout))
	}
	mainClient, err := httputil.NewClient(ProviderID, mainOpts...)
	if err != nil {
		return nil, fmt.Errorf("ibmimds: build main client: %w", err)
	}

	return &Client{http: mainClient, tokenSrc: src}, nil
}

func (c *Client) ID() imds.ID { return ProviderID }

func (c *Client) Probe(ctx context.Context) (bool, error) {
	_, err := c.GetInstanceDocument(ctx)
	if err == nil {
		return true, nil
	}
	// 4xx (and other non-5xx) responses are a clean "not this
	// provider" signal — the endpoint responded but doesn't look
	// like IBM Cloud IMDS. Report this without an error so
	// Detect() can move on cleanly.
	var me *imds.MetadataError
	if errors.As(err, &me) && me.StatusCode < 500 {
		return false, nil
	}
	// Everything else (5xx, transport failures, context errors) is
	// surfaced as an error. Detect() error aggregation can then
	// explain why a probe sequence did not converge, instead of
	// silently eating the root cause under a (false, nil) result.
	return false, err
}

func (c *Client) GetInstanceDocument(ctx context.Context) (*InstanceDocument, error) {
	body, err := c.http.Do(ctx, "/metadata/v1/instance",
		httputil.WithQueryParam("version", apiVersion),
	)
	if err != nil {
		return nil, err
	}

	var doc InstanceDocument
	if err := json.Unmarshal(body.Body, &doc); err != nil {
		return nil, fmt.Errorf("ibmimds: unmarshal instance: %w", err)
	}

	return &doc, nil
}

func (c *Client) GetMetadata(ctx context.Context) (*imds.InstanceMetadata, error) {
	doc, err := c.GetInstanceDocument(ctx)
	if err != nil {
		return nil, err
	}
	return doc.toMetadata(), nil
}

func docField[T any](c *Client, ctx context.Context, fn func(*InstanceDocument) T) (T, error) {
	doc, err := c.GetInstanceDocument(ctx)
	if err != nil {
		var zero T
		return zero, err
	}
	return fn(doc), nil
}

func (c *Client) InstanceID(ctx context.Context) (string, error) {
	return docField(c, ctx, func(d *InstanceDocument) string { return d.ID })
}

func (c *Client) Region(ctx context.Context) (string, error) {
	return docField(c, ctx, func(d *InstanceDocument) string { return parseRegion(d.Zone.Name) })
}

func (c *Client) Zone(ctx context.Context) (string, error) {
	return docField(c, ctx, func(d *InstanceDocument) string { return d.Zone.Name })
}

func (c *Client) ProfileName(ctx context.Context) (string, error) {
	return docField(c, ctx, func(d *InstanceDocument) string { return d.Profile.Name })
}

func (c *Client) ImageID(ctx context.Context) (string, error) {
	return docField(c, ctx, func(d *InstanceDocument) string { return d.Image.ID })
}

func (c *Client) Hostname(ctx context.Context) (string, error) {
	return docField(c, ctx, func(d *InstanceDocument) string { return d.Name })
}

func (c *Client) CRN(ctx context.Context) (string, error) {
	return docField(c, ctx, func(d *InstanceDocument) string { return d.CRN })
}

func (c *Client) Interfaces(ctx context.Context) ([]imds.NetworkInterface, error) {
	return docField(c, ctx, func(d *InstanceDocument) []imds.NetworkInterface { return d.toMetadata().Interfaces })
}

func (c *Client) Watch(ctx context.Context, cfg imds.WatchConfig) (<-chan imds.Event, error) {
	return watchutil.PollWatch(ctx, cfg, c.GetMetadata)
}

type ibmTokenSource struct {
	http *httputil.Client
}

func (s *ibmTokenSource) Token(ctx context.Context) (string, error) {
	raw, err := s.fetchToken(ctx, tokenTTL)
	if err != nil {
		return "", err
	}
	return "Bearer " + raw, nil
}

// fetchToken hits the instance identity token endpoint and returns the
// raw JWT (no "Bearer " prefix). Shared between the Authorization
// header path and the public GetIdentityToken API.
func (s *ibmTokenSource) fetchToken(ctx context.Context, expiresIn int) (string, error) {
	resp, err := s.http.Do(ctx, "/instance_identity/v1/token",
		httputil.WithMethod(http.MethodPut),
		httputil.WithQueryParam("version", apiVersion),
		httputil.WithHeader("Metadata-Flavor", "ibm"),
		httputil.WithHeader("Content-Type", "application/json"),
		httputil.WithBody(strings.NewReader(fmt.Sprintf(`{"expires_in":%d}`, expiresIn))),
	)
	if err != nil {
		return "", err
	}

	var tok tokenResponse
	if err := json.Unmarshal(resp.Body, &tok); err != nil {
		return "", fmt.Errorf("ibmimds: unmarshal token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("ibmimds: token response has empty access_token")
	}
	return tok.AccessToken, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

type InstanceDocument struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	CRN     string `json:"crn"`
	Profile struct {
		Name string `json:"name"`
	} `json:"profile"`
	Zone struct {
		Name string `json:"name"`
	} `json:"zone"`
	VCPU struct {
		Architecture string `json:"architecture"`
	} `json:"vcpu"`
	Image struct {
		ID string `json:"id"`
	} `json:"image"`
	VPC struct {
		ID string `json:"id"`
	} `json:"vpc"`
	ResourceGroup struct {
		ID string `json:"id"`
	} `json:"resource_group"`
	PrimaryNetworkInterface NetworkInterfaceResponse   `json:"primary_network_interface"`
	NetworkInterfaces       []NetworkInterfaceResponse `json:"network_interfaces"`
}

type NetworkInterfaceResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	PrimaryIPv4 string `json:"primary_ipv4_address"`
	FloatingIP  *struct {
		Address string `json:"address"`
	} `json:"floating_ip,omitempty"`
	Subnet struct {
		ID string `json:"id"`
	} `json:"subnet"`
}

func (r *InstanceDocument) toMetadata() *imds.InstanceMetadata {
	zone := r.Zone.Name
	region := parseRegion(zone)

	m := &imds.InstanceMetadata{
		Provider: ProviderID,
		Instance: imds.InstanceInfo{
			ID:           r.ID,
			Hostname:     r.Name,
			InstanceType: r.Profile.Name,
			ImageID:      r.Image.ID,
			Architecture: imds.NormalizeArch(r.VCPU.Architecture),
			Location: imds.Location{
				Region: region,
				Zone:   zone,
			},
		},
	}

	extra := make(map[string]any)
	if r.CRN != "" {
		extra["crn"] = r.CRN
	}
	if r.ResourceGroup.ID != "" {
		extra["resource_group_id"] = r.ResourceGroup.ID
	}
	if r.VPC.ID != "" {
		extra["vpc_id"] = r.VPC.ID
	}
	if len(extra) > 0 {
		m.AdditionalProperties = extra
	}

	seen := make(map[string]bool)
	addIface := func(ni NetworkInterfaceResponse) {
		// Skip zero-valued entries (happens when IMDS omits
		// primary_network_interface from the response).
		if ni.ID == "" {
			return
		}
		if seen[ni.ID] {
			return
		}
		seen[ni.ID] = true
		iface := imds.NetworkInterface{
			ID:       ni.ID,
			Name:     ni.Name,
			SubnetID: ni.Subnet.ID,
		}
		if ni.PrimaryIPv4 != "" {
			iface.PrivateIPv4s = []string{ni.PrimaryIPv4}
		}
		if ni.FloatingIP != nil && ni.FloatingIP.Address != "" {
			iface.PublicIPv4s = []string{ni.FloatingIP.Address}
		}
		m.Interfaces = append(m.Interfaces, iface)
	}

	addIface(r.PrimaryNetworkInterface)
	for _, ni := range r.NetworkInterfaces {
		addIface(ni)
	}

	return m
}

// parseRegion strips the trailing "-N" numeric suffix from an IBM zone
// name like "us-south-1" -> "us-south". Returns the input unchanged if
// the trailing segment after the last dash is not all digits — so
// "us-south" stays "us-south", not "us". Any all-digit suffix is
// accepted (including hypothetical "0") to stay forward-compatible
// with future IBM zone numbering.
func parseRegion(zone string) string {
	i := strings.LastIndex(zone, "-")
	if i < 0 {
		return zone
	}
	suffix := zone[i+1:]
	if suffix == "" {
		return zone
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return zone
		}
	}
	return zone[:i]
}

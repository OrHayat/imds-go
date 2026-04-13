// Package ociimds is the Oracle Cloud Infrastructure Instance Metadata
// Service (IMDS) provider for github.com/OrHayat/imds-go. It offers a
// client for fetching instance metadata, retrieving the per-instance
// x509 identity bundle (leaf cert, intermediate cert, and optionally a
// nonce-signing private key), and standalone verification helpers that
// validate the bundle against Oracle's regional root CA.
//
// The identity workflow is: GetIdentityDocument fetches cert.pem /
// intermediate.pem / key.pem from /opc/v2/identity/ on the instance;
// VerifyIdentityDocument validates the chain against Oracle's regional
// root CA bundle (fetched from auth.<region>.oraclecloud.com and
// cached), extracts tenancy/instance/compartment OCIDs from the leaf
// cert's subject attributes, and optionally verifies an RSA signature
// over a verifier-supplied nonce to prove freshness.
package ociimds

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

const ProviderID imds.ID = "oci"

const (
	defaultIPv4 = "http://169.254.169.254"
	defaultIPv6 = "http://[fd00:c1::a9fe:a9fe]"
	basePath    = "/opc/v2/"
)

type EndpointMode int

const (
	EndpointModeIPv4 EndpointMode = iota
	EndpointModeIPv6
)

type options struct {
	httpClient   *http.Client
	baseURL      string
	endpointMode EndpointMode
	timeout      time.Duration
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
	http    *httputil.Client
	baseURL string
}

func New(opts ...Option) (*Client, error) {
	o := options{}
	for _, fn := range opts {
		fn(&o)
	}

	base := strings.TrimRight(o.baseURL, "/")
	if base == "" {
		switch o.endpointMode {
		case EndpointModeIPv6:
			base = defaultIPv6
		default:
			base = defaultIPv4
		}
	}

	clientOpts := []httputil.ClientOption{
		httputil.WithBaseURL(base + basePath),
		httputil.WithDefaultHeader("Authorization", "Bearer Oracle"),
	}
	if o.httpClient != nil {
		clientOpts = append(clientOpts, httputil.WithHTTPClient(o.httpClient))
	}
	if o.timeout > 0 {
		clientOpts = append(clientOpts, httputil.WithTimeout(o.timeout))
	}

	hc, err := httputil.NewClient(ProviderID, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("ociimds: %w", err)
	}

	return &Client{
		http:    hc,
		baseURL: base,
	}, nil
}

func (c *Client) ID() imds.ID { return ProviderID }

func (c *Client) Probe(ctx context.Context) (bool, error) {
	_, err := c.Query(ctx, "instance/")
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

func (c *Client) GetInstanceDocument(ctx context.Context) (*InstanceDocument, error) {
	data, err := c.Query(ctx, "instance/")
	if err != nil {
		return nil, err
	}
	var inst InstanceDocument
	if err := json.Unmarshal(data, &inst); err != nil {
		return nil, fmt.Errorf("ociimds: unmarshal instance: %w", err)
	}
	return &inst, nil
}

func (c *Client) GetVNICs(ctx context.Context) ([]VNIC, error) {
	data, err := c.Query(ctx, "vnics/")
	if err != nil {
		return nil, err
	}
	var vnics []VNIC
	if err := json.Unmarshal(data, &vnics); err != nil {
		return nil, fmt.Errorf("ociimds: unmarshal vnics: %w", err)
	}
	return vnics, nil
}

func (c *Client) queryString(ctx context.Context, path string) (string, error) {
	data, err := c.Query(ctx, path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (c *Client) InstanceID(ctx context.Context) (string, error) {
	return c.queryString(ctx, "instance/id")
}

func (c *Client) Region(ctx context.Context) (string, error) {
	return c.queryString(ctx, "instance/region")
}

func (c *Client) Zone(ctx context.Context) (string, error) {
	return c.queryString(ctx, "instance/availabilityDomain")
}

func (c *Client) Shape(ctx context.Context) (string, error) {
	return c.queryString(ctx, "instance/shape")
}

func (c *Client) ImageID(ctx context.Context) (string, error) {
	return c.queryString(ctx, "instance/imageId")
}

func (c *Client) CompartmentID(ctx context.Context) (string, error) {
	return c.queryString(ctx, "instance/compartmentId")
}

func (c *Client) Hostname(ctx context.Context) (string, error) {
	return c.queryString(ctx, "instance/hostname")
}

func (c *Client) Tags(ctx context.Context) (map[string]string, error) {
	data, err := c.Query(ctx, "instance/freeformTags")
	if err != nil {
		return nil, err
	}
	var tags map[string]string
	if err := json.Unmarshal(data, &tags); err != nil {
		return nil, fmt.Errorf("ociimds: unmarshal freeformTags: %w", err)
	}
	return tags, nil
}

func (c *Client) Interfaces(ctx context.Context) ([]imds.NetworkInterface, error) {
	vnics, err := c.GetVNICs(ctx)
	if err != nil {
		return nil, err
	}
	return vnicsToInterfaces(vnics), nil
}

func vnicsToInterfaces(vnics []VNIC) []imds.NetworkInterface {
	ifaces := make([]imds.NetworkInterface, 0, len(vnics))
	for _, v := range vnics {
		iface := imds.NetworkInterface{
			ID:    v.VnicID,
			MAC:   v.MACAddress,
			VPCID: v.VirtualNetworkID,
		}
		if v.SubnetCIDRBlock != "" {
			iface.SubnetID = v.SubnetCIDRBlock
		}
		if v.PrivateIP != "" {
			iface.PrivateIPv4s = []string{v.PrivateIP}
		}
		if v.PublicIP != "" {
			iface.PublicIPv4s = []string{v.PublicIP}
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces
}

func (c *Client) GetMetadata(ctx context.Context) (*imds.InstanceMetadata, error) {
	inst, err := c.GetInstanceDocument(ctx)
	if err != nil {
		return nil, err
	}

	vnics, err := c.GetVNICs(ctx)
	if err != nil {
		return nil, err
	}

	md := &imds.InstanceMetadata{
		Provider: ProviderID,
		Instance: imds.InstanceInfo{
			ID:           inst.ID,
			InstanceType: inst.Shape,
			ImageID:      inst.ImageID,
			AccountID:    inst.CompartmentID,
			Hostname:     inst.Hostname,
			Architecture: imds.RuntimeArchitecture(),
			Location: imds.Location{
				Region:      inst.Region,
				Zone:        inst.AvailabilityDomain,
				FaultDomain: inst.FaultDomain,
			},
		},
		Tags:       inst.FreeformTags,
		Interfaces: vnicsToInterfaces(vnics),
	}

	if inst.DisplayName != "" {
		md.AdditionalProperties = map[string]any{
			"displayName": inst.DisplayName,
		}
	}

	return md, nil
}

func (c *Client) Watch(ctx context.Context, cfg imds.WatchConfig) (<-chan imds.Event, error) {
	return watchutil.PollWatch(ctx, cfg, c.GetMetadata)
}

type InstanceDocument struct {
	ID                 string            `json:"id"`
	Shape              string            `json:"shape"`
	Region             string            `json:"region"`
	AvailabilityDomain string            `json:"availabilityDomain"`
	ImageID            string            `json:"imageId"`
	CompartmentID      string            `json:"compartmentId"`
	Hostname           string            `json:"hostname"`
	DisplayName        string            `json:"displayName"`
	FaultDomain        string            `json:"faultDomain"`
	FreeformTags       map[string]string `json:"freeformTags"`
}

type VNIC struct {
	VnicID           string `json:"vnicId"`
	PrivateIP        string `json:"privateIp"`
	PublicIP         string `json:"publicIp"`
	MACAddress       string `json:"macAddress"`
	SubnetCIDRBlock  string `json:"subnetCidrBlock"`
	VirtualNetworkID string `json:"virtualNetworkId"`
}

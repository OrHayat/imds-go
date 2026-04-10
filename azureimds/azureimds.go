// Package azureimds is the Azure Instance Metadata Service (IMDS) provider
// for github.com/OrHayat/imds-go. It offers a client for fetching instance
// metadata and retrieving signed attested documents, plus standalone
// verification helpers that parse and validate those documents.
//
// The attestation workflow is: GetAttestedDocument fetches a PKCS7 blob
// from /metadata/attested/document; VerifyAttestedDocument (or
// VerifyAttestedDocumentWithRoots for off-cloud verifiers with their own
// trust pool) validates the signature, signer chain, timestamp window,
// and optional nonce, and returns typed Claims describing the VM.
package azureimds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	imds "github.com/OrHayat/imds-go"
	"github.com/OrHayat/imds-go/internal/httputil"
	"github.com/OrHayat/imds-go/internal/watchutil"
)

const ProviderID imds.ID = "azure"

const (
	defaultBaseURL    = "http://169.254.169.254"
	defaultAPIVersion = "2021-02-01"
)

type options struct {
	timeout    time.Duration
	httpClient *http.Client
	baseURL    string
	apiVersion string
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

func WithAPIVersion(v string) Option {
	return func(o *options) { o.apiVersion = v }
}

type Client struct {
	http *httputil.Client
}

func New(opts ...Option) *Client {
	o := options{
		baseURL:    defaultBaseURL,
		apiVersion: defaultAPIVersion,
	}
	for _, fn := range opts {
		fn(&o)
	}
	if o.baseURL == "" {
		o.baseURL = defaultBaseURL
	}
	if o.apiVersion == "" {
		o.apiVersion = defaultAPIVersion
	}

	clientOpts := []httputil.ClientOption{
		httputil.WithBaseURL(o.baseURL),
		httputil.WithDefaultHeader("Metadata", "true"),
		httputil.WithDefaultQuery("api-version", o.apiVersion),
	}
	if o.httpClient != nil {
		clientOpts = append(clientOpts, httputil.WithHTTPClient(o.httpClient))
	}
	if o.timeout > 0 {
		clientOpts = append(clientOpts, httputil.WithTimeout(o.timeout))
	}

	hc, err := httputil.NewClient(ProviderID, clientOpts...)
	if err != nil {
		// Unreachable: defaults always provide a valid base URL and provider ID.
		panic(fmt.Sprintf("azureimds: %v", err))
	}
	return &Client{http: hc}
}

func (c *Client) ID() imds.ID { return ProviderID }

func (c *Client) Probe(ctx context.Context) (bool, error) {
	_, err := c.Query(ctx, "/metadata/instance/compute/vmId?format=text")
	if err == nil {
		return true, nil
	}
	var me *imds.MetadataError
	if errors.As(err, &me) && me.StatusCode < 500 {
		return false, nil
	}
	return false, err
}

func (c *Client) GetInstanceDocument(ctx context.Context) (*InstanceDocument, error) {
	body, err := c.Query(ctx, "/metadata/instance")
	if err != nil {
		return nil, err
	}

	var doc InstanceDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("azureimds: unmarshal: %w", err)
	}

	return &doc, nil
}

func (c *Client) GetMetadata(ctx context.Context) (*imds.InstanceMetadata, error) {
	doc, err := c.GetInstanceDocument(ctx)
	if err != nil {
		return nil, err
	}
	md := mapMetadata(doc)
	if events, err := c.getScheduledEvents(ctx); err == nil {
		md.SpotTerminating = hasPreemptEvent(events)
		md.MaintenanceEvents = toMaintenanceEvents(events)
	}
	return md, nil
}

type scheduledEventsResponse struct {
	Events []scheduledEvent `json:"Events"`
}

type scheduledEvent struct {
	EventType    string `json:"EventType"`
	EventStatus  string `json:"EventStatus"`
	NotBefore    string `json:"NotBefore"`
	ResourceType string `json:"ResourceType"`
}

func (c *Client) SpotTerminating(ctx context.Context) (bool, error) {
	events, err := c.getScheduledEvents(ctx)
	if err != nil {
		return false, err
	}
	return hasPreemptEvent(events), nil
}

func (c *Client) MaintenanceEvents(ctx context.Context) ([]imds.MaintenanceEvent, error) {
	events, err := c.getScheduledEvents(ctx)
	if err != nil {
		return nil, err
	}
	return toMaintenanceEvents(events), nil
}

func hasPreemptEvent(events []scheduledEvent) bool {
	for _, e := range events {
		if strings.EqualFold(e.EventType, "Preempt") {
			return true
		}
	}
	return false
}

func toMaintenanceEvents(events []scheduledEvent) []imds.MaintenanceEvent {
	out := make([]imds.MaintenanceEvent, 0, len(events))
	for _, e := range events {
		me := imds.MaintenanceEvent{
			ProviderType: strings.ToLower(e.EventType),
			Status:       imds.EventStatus(strings.ToLower(e.EventStatus)),
		}
		if t, err := time.Parse(time.RFC3339, e.NotBefore); err == nil {
			me.Before = t
		}
		out = append(out, me)
	}
	return out
}

// getScheduledEvents pins api-version to 2020-07-01 independent of WithAPIVersion,
// because scheduledevents is served by a separate service with its own versioning.
func (c *Client) getScheduledEvents(ctx context.Context) ([]scheduledEvent, error) {
	body, err := c.http.GetWithQuery(ctx, "/metadata/scheduledevents",
		url.Values{"api-version": {"2020-07-01"}})
	if err != nil {
		return nil, err
	}
	var resp scheduledEventsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("azureimds: unmarshal scheduled events: %w", err)
	}
	return resp.Events, nil
}

func (c *Client) VMID(ctx context.Context) (string, error) {
	return c.queryText(ctx, "/metadata/instance/compute/vmId")
}

func (c *Client) Region(ctx context.Context) (string, error) {
	return c.queryText(ctx, "/metadata/instance/compute/location")
}

func (c *Client) Zone(ctx context.Context) (string, error) {
	return c.queryText(ctx, "/metadata/instance/compute/zone")
}

func (c *Client) VMSize(ctx context.Context) (string, error) {
	return c.queryText(ctx, "/metadata/instance/compute/vmSize")
}

func (c *Client) SubscriptionID(ctx context.Context) (string, error) {
	return c.queryText(ctx, "/metadata/instance/compute/subscriptionId")
}

func (c *Client) Hostname(ctx context.Context) (string, error) {
	return c.queryText(ctx, "/metadata/instance/compute/name")
}

func (c *Client) Tags(ctx context.Context) (map[string]string, error) {
	body, err := c.Query(ctx, "/metadata/instance/compute/tagsList")
	if err != nil {
		return nil, err
	}
	var tags []Tag
	if err := json.Unmarshal(body, &tags); err != nil {
		return nil, fmt.Errorf("azureimds: unmarshal tags: %w", err)
	}
	return mapTags(tags), nil
}

func (c *Client) Interfaces(ctx context.Context) ([]imds.NetworkInterface, error) {
	body, err := c.Query(ctx, "/metadata/instance/network/interface")
	if err != nil {
		return nil, err
	}
	var ifaces []Interface
	if err := json.Unmarshal(body, &ifaces); err != nil {
		return nil, fmt.Errorf("azureimds: unmarshal interfaces: %w", err)
	}
	return mapInterfaces(ifaces), nil
}

func (c *Client) Watch(ctx context.Context, cfg imds.WatchConfig) (<-chan imds.Event, error) {
	return watchutil.PollWatch(ctx, cfg, c.GetMetadata)
}

func (c *Client) Query(ctx context.Context, path string) ([]byte, error) {
	return c.http.Get(ctx, path)
}

func (c *Client) queryText(ctx context.Context, path string) (string, error) {
	body, err := c.Query(ctx, path+"?format=text")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

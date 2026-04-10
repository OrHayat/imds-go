package awsimds

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	imdspkg "github.com/OrHayat/imds-go"
	"github.com/OrHayat/imds-go/internal/watchutil"
)

const ProviderID imdspkg.ID = "aws"

type Client struct {
	sdk *imds.Client
}

func New(opts imds.Options, optFns ...func(*imds.Options)) *Client {
	return &Client{sdk: imds.New(opts, optFns...)}
}

func NewFromConfig(cfg aws.Config, optFns ...func(*imds.Options)) *Client {
	return &Client{sdk: imds.NewFromConfig(cfg, optFns...)}
}

func (c *Client) ID() imdspkg.ID { return ProviderID }

func (c *Client) Probe(ctx context.Context) (bool, error) {
	_, err := c.Query(ctx, "instance-id")
	if err == nil {
		return true, nil
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		return false, nil
	}
	return false, err
}

func (c *Client) GetIdentityDocument(ctx context.Context) (*imds.GetInstanceIdentityDocumentOutput, error) {
	return c.sdk.GetInstanceIdentityDocument(ctx, nil)
}

func (c *Client) Hostname(ctx context.Context) (string, error) {
	return c.getMetadataString(ctx, "hostname")
}

func (c *Client) Interfaces(ctx context.Context) ([]imdspkg.NetworkInterface, error) {
	return c.fetchInterfaces(ctx)
}

func (c *Client) Tags(ctx context.Context) (map[string]string, error) {
	return c.fetchTags(ctx)
}

func (c *Client) Region(ctx context.Context) (string, error) {
	out, err := c.sdk.GetRegion(ctx, nil)
	if err != nil {
		return "", err
	}
	return out.Region, nil
}

func (c *Client) SpotTerminating(ctx context.Context) (bool, error) {
	_, err := c.getMetadataString(ctx, "spot/termination-time")
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (c *Client) GetMetadata(ctx context.Context) (*imdspkg.InstanceMetadata, error) {
	doc, err := c.sdk.GetInstanceIdentityDocument(ctx, nil)
	if err != nil {
		return nil, err
	}

	md := &imdspkg.InstanceMetadata{
		Provider: ProviderID,
		Instance: imdspkg.InstanceInfo{
			ID:           doc.InstanceID,
			InstanceType: doc.InstanceType,
			ImageID:      doc.ImageID,
			AccountID:    doc.AccountID,
			Architecture: imdspkg.NormalizeArch(doc.Architecture),
			Location: imdspkg.Location{
				Region: doc.Region,
				Zone:   doc.AvailabilityZone,
			},
		},
	}
	md.Instance.Hostname, _ = c.Hostname(ctx)
	md.Instance.Location.FaultDomain, _ = c.getMetadataString(ctx, "placement/partition-number")
	md.Interfaces, _ = c.Interfaces(ctx)
	md.Tags, _ = c.Tags(ctx)
	md.SpotTerminating, _ = c.SpotTerminating(ctx)
	md.MaintenanceEvents, _ = c.MaintenanceEvents(ctx)

	return md, nil
}

func (c *Client) Watch(ctx context.Context, cfg imdspkg.WatchConfig) (<-chan imdspkg.Event, error) {
	return watchutil.PollWatch(ctx, cfg, c.GetMetadata)
}

func (c *Client) Query(ctx context.Context, path string) ([]byte, error) {
	out, err := c.sdk.GetMetadata(ctx, &imds.GetMetadataInput{Path: path})
	if err != nil {
		return nil, err
	}
	defer out.Content.Close()
	return io.ReadAll(out.Content)
}

func (c *Client) getMetadataString(ctx context.Context, path string) (string, error) {
	b, err := c.Query(ctx, path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *Client) fetchInterfaces(ctx context.Context) ([]imdspkg.NetworkInterface, error) {
	macsRaw, err := c.getMetadataString(ctx, "network/interfaces/macs/")
	if err != nil {
		return nil, err
	}

	var ifaces []imdspkg.NetworkInterface
	for _, mac := range splitLines(macsRaw) {
		mac = strings.TrimSuffix(mac, "/")
		if mac == "" {
			continue
		}
		prefix := "network/interfaces/macs/" + mac + "/"
		iface := imdspkg.NetworkInterface{MAC: mac}
		if v, err := c.getMetadataString(ctx, prefix+"interface-id"); err == nil {
			iface.ID = v
		}

		if v, err := c.getMetadataString(ctx, prefix+"local-ipv4s"); err == nil && v != "" {
			iface.PrivateIPv4s = splitLines(v)
		}
		if v, err := c.getMetadataString(ctx, prefix+"public-ipv4s"); err == nil && v != "" {
			iface.PublicIPv4s = splitLines(v)
		}
		if v, err := c.getMetadataString(ctx, prefix+"ipv6s"); err == nil && v != "" {
			iface.IPv6s = splitLines(v)
		}
		if v, err := c.getMetadataString(ctx, prefix+"subnet-id"); err == nil {
			iface.SubnetID = v
		}
		if v, err := c.getMetadataString(ctx, prefix+"vpc-id"); err == nil {
			iface.VPCID = v
		}

		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

func (c *Client) fetchTags(ctx context.Context) (map[string]string, error) {
	keysRaw, err := c.getMetadataString(ctx, "tags/instance/")
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string)
	for _, key := range splitLines(keysRaw) {
		if key == "" {
			continue
		}
		if v, err := c.getMetadataString(ctx, "tags/instance/"+key); err == nil {
			tags[key] = v
		}
	}
	return tags, nil
}

type awsMaintenanceEvent struct {
	Code        string `json:"Code"`
	State       string `json:"State"`
	NotBefore   string `json:"NotBefore"`
	Description string `json:"Description"`
}

func (c *Client) MaintenanceEvents(ctx context.Context) ([]imdspkg.MaintenanceEvent, error) {
	raw, err := c.Query(ctx, "events/maintenance/scheduled")
	if err != nil {
		return nil, err
	}
	var events []awsMaintenanceEvent
	if err := json.Unmarshal(raw, &events); err != nil {
		return nil, err
	}
	var out []imdspkg.MaintenanceEvent
	for _, e := range events {
		code := strings.ToLower(e.Code)
		me := imdspkg.MaintenanceEvent{
			Type:         awsEventType(code),
			ProviderType: code,
			Status:       awsEventStatus(strings.ToLower(e.State)),
		}
		if t, err := time.Parse(time.RFC3339, e.NotBefore); err == nil {
			me.Before = t
		}
		out = append(out, me)
	}
	return out, nil
}

func awsEventType(code string) imdspkg.EventType {
	switch code {
	case "instance-reboot", "system-reboot":
		return imdspkg.EventTypeReboot
	case "system-maintenance":
		return imdspkg.EventTypeMigrate
	case "instance-retirement", "instance-stop":
		return imdspkg.EventTypeTerminate
	}
	return ""
}

func awsEventStatus(state string) imdspkg.EventStatus {
	if state == "active" {
		return imdspkg.EventStatusStarted
	}
	return ""
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

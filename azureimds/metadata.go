package azureimds

import (
	"fmt"

	imds "github.com/OrHayat/imds-go"
)

type InstanceDocument struct {
	Compute Compute `json:"compute"`
	Network Network `json:"network"`
}

type Compute struct {
	VMID                 string  `json:"vmId"`
	Location             string  `json:"location"`
	Zone                 string  `json:"zone"`
	PhysicalZone         string  `json:"physicalZone"`
	VMSize               string  `json:"vmSize"`
	SubscriptionID       string  `json:"subscriptionId"`
	Name                 string  `json:"name"`
	ResourceID           string  `json:"resourceId"`
	AzEnvironment        string  `json:"azEnvironment"`
	OSType               string  `json:"osType"`
	LicenseType          string  `json:"licenseType"`
	PlatformFaultDomain  string  `json:"platformFaultDomain"`
	PlatformUpdateDomain string  `json:"platformUpdateDomain"`
	ResourceGroupName    string  `json:"resourceGroupName"`
	VMScaleSetName       string  `json:"vmScaleSetName"`
	StorageProfile       Storage `json:"storageProfile"`
	TagsList             []Tag   `json:"tagsList"`
}

type Storage struct {
	ImageReference ImageRef `json:"imageReference"`
}

type ImageRef struct {
	Offer   string `json:"offer"`
	SKU     string `json:"sku"`
	Version string `json:"version"`
}

type Tag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Network struct {
	Interfaces []Interface `json:"interface"`
}

type Interface struct {
	MACAddress string   `json:"macAddress"`
	IPv4       IPFamily `json:"ipv4"`
	IPv6       IPFamily `json:"ipv6"`
}

type IPFamily struct {
	IPAddress []IPAddress `json:"ipAddress"`
	Subnet    []Subnet    `json:"subnet"`
}

type IPAddress struct {
	PrivateIPAddress string `json:"privateIpAddress"`
	PublicIPAddress  string `json:"publicIpAddress"`
}

type Subnet struct {
	Address string `json:"address"`
	Prefix  string `json:"prefix"`
}

func mapTags(tagsList []Tag) map[string]string {
	if len(tagsList) == 0 {
		return nil
	}
	tags := make(map[string]string, len(tagsList))
	for _, t := range tagsList {
		tags[t.Name] = t.Value
	}
	return tags
}

func mapInterfaces(raw []Interface) []imds.NetworkInterface {
	ifaces := make([]imds.NetworkInterface, 0, len(raw))
	for _, iface := range raw {
		ni := imds.NetworkInterface{MAC: iface.MACAddress}
		for _, ip := range iface.IPv4.IPAddress {
			if ip.PrivateIPAddress != "" {
				ni.PrivateIPv4s = append(ni.PrivateIPv4s, ip.PrivateIPAddress)
			}
			if ip.PublicIPAddress != "" {
				ni.PublicIPv4s = append(ni.PublicIPv4s, ip.PublicIPAddress)
			}
		}
		for _, ip := range iface.IPv6.IPAddress {
			if ip.PrivateIPAddress != "" {
				ni.IPv6s = append(ni.IPv6s, ip.PrivateIPAddress)
			}
		}
		if len(iface.IPv4.Subnet) > 0 {
			s := iface.IPv4.Subnet[0]
			ni.SubnetID = s.Address + "/" + s.Prefix
		}
		ifaces = append(ifaces, ni)
	}
	return ifaces
}

func mapMetadata(raw *InstanceDocument) *imds.InstanceMetadata {
	c := &raw.Compute

	additional := map[string]any{}
	addIfSet := func(key, val string) {
		if val != "" {
			additional[key] = val
		}
	}
	addIfSet("platformUpdateDomain", c.PlatformUpdateDomain)
	addIfSet("resourceGroupName", c.ResourceGroupName)
	addIfSet("vmScaleSetName", c.VMScaleSetName)
	addIfSet("resourceId", c.ResourceID)
	addIfSet("azEnvironment", c.AzEnvironment)
	addIfSet("osType", c.OSType)
	addIfSet("licenseType", c.LicenseType)
	addIfSet("physicalZone", c.PhysicalZone)
	if len(additional) == 0 {
		additional = nil
	}

	return &imds.InstanceMetadata{
		Provider: ProviderID,
		Instance: imds.InstanceInfo{
			ID:           c.VMID,
			InstanceType: c.VMSize,
			ImageID:      formatImageID(c.StorageProfile.ImageReference),
			AccountID:    c.SubscriptionID,
			Hostname:     c.Name,
			Architecture: imds.RuntimeArchitecture(),
			Location: imds.Location{
				Region:      c.Location,
				Zone:        c.Zone,
				FaultDomain: c.PlatformFaultDomain,
			},
		},
		Interfaces:           mapInterfaces(raw.Network.Interfaces),
		Tags:                 mapTags(c.TagsList),
		AdditionalProperties: additional,
	}
}

func formatImageID(ref ImageRef) string {
	if ref.Offer == "" && ref.SKU == "" && ref.Version == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s:%s", ref.Offer, ref.SKU, ref.Version)
}

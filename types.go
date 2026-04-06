package imds

// InstanceMetadata is the normalized, cross-provider metadata struct.
type InstanceMetadata struct {
	Provider             ID                  `json:"provider"`
	Instance             InstanceInfo        `json:"instance"`
	Interfaces           []NetworkInterface  `json:"interfaces"`
	Tags                 map[string]string   `json:"tags,omitempty"`
	AdditionalProperties map[string]any      `json:"additional_properties,omitempty"`
}

// InstanceInfo holds compute instance details.
type InstanceInfo struct {
	ID           string   `json:"id"`
	Location     Location `json:"location"`
	InstanceType string   `json:"instance_type,omitempty"`
	ImageID      string   `json:"image_id,omitempty"`
	AccountID    string   `json:"account_id,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
}

// Location identifies where an instance is running.
type Location struct {
	Region string `json:"region"`
	Zone   string `json:"zone,omitempty"`
}

// NetworkInterface holds network configuration for a single interface.
type NetworkInterface struct {
	ID           string   `json:"id,omitempty"`
	Name         string   `json:"name,omitempty"`
	PrivateIPv4s []string `json:"private_ipv4s"`
	PublicIPv4s  []string `json:"public_ipv4s,omitempty"`
	IPv6s        []string `json:"ipv6s,omitempty"`
	MAC          string   `json:"mac"`
	SubnetID     string   `json:"subnet_id,omitempty"`
	VPCID        string   `json:"vpc_id,omitempty"`
}

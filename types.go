package imds

import (
	"runtime"
	"time"
)

// InstanceMetadata is the normalized, cross-provider metadata struct.
type InstanceMetadata struct {
	Provider             ID                  `json:"provider"`
	Instance             InstanceInfo        `json:"instance"`
	Interfaces           []NetworkInterface  `json:"interfaces"`
	Tags                 map[string]string   `json:"tags,omitempty"`
	SpotTerminating      bool                `json:"spot_terminating,omitempty"`
	MaintenanceEvents    []MaintenanceEvent  `json:"maintenance_events,omitempty"`
	AdditionalProperties map[string]any      `json:"additional_properties,omitempty"`
}

// EventType is the normalized maintenance-event category. Provider mappers
// populate it when a provider-specific code cleanly fits a bucket; if no
// bucket fits, leave it empty and rely on ProviderType for the verbatim value.
type EventType string

const (
	EventTypeReboot    EventType = "reboot"
	EventTypeTerminate EventType = "terminate"
	EventTypeMigrate   EventType = "migrate"
	EventTypePause     EventType = "pause"
)

// EventStatus is the normalized maintenance-event lifecycle state.
type EventStatus string

const (
	EventStatusScheduled EventStatus = "scheduled"
	EventStatusStarted   EventStatus = "started"
)

// MaintenanceEvent describes a scheduled maintenance action.
type MaintenanceEvent struct {
	Type         EventType   `json:"type"`          // normalized bucket; "" if no mapping fits
	ProviderType string      `json:"provider_type"` // verbatim provider event identifier, lowercased
	Status       EventStatus `json:"status"`
	Before       time.Time   `json:"before"`
}

// InstanceInfo holds compute instance details.
type InstanceInfo struct {
	ID           string   `json:"id"`
	Location     Location `json:"location"`
	InstanceType string   `json:"instance_type,omitempty"`
	ImageID      string   `json:"image_id,omitempty"`
	AccountID    string   `json:"account_id,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	Architecture string   `json:"architecture,omitempty"`
}

// NormalizeArch maps platform architecture strings to Go convention.
func NormalizeArch(s string) string {
	switch s {
	case "x86_64":
		return "amd64"
	case "i386", "i686":
		return "386"
	case "aarch64":
		return "arm64"
	default:
		return s
	}
}

// RuntimeArchitecture returns the CPU architecture from runtime.GOARCH.
func RuntimeArchitecture() string {
	return runtime.GOARCH
}

// Location identifies where an instance is running.
type Location struct {
	Region      string `json:"region"`
	Zone        string `json:"zone,omitempty"`
	FaultDomain string `json:"fault_domain,omitempty"`
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

package models

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

type AlertSeverity string

const (
	SeverityInfo     AlertSeverity = "INFO"
	SeverityLow      AlertSeverity = "LOW"
	SeverityMedium   AlertSeverity = "MEDIUM"
	SeverityHigh     AlertSeverity = "HIGH"
	SeverityCritical AlertSeverity = "CRITICAL"
)

type CloudServiceType string

const (
	CloudServiceUnknown        CloudServiceType = "UNKNOWN"
	CloudServiceAWSIMDS        CloudServiceType = "AWS_IMDS"
	CloudServiceAWSS3          CloudServiceType = "AWS_S3"
	CloudServiceAWSSTS         CloudServiceType = "AWS_STS"
	CloudServiceAWSSecrets     CloudServiceType = "AWS_SECRETS_MANAGER"
	CloudServiceKubeAPIServer  CloudServiceType = "KUBE_API_SERVER"
	CloudServiceExternalPublic CloudServiceType = "EXTERNAL_PUBLIC"
)

// PodContext contains Kubernetes metadata enriched from cgroups
type PodContext struct {
	PodName        string            `json:"pod_name"`
	Namespace      string            `json:"namespace"`
	ContainerID    string            `json:"container_id"`
	ContainerName  string            `json:"container_name"`
	ServiceAccount string            `json:"service_account"`
	IAMRoleARN     string            `json:"iam_role_arn,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
}

// EgressEvent represents a raw or enriched network event originating from the Linux kernel
type EgressEvent struct {
	Timestamp      time.Time        `json:"timestamp"`
	PID            uint32           `json:"pid"`
	TGID           uint32           `json:"tgid"`
	CgroupID       uint64           `json:"cgroup_id"`
	Command        string           `json:"comm"`
	SourceAddress  net.IP           `json:"source_ip"`
	DestAddress    net.IP           `json:"dest_ip"`
	SourcePort     uint16           `json:"source_port"`
	DestPort       uint16           `json:"dest_port"`
	Protocol       string           `json:"protocol"`
	Flags          uint8            `json:"flags"`
	CloudService   CloudServiceType `json:"cloud_service"`
	Pod            *PodContext      `json:"pod,omitempty"`
}

func (e *EgressEvent) String() string {
	podInfo := "host"
	if e.Pod != nil {
		podInfo = fmt.Sprintf("%s/%s", e.Pod.Namespace, e.Pod.PodName)
	}
	return fmt.Sprintf("[%s] %s (%s:%d -> %s:%d) Service: %s Comm: %s",
		e.Timestamp.Format("15:04:05.000"),
		podInfo,
		e.SourceAddress, e.SourcePort,
		e.DestAddress, e.DestPort,
		e.CloudService,
		e.Command,
	)
}

// SecurityAlert represents a policy violation or anomaly detected at runtime
type SecurityAlert struct {
	ID          string        `json:"id"`
	Timestamp   time.Time     `json:"timestamp"`
	Severity    AlertSeverity `json:"severity"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	RuleName    string        `json:"rule_name"`
	Event       EgressEvent   `json:"event"`
	Mitigation  string        `json:"mitigation"`
}

func (a *SecurityAlert) ToJSON() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

package engine

import (
	"net"
	"strings"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

// ClassifyCloudIP evaluates public destination IPs against known cloud service CIDR ranges
func ClassifyCloudIP(ip net.IP) models.CloudServiceType {
	if ip == nil {
		return models.CloudServiceUnknown
	}

	ipStr := ip.String()

	// AWS well-known address patterns or heuristics
	if strings.HasPrefix(ipStr, "52.") || strings.HasPrefix(ipStr, "54.") || strings.HasPrefix(ipStr, "3.") {
		return models.CloudServiceAWSS3
	}

	if strings.HasPrefix(ipStr, "18.") {
		return models.CloudServiceAWSSTS
	}

	return models.CloudServiceExternalPublic
}

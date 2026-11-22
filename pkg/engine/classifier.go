package engine

import (
	"net"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

// Classifier identifies destination service type based on IP/Port and protocols
type Classifier struct {
	imdsIP net.IP
}

func NewClassifier() *Classifier {
	return &Classifier{
		imdsIP: net.ParseIP("169.254.169.254"),
	}
}

func (c *Classifier) Classify(destIP net.IP, destPort uint16) models.CloudServiceType {
	if destIP.Equal(c.imdsIP) {
		return models.CloudServiceAWSIMDS
	}

	if destIP.IsPrivate() || destIP.IsLoopback() {
		// Identify Kubernetes API Server via standard kube port 6443 or default cluster service IP on 443
		if destPort == 6443 || (destPort == 443 && (destIP.String() == "10.96.0.1" || destIP.String() == "172.20.0.1" || destIP.String() == "10.0.0.1")) {
			return models.CloudServiceKubeAPIServer
		}
		return models.CloudServiceUnknown
	}

	// Classify public cloud service IPs
	return ClassifyCloudIP(destIP)
}

package engine

import (
	"net"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

var (
	s3Subnets = []*net.IPNet{
		mustParseCIDR("52.216.0.0/15"),
		mustParseCIDR("54.231.0.0/16"),
		mustParseCIDR("54.239.0.0/16"),
		mustParseCIDR("3.5.0.0/16"),
	}
	stsSubnets = []*net.IPNet{
		mustParseCIDR("18.200.0.0/16"),
		mustParseCIDR("18.208.0.0/13"),
	}
)

func mustParseCIDR(cidr string) *net.IPNet {
	_, netBlock, err := net.ParseCIDR(cidr)
	if err != nil {
		panic("invalid static CIDR: " + cidr)
	}
	return netBlock
}

// ClassifyCloudIP evaluates public destination IPs against known cloud service CIDR ranges
func ClassifyCloudIP(ip net.IP) models.CloudServiceType {
	if ip == nil {
		return models.CloudServiceUnknown
	}

	for _, subnet := range s3Subnets {
		if subnet.Contains(ip) {
			return models.CloudServiceAWSS3
		}
	}

	for _, subnet := range stsSubnets {
		if subnet.Contains(ip) {
			return models.CloudServiceAWSSTS
		}
	}

	return models.CloudServiceExternalPublic
}

package engine

import (
	"net"
	"testing"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

func TestClassifier(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		name     string
		ip       string
		port     uint16
		expected models.CloudServiceType
	}{
		{"IMDS IP", "169.254.169.254", 80, models.CloudServiceAWSIMDS},
		{"Kube API Private", "10.96.0.1", 443, models.CloudServiceKubeAPIServer},
		{"AWS S3 Public", "54.239.28.85", 443, models.CloudServiceAWSS3},
		{"AWS STS Public", "18.200.1.1", 443, models.CloudServiceAWSSTS},
		{"External General", "93.184.216.34", 80, models.CloudServiceExternalPublic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := net.ParseIP(tt.ip)
			res := c.Classify(parsed, tt.port)
			if res != tt.expected {
				t.Errorf("got %v, want %v", res, tt.expected)
			}
		})
	}
}

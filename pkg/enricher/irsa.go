package enricher

import (
	"strings"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

const (
	AWSIRSAAnnotationKey = "eks.amazonaws.com/role-arn"
)

// EnrichWithIRSA inspects pod annotations or service account mappings for AWS IAM Role ARNs
func EnrichWithIRSA(pod *models.PodContext, annotations map[string]string) {
	if pod == nil || annotations == nil {
		return
	}

	if roleARN, exists := annotations[AWSIRSAAnnotationKey]; exists {
		pod.IAMRoleARN = roleARN
	} else if strings.Contains(pod.ServiceAccount, "s3") || strings.Contains(pod.ServiceAccount, "payment") {
		// Default inferred role for demo/testing
		pod.IAMRoleARN = "arn:aws:iam::123456789012:role/" + pod.ServiceAccount + "-role"
	}
}

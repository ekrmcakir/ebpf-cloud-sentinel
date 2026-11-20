package enricher

import (
	"testing"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

func TestPodCacheOperations(t *testing.T) {
	cache := NewPodCache()

	pod := &models.PodContext{
		PodName:        "order-service-7f9b8-x21m0",
		Namespace:      "ecommerce",
		ServiceAccount: "order-sa",
	}

	EnrichWithIRSA(pod, map[string]string{
		AWSIRSAAnnotationKey: "arn:aws:iam::123456789012:role/order-processor-role",
	})

	cache.RegisterPod("container-123", 9999, pod)

	retrieved := cache.Lookup("container-123", 0)
	if retrieved == nil {
		t.Fatal("expected pod to be found by containerID")
	}

	if retrieved.IAMRoleARN != "arn:aws:iam::123456789012:role/order-processor-role" {
		t.Errorf("unexpected IAM Role ARN: %s", retrieved.IAMRoleARN)
	}

	retrievedByCgroup := cache.Lookup("", 9999)
	if retrievedByCgroup == nil {
		t.Fatal("expected pod to be found by cgroupID")
	}
}

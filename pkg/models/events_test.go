package models

import (
	"net"
	"testing"
	"time"
)

func TestEgressEventFormatting(t *testing.T) {
	evt := &EgressEvent{
		Timestamp:     time.Now(),
		PID:           1024,
		Command:       "curl",
		SourceAddress: net.ParseIP("10.244.1.15"),
		DestAddress:   net.ParseIP("169.254.169.254"),
		SourcePort:    42100,
		DestPort:      80,
		Protocol:      "TCP",
		CloudService:  CloudServiceAWSIMDS,
		Pod: &PodContext{
			PodName:        "payment-worker-89f4b-m7z4c",
			Namespace:      "production",
			ServiceAccount: "payment-sa",
			IAMRoleARN:     "arn:aws:iam::123456789012:role/payment-processor",
		},
	}

	str := evt.String()
	if str == "" {
		t.Fatal("expected non-empty string representation")
	}

	alert := &SecurityAlert{
		ID:          "alert-001",
		Timestamp:   time.Now(),
		Severity:    SeverityCritical,
		Title:       "Unauthorized IMDSv2 Access",
		Description: "Pod attempted to query instance metadata without authorized token header",
		RuleName:    "imds-ssrf-guard",
		Event:       *evt,
		Mitigation:  "Apply AWS IMDS Hop Limit = 1 or enforce K8s NetworkPolicy",
	}

	jsonBytes, err := alert.ToJSON()
	if err != nil {
		t.Fatalf("failed to marshal alert: %v", err)
	}

	if len(jsonBytes) == 0 {
		t.Fatal("expected json payload to have content")
	}
}

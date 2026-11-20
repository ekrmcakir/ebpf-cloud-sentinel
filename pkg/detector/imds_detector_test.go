package detector

import (
	"net"
	"testing"
	"time"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

func TestIMDSDetector(t *testing.T) {
	det := NewIMDSDetector()

	normalEvt := &models.EgressEvent{
		Timestamp:    time.Now(),
		CloudService: models.CloudServiceExternalPublic,
		DestAddress:  net.ParseIP("93.184.216.34"),
	}

	if alert := det.Evaluate(normalEvt); alert != nil {
		t.Fatalf("expected nil alert for normal public egress, got %v", alert)
	}

	imdsEvt := &models.EgressEvent{
		Timestamp:    time.Now(),
		Command:      "curl",
		CloudService: models.CloudServiceAWSIMDS,
		DestAddress:  net.ParseIP("169.254.169.254"),
		Pod: &models.PodContext{
			PodName:   "compromised-pod-1",
			Namespace: "default",
		},
	}

	alert := det.Evaluate(imdsEvt)
	if alert == nil {
		t.Fatal("expected security alert for IMDS egress")
	}

	if alert.Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %v", alert.Severity)
	}
}

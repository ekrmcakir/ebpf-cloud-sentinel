package detector

import (
	"net"
	"testing"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

func TestRateDetector(t *testing.T) {
	rd := NewRateDetector(3)
	defer rd.Close()

	evt := &models.EgressEvent{
		Command:     "exfil",
		DestAddress: net.ParseIP("198.51.100.1"),
	}

	for i := 1; i <= 3; i++ {
		alert := rd.Evaluate(evt)
		if alert != nil {
			t.Fatalf("unexpected alert on iteration %d before threshold", i)
		}
	}

	// 4th event exceeds threshold 3
	alert := rd.Evaluate(evt)
	if alert == nil {
		t.Fatal("expected alert when egress frequency exceeds threshold")
	}

	if alert.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", alert.Severity)
	}
}

func TestRateDetectorLifecycle(t *testing.T) {
	rd := NewRateDetector(10)
	if err := rd.Close(); err != nil {
		t.Fatalf("expected clean close, got %v", err)
	}

	// Evaluate after close should safely return nil without panic
	evt := &models.EgressEvent{
		Command:     "curl",
		DestAddress: net.ParseIP("198.51.100.1"),
	}
	if alert := rd.Evaluate(evt); alert != nil {
		t.Fatalf("expected nil after close, got %v", alert)
	}
}

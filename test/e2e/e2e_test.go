package e2e

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/detector"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/ebpf"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/engine"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/enricher"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/telemetry"
)

func TestEndToEndEgressCaptureToAlert(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockDriver := ebpf.NewMockDriver()
	if err := mockDriver.Init(ctx); err != nil {
		t.Fatalf("failed to init mock driver: %v", err)
	}
	defer mockDriver.Close()

	classifier := engine.NewClassifier()
	imdsDetector := detector.NewIMDSDetector()
	metrics := telemetry.NewMetricsExporter()
	podCache := enricher.NewPodCache()

	// Register test pod
	podCache.RegisterPod("container-victim", 4242, &models.PodContext{
		PodName:        "payment-api-6b79d",
		Namespace:      "production",
		ServiceAccount: "payment-sa",
		IAMRoleARN:     "arn:aws:iam::123456789012:role/payment-processor",
	})

	// Inject unauthorized IMDS access event
	mockDriver.InjectEvent(models.EgressEvent{
		Timestamp:     time.Now(),
		PID:           8888,
		CgroupID:      4242,
		Command:       "curl",
		SourceAddress: net.ParseIP("10.244.1.80"),
		DestAddress:   net.ParseIP("169.254.169.254"),
		SourcePort:    49152,
		DestPort:      80,
		Protocol:      "TCP",
	})

	select {
	case evt := <-mockDriver.Events():
		evt.Pod = podCache.Lookup("", evt.CgroupID)
		evt.CloudService = classifier.Classify(evt.DestAddress, evt.DestPort)
		metrics.RecordEvent(&evt)

		alert := imdsDetector.Evaluate(&evt)
		if alert == nil {
			t.Fatal("expected security alert for IMDS egress attempt")
		}

		if alert.Severity != models.SeverityCritical {
			t.Errorf("expected CRITICAL severity, got %s", alert.Severity)
		}

		if alert.Event.Pod == nil || alert.Event.Pod.PodName != "payment-api-6b79d" {
			t.Errorf("expected enriched pod context, got %v", alert.Event.Pod)
		}

		if alert.Event.Pod.IAMRoleARN == "" {
			t.Errorf("expected resolved IAM Role ARN")
		}

	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for eBPF event pipeline")
	}
}

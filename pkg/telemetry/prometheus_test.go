package telemetry

import (
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

func TestMetricsExporter(t *testing.T) {
	exp := NewMetricsExporter()

	evt := &models.EgressEvent{
		Timestamp:    time.Now(),
		DestAddress:  net.ParseIP("169.254.169.254"),
		CloudService: models.CloudServiceAWSIMDS,
	}

	exp.RecordEvent(evt)
	exp.RecordAlert(&models.SecurityAlert{
		Severity: models.SeverityCritical,
	})

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	exp.MetricsHandler()(w, req)

	resp := w.Body.String()
	if !strings.Contains(resp, "ebpf_sentinel_egress_events_total 1") {
		t.Errorf("expected 1 egress event in metrics output, got: %s", resp)
	}

	if !strings.Contains(resp, "ebpf_sentinel_imds_queries_total 1") {
		t.Errorf("expected 1 imds query in metrics output, got: %s", resp)
	}
}

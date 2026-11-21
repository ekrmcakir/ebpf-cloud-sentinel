package telemetry

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

// MetricsExporter maintains standard Prometheus counters and registers HTTP endpoint
type MetricsExporter struct {
	egressTotal    uint64
	imdsTotal      uint64
	alertsTotal    uint64
	serviceCounts  map[models.CloudServiceType]*uint64
	mu             sync.RWMutex
}

func NewMetricsExporter() *MetricsExporter {
	return &MetricsExporter{
		serviceCounts: make(map[models.CloudServiceType]*uint64),
	}
}

func (m *MetricsExporter) RecordEvent(evt *models.EgressEvent) {
	if evt == nil {
		return
	}
	atomic.AddUint64(&m.egressTotal, 1)

	if evt.CloudService == models.CloudServiceAWSIMDS {
		atomic.AddUint64(&m.imdsTotal, 1)
	}

	m.mu.Lock()
	ptr, exists := m.serviceCounts[evt.CloudService]
	if !exists {
		var val uint64
		ptr = &val
		m.serviceCounts[evt.CloudService] = ptr
	}
	m.mu.Unlock()

	atomic.AddUint64(ptr, 1)
}

func (m *MetricsExporter) RecordAlert(alert *models.SecurityAlert) {
	atomic.AddUint64(&m.alertsTotal, 1)
}

func (m *MetricsExporter) MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP ebpf_sentinel_egress_events_total Total number of eBPF monitored egress events\n")
		fmt.Fprintf(w, "# TYPE ebpf_sentinel_egress_events_total counter\n")
		fmt.Fprintf(w, "ebpf_sentinel_egress_events_total %d\n\n", atomic.LoadUint64(&m.egressTotal))

		fmt.Fprintf(w, "# HELP ebpf_sentinel_imds_queries_total Total number of AWS IMDS egress attempts\n")
		fmt.Fprintf(w, "# TYPE ebpf_sentinel_imds_queries_total counter\n")
		fmt.Fprintf(w, "ebpf_sentinel_imds_queries_total %d\n\n", atomic.LoadUint64(&m.imdsTotal))

		fmt.Fprintf(w, "# HELP ebpf_sentinel_security_alerts_total Total number of generated security alerts\n")
		fmt.Fprintf(w, "# TYPE ebpf_sentinel_security_alerts_total counter\n")
		fmt.Fprintf(w, "ebpf_sentinel_security_alerts_total %d\n\n", atomic.LoadUint64(&m.alertsTotal))
	}
}

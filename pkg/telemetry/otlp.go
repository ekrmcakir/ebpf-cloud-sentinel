package telemetry

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

// OTLPLogRecord represents an OpenTelemetry format log entry
type OTLPLogRecord struct {
	Timestamp   time.Time         `json:"timestamp"`
	Severity    string            `json:"severity_text"`
	Body        string            `json:"body"`
	Attributes  map[string]string `json:"attributes"`
}

type OTLPExporter struct {
	endpoint string
}

func NewOTLPExporter(endpoint string) *OTLPExporter {
	return &OTLPExporter{endpoint: endpoint}
}

func (o *OTLPExporter) FormatAlertRecord(alert *models.SecurityAlert) (*OTLPLogRecord, error) {
	if alert == nil {
		return nil, fmt.Errorf("nil alert")
	}

	attrs := map[string]string{
		"security.rule":       alert.RuleName,
		"security.severity":   string(alert.Severity),
		"network.source_ip":   alert.Event.SourceAddress.String(),
		"network.dest_ip":     alert.Event.DestAddress.String(),
		"network.dest_port":   fmt.Sprintf("%d", alert.Event.DestPort),
		"cloud.service":       string(alert.Event.CloudService),
	}

	if alert.Event.Pod != nil {
		attrs["k8s.pod.name"] = alert.Event.Pod.PodName
		attrs["k8s.namespace"] = alert.Event.Pod.Namespace
		attrs["aws.iam.role"] = alert.Event.Pod.IAMRoleARN
	}

	return &OTLPLogRecord{
		Timestamp:  alert.Timestamp,
		Severity:   string(alert.Severity),
		Body:       alert.Description,
		Attributes: attrs,
	}, nil
}

func (o *OTLPExporter) ExportLogJSON(alert *models.SecurityAlert) ([]byte, error) {
	record, err := o.FormatAlertRecord(alert)
	if err != nil {
		return nil, err
	}
	return json.Marshal(record)
}

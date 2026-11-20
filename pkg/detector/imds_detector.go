package detector

import (
	"fmt"
	"time"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

// IMDSDetector detects unauthorized queries to 169.254.169.254 (SSRF / Credential Scraping)
type IMDSDetector struct {
	enabled bool
}

func NewIMDSDetector() *IMDSDetector {
	return &IMDSDetector{enabled: true}
}

func (d *IMDSDetector) Evaluate(evt *models.EgressEvent) *models.SecurityAlert {
	if !d.enabled || evt == nil {
		return nil
	}

	if evt.CloudService == models.CloudServiceAWSIMDS {
		podDesc := "host process"
		severity := models.SeverityHigh
		if evt.Pod != nil {
			podDesc = fmt.Sprintf("pod %s/%s", evt.Pod.Namespace, evt.Pod.PodName)
			// Production container calling IMDS is critical
			severity = models.SeverityCritical
		}

		return &models.SecurityAlert{
			ID:          fmt.Sprintf("alert-imds-%d", time.Now().UnixNano()),
			Timestamp:   time.Now(),
			Severity:    severity,
			Title:       "AWS IMDSv2 Metadata Access Attempt",
			Description: fmt.Sprintf("Suspicious connection to 169.254.169.254 from %s (command: %s)", podDesc, evt.Command),
			RuleName:    "sec-rule-imds-ssrf-block",
			Event:       *evt,
			Mitigation:  "Configure AWS IMDS Hop Limit = 1 and restrict via K8s NetworkPolicy",
		}
	}

	return nil
}

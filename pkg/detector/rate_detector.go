package detector

import (
	"fmt"
	"sync"
	"time"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

// RateDetector tracks outbound connection frequency to detect data scraping or exfiltration
type RateDetector struct {
	mu           sync.Mutex
	windowCounts map[string]int
	threshold    int
}

func NewRateDetector(thresholdPerWindow int) *RateDetector {
	rd := &RateDetector{
		windowCounts: make(map[string]int),
		threshold:    thresholdPerWindow,
	}

	// Reset window every minute
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		for range ticker.C {
			rd.mu.Lock()
			rd.windowCounts = make(map[string]int)
			rd.mu.Unlock()
		}
	}()

	return rd
}

func (r *RateDetector) Evaluate(evt *models.EgressEvent) *models.SecurityAlert {
	if evt == nil || evt.DestAddress == nil {
		return nil
	}

	key := fmt.Sprintf("%s->%s", evt.Command, evt.DestAddress.String())

	r.mu.Lock()
	r.windowCounts[key]++
	count := r.windowCounts[key]
	r.mu.Unlock()

	if count > r.threshold {
		return &models.SecurityAlert{
			ID:          fmt.Sprintf("alert-rate-%d", time.Now().UnixNano()),
			Timestamp:   time.Now(),
			Severity:    models.SeverityHigh,
			Title:       "High-Frequency Egress Anomaly Detected",
			Description: fmt.Sprintf("Process %s initiated %d connections to %s within rolling window", evt.Command, count, evt.DestAddress),
			RuleName:    "sec-rule-high-egress-rate",
			Event:       *evt,
			Mitigation:  "Investigate potential data exfiltration burst or runaway egress loop",
		}
	}

	return nil
}

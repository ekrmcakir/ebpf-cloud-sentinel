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
	stopChan     chan struct{}
	wg           sync.WaitGroup
	isClosed     bool
}

func NewRateDetector(thresholdPerWindow int) *RateDetector {
	rd := &RateDetector{
		windowCounts: make(map[string]int),
		threshold:    thresholdPerWindow,
		stopChan:     make(chan struct{}),
	}

	// Reset window every minute with clean termination support
	rd.wg.Add(1)
	go func() {
		defer rd.wg.Done()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-rd.stopChan:
				return
			case <-ticker.C:
				rd.mu.Lock()
				rd.windowCounts = make(map[string]int)
				rd.mu.Unlock()
			}
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
	if r.isClosed {
		r.mu.Unlock()
		return nil
	}
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

func (r *RateDetector) Close() error {
	r.mu.Lock()
	if r.isClosed {
		r.mu.Unlock()
		return nil
	}
	r.isClosed = true
	close(r.stopChan)
	r.mu.Unlock()

	r.wg.Wait()
	return nil
}

package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

// AlertDispatcher forwards critical alerts to configured SIEM, Slack, or webhook endpoints
type AlertDispatcher struct {
	webhookURL string
	client     *http.Client
	alertsChan chan *models.SecurityAlert
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	isClosed   bool
}

func NewAlertDispatcher(webhookURL string, bufferSize int) *AlertDispatcher {
	ctx, cancel := context.WithCancel(context.Background())
	d := &AlertDispatcher{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 5 * time.Second},
		alertsChan: make(chan *models.SecurityAlert, bufferSize),
		ctx:        ctx,
		cancel:     cancel,
	}
	d.startWorker()
	return d
}

func (d *AlertDispatcher) Dispatch(alert *models.SecurityAlert) {
	if alert == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.isClosed {
		return
	}

	select {
	case d.alertsChan <- alert:
	default:
		// Queue full, drop to prevent memory leak
	}
}

func (d *AlertDispatcher) startWorker() {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for alert := range d.alertsChan {
			d.sendWebhook(alert)
		}
	}()
}

func (d *AlertDispatcher) sendWebhook(alert *models.SecurityAlert) {
	if d.webhookURL == "" {
		// Log locally if no remote endpoint configured
		fmt.Printf("[ALERT DISPATCHER] %s: %s (Severity: %s)\n", alert.Title, alert.Description, alert.Severity)
		return
	}

	payload, err := json.Marshal(alert)
	if err != nil {
		return
	}

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reqCancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", d.webhookURL, bytes.NewBuffer(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}
}

func (d *AlertDispatcher) Close() error {
	d.mu.Lock()
	if d.isClosed {
		d.mu.Unlock()
		return nil
	}
	d.isClosed = true
	close(d.alertsChan)
	d.mu.Unlock()

	d.wg.Wait()
	d.cancel()
	return nil
}

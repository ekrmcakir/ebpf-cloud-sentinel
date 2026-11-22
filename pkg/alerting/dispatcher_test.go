package alerting

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/models"
)

func TestAlertDispatcherWebhook(t *testing.T) {
	var receivedCount uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddUint64(&receivedCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := NewAlertDispatcher(server.URL, 10)
	defer dispatcher.Close()

	alert := &models.SecurityAlert{
		ID:       "alert-test",
		Title:    "Unauthorized IMDS Access",
		Severity: models.SeverityCritical,
	}

	dispatcher.Dispatch(alert)

	// Wait briefly for async worker delivery
	time.Sleep(50 * time.Millisecond)

	if atomic.LoadUint64(&receivedCount) != 1 {
		t.Errorf("expected 1 webhook delivered, got %d", receivedCount)
	}
}

func TestAlertDispatcherCloseNoPanic(t *testing.T) {
	dispatcher := NewAlertDispatcher("", 10)
	if err := dispatcher.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	// Dispatch after close must not panic
	dispatcher.Dispatch(&models.SecurityAlert{
		ID:    "alert-post-close",
		Title: "Should Not Panic",
	})
}

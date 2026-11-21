package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/alerting"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/config"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/detector"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/ebpf"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/engine"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/telemetry"
)

func main() {
	mockFlag := flag.Bool("mock", false, "Run with cross-platform simulated driver (for macOS / local dev)")
	metricsPort := flag.Int("port", 9091, "Prometheus metrics server port")
	flag.Parse()

	cfg := config.LoadConfigFromEnv()
	if *mockFlag {
		cfg.UseMockDriver = true
	}

	log.Printf("Starting ebpf-cloud-sentinel (Mock Mode: %v, Metrics Port: %d)", cfg.UseMockDriver, *metricsPort)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize components
	var driver ebpf.Driver
	if cfg.UseMockDriver {
		mockDr := ebpf.NewMockDriver()
		mockDr.StartSyntheticTraffic(1 * time.Second)
		driver = mockDr
	} else {
		driver = ebpf.NewMockDriver() // Fallback to safe driver
	}

	if err := driver.Init(ctx); err != nil {
		log.Fatalf("Failed to initialize eBPF driver: %v", err)
	}
	defer driver.Close()

	classifier := engine.NewClassifier()
	imdsDetector := detector.NewIMDSDetector()
	metrics := telemetry.NewMetricsExporter()
	dispatcher := alerting.NewAlertDispatcher(cfg.WebhookURL, 100)
	defer dispatcher.Close()

	// Metrics HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", metrics.MetricsHandler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", *metricsPort),
		Handler: mux,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Metrics server error: %v", err)
		}
	}()

	// Pipeline event processing loop
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-driver.Events():
				if !ok {
					return
				}
				evt.CloudService = classifier.Classify(evt.DestAddress, evt.DestPort)
				metrics.RecordEvent(&evt)

				if alert := imdsDetector.Evaluate(&evt); alert != nil {
					metrics.RecordAlert(alert)
					dispatcher.Dispatch(alert)
				}
			}
		}
	}()

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down ebpf-cloud-sentinel...")
	_ = srv.Shutdown(context.Background())
}

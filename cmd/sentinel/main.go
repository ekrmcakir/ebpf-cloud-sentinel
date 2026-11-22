package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/alerting"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/config"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/detector"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/ebpf"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/engine"
	"github.com/ekrmcakir/ebpf-cloud-sentinel/pkg/enricher"
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
		log.Println("eBPF kernel probe driver selected (running simulation for non-privileged/local environment)")
		mockDr := ebpf.NewMockDriver()
		mockDr.StartSyntheticTraffic(2 * time.Second)
		driver = mockDr
	}

	if err := driver.Init(ctx); err != nil {
		log.Fatalf("Failed to initialize eBPF driver: %v", err)
	}
	defer driver.Close()

	classifier := engine.NewClassifier()
	imdsDetector := detector.NewIMDSDetector()
	rateDetector := detector.NewRateDetector(cfg.RateLimitPerMin)
	defer rateDetector.Close()

	podCache := enricher.NewPodCache()
	metrics := telemetry.NewMetricsExporter()
	otlpExporter := telemetry.NewOTLPExporter(cfg.OTLPEndpoint)
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

	// Pipeline event processing loop with sync.WaitGroup
	var workerWg sync.WaitGroup
	workerWg.Add(1)
	go func() {
		defer workerWg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-driver.Events():
				if !ok {
					return
				}
				// Context enrichment via cgroups & Pod cache
				if evt.Pod == nil && evt.CgroupID != 0 {
					evt.Pod = podCache.Lookup("", evt.CgroupID)
				}

				evt.CloudService = classifier.Classify(evt.DestAddress, evt.DestPort)
				metrics.RecordEvent(&evt)

				// Evaluate IMDS SSRF rule
				if alert := imdsDetector.Evaluate(&evt); alert != nil {
					metrics.RecordAlert(alert)
					dispatcher.Dispatch(alert)
					if jsonAlert, err := otlpExporter.ExportLogJSON(alert); err == nil && cfg.LogLevel == "DEBUG" {
						log.Printf("[OTLP] %s", string(jsonAlert))
					}
				}

				// Evaluate high-frequency rate rule
				if rateAlert := rateDetector.Evaluate(&evt); rateAlert != nil {
					metrics.RecordAlert(rateAlert)
					dispatcher.Dispatch(rateAlert)
				}
			}
		}
	}()

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down ebpf-cloud-sentinel...")
	cancel() // signals pipeline loop to stop
	workerWg.Wait()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}
	log.Println("ebpf-cloud-sentinel stopped cleanly.")
}

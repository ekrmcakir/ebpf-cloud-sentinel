package config

import (
	"os"
	"strconv"
)

type SentinelConfig struct {
	MetricsPort      int
	UseMockDriver    bool
	WebhookURL       string
	OTLPEndpoint     string
	RateLimitPerMin  int
	LogLevel         string
}

func DefaultConfig() *SentinelConfig {
	return &SentinelConfig{
		MetricsPort:     9091,
		UseMockDriver:   false,
		WebhookURL:      "",
		OTLPEndpoint:    "localhost:4317",
		RateLimitPerMin: 100,
		LogLevel:        "INFO",
	}
}

func LoadConfigFromEnv() *SentinelConfig {
	cfg := DefaultConfig()

	if portStr := os.Getenv("SENTINEL_METRICS_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			cfg.MetricsPort = p
		}
	}

	if mockStr := os.Getenv("SENTINEL_MOCK_DRIVER"); mockStr == "true" || mockStr == "1" {
		cfg.UseMockDriver = true
	}

	if webhook := os.Getenv("SENTINEL_WEBHOOK_URL"); webhook != "" {
		cfg.WebhookURL = webhook
	}

	if otlp := os.Getenv("SENTINEL_OTLP_ENDPOINT"); otlp != "" {
		cfg.OTLPEndpoint = otlp
	}

	return cfg
}

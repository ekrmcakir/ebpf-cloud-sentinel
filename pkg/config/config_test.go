package config

import (
	"os"
	"testing"
)

func TestLoadConfigFromEnv(t *testing.T) {
	os.Setenv("SENTINEL_METRICS_PORT", "9999")
	os.Setenv("SENTINEL_MOCK_DRIVER", "true")
	defer os.Unsetenv("SENTINEL_METRICS_PORT")
	defer os.Unsetenv("SENTINEL_MOCK_DRIVER")

	cfg := LoadConfigFromEnv()

	if cfg.MetricsPort != 9999 {
		t.Errorf("expected port 9999, got %d", cfg.MetricsPort)
	}

	if !cfg.UseMockDriver {
		t.Errorf("expected mock driver to be true")
	}
}

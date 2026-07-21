package config_test

import (
	"testing"

	"github.com/saptreekly/casre/internal/config"
)

func TestApplyCrawlPresetDeep(t *testing.T) {
	cfg := config.Default()
	config.ApplyCrawlPreset(&cfg, config.PresetDeep)
	if cfg.Depth != 12 || cfg.MaxURLs != 60 || !cfg.FuzzPaths || !cfg.Campaign || cfg.HopWorkers != 16 {
		t.Fatalf("deep preset: %+v", cfg)
	}
	if config.DetectCrawlPreset(cfg) != config.PresetDeep {
		t.Fatalf("detect=%s", config.DetectCrawlPreset(cfg))
	}
}

func TestApplyCrawlPresetHopWorkers(t *testing.T) {
	cfg := config.Default()
	config.ApplyCrawlPreset(&cfg, config.PresetQuick)
	if cfg.HopWorkers != 8 {
		t.Fatalf("quick workers=%d", cfg.HopWorkers)
	}
	config.ApplyCrawlPreset(&cfg, config.PresetWide)
	if cfg.HopWorkers != 24 {
		t.Fatalf("wide workers=%d", cfg.HopWorkers)
	}
}

func TestClampHopWorkers(t *testing.T) {
	if got := config.ClampHopWorkers(0); got != 8 {
		t.Fatalf("default empty: %d", got)
	}
	if got := config.ClampHopWorkers(100); got != config.HopWorkersMax {
		t.Fatalf("cap: %d", got)
	}
	if got := config.ClampHopWorkers(12); got != 12 {
		t.Fatalf("passthrough: %d", got)
	}
}

func TestCycleCrawlPreset(t *testing.T) {
	cfg := config.Default()
	config.ApplyCrawlPreset(&cfg, config.PresetQuick)
	config.CycleCrawlPreset(&cfg, 1)
	if cfg.CrawlPreset != config.PresetDeep {
		t.Fatalf("got %s", cfg.CrawlPreset)
	}
	config.CycleCrawlPreset(&cfg, 1)
	if cfg.CrawlPreset != config.PresetWide {
		t.Fatalf("got %s", cfg.CrawlPreset)
	}
	config.CycleCrawlPreset(&cfg, 1)
	if cfg.CrawlPreset != config.PresetCustom {
		t.Fatalf("got %s", cfg.CrawlPreset)
	}
}

func TestMarkCustomOnManualEdit(t *testing.T) {
	cfg := config.Default()
	config.ApplyCrawlPreset(&cfg, config.PresetQuick)
	cfg.Depth = 9
	config.MarkCustomPreset(&cfg)
	if cfg.CrawlPreset != config.PresetCustom {
		t.Fatal(cfg.CrawlPreset)
	}
}

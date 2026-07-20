package config

import (
	"time"
)

// Crawl preset names shown in the TUI Options screen.
const (
	PresetQuick  = "quick"
	PresetDeep   = "deep"
	PresetWide   = "wide"
	PresetCustom = "custom"
)

// Config holds runtime options for a scan run.
type Config struct {
	Concurrency int
	RateLimit   float64 // requests per second (0 = unlimited)
	Timeout     time.Duration
	Ports       []int
	Modules     Modules
	OutputJSON  bool
	Quiet       bool
	InsecureTLS bool
	Verbose     bool // full SAN/TXT dumps in text output

	// Follow enables phishing-graph crawling for URL inputs.
	Follow  bool
	Depth   int // max hop depth from the seed URL
	MaxURLs int // max URLs to probe while crawling

	// Campaign restricts crawl to ESP → cloaker → lander style chains
	// and stops expanding brand / CDN / social decoys. Default on with Follow.
	Campaign bool

	// CrawlPreset is quick|deep|wide|custom — informational + Options cycling.
	CrawlPreset string

	// CrawlBudget is the wall-clock limit for hop-graph mapping (0 = auto).
	CrawlBudget time.Duration

	// HopWorkers is parallelism for URL hop probes within one target.
	HopWorkers int

	// EvidenceDir when set saves HTML snapshots of cloaker/lander pages.
	EvidenceDir string

	// FuzzPaths probes common kit/admin paths on cloaker/lander hosts after the crawl.
	FuzzPaths bool
	// FuzzMaxHosts caps how many hosts path-fuzzing will hit (0 = default 3).
	FuzzMaxHosts int
}

// Modules toggles scanner capabilities.
type Modules struct {
	DNS    bool
	TLS    bool
	Banner bool
	HTTP   bool
	Enrich bool // ASN / CDN / infra hints
}

// Default returns a sensible configuration for recon scans.
func Default() Config {
	cfg := Config{
		Concurrency:  100,
		RateLimit:    50,
		Timeout:      3 * time.Second,
		Ports:        []int{80, 443, 22},
		Modules: Modules{
			DNS:    true,
			TLS:    true,
			Banner: true,
			HTTP:   true,
			Enrich: true,
		},
		Follow:       true,
		Depth:        5,
		MaxURLs:      25,
		Campaign:     true,
		CrawlPreset:  PresetCustom,
		CrawlBudget:  0,
		HopWorkers:   8,
		FuzzPaths:    false,
		FuzzMaxHosts: 3,
	}
	return cfg
}

// ApplyCrawlPreset sets depth / max URLs / campaign / fuzz for a named profile.
func ApplyCrawlPreset(cfg *Config, preset string) {
	switch preset {
	case PresetQuick:
		cfg.Follow = true
		cfg.Depth = 3
		cfg.MaxURLs = 12
		cfg.Campaign = true
		cfg.FuzzPaths = false
		cfg.CrawlPreset = PresetQuick
	case PresetDeep:
		cfg.Follow = true
		cfg.Depth = 12
		cfg.MaxURLs = 60
		cfg.Campaign = true
		cfg.FuzzPaths = true
		cfg.CrawlPreset = PresetDeep
	case PresetWide:
		cfg.Follow = true
		cfg.Depth = 6
		cfg.MaxURLs = 100
		cfg.Campaign = false
		cfg.FuzzPaths = true
		cfg.CrawlPreset = PresetWide
	default:
		cfg.CrawlPreset = PresetCustom
	}
}

// MarkCustomPreset flips the label when the user edits knobs by hand.
func MarkCustomPreset(cfg *Config) {
	cfg.CrawlPreset = PresetCustom
}

// DetectCrawlPreset returns which named preset matches cfg, or custom.
func DetectCrawlPreset(cfg Config) string {
	candidates := []string{PresetQuick, PresetDeep, PresetWide}
	for _, p := range candidates {
		tmp := cfg
		ApplyCrawlPreset(&tmp, p)
		if tmp.Depth == cfg.Depth &&
			tmp.MaxURLs == cfg.MaxURLs &&
			tmp.Campaign == cfg.Campaign &&
			tmp.Follow == cfg.Follow &&
			tmp.FuzzPaths == cfg.FuzzPaths {
			return p
		}
	}
	return PresetCustom
}

// CycleCrawlPreset moves Quick → Deep → Wide → Custom → Quick.
func CycleCrawlPreset(cfg *Config, delta int) {
	order := []string{PresetQuick, PresetDeep, PresetWide, PresetCustom}
	cur := cfg.CrawlPreset
	if cur == "" {
		cur = DetectCrawlPreset(*cfg)
	}
	idx := 0
	for i, p := range order {
		if p == cur {
			idx = i
			break
		}
	}
	n := len(order)
	idx = ((idx+delta)%n + n) % n
	next := order[idx]
	if next == PresetCustom {
		cfg.CrawlPreset = PresetCustom
		return
	}
	ApplyCrawlPreset(cfg, next)
}

package config

import (
	"time"
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

	// CrawlBudget is the wall-clock limit for hop-graph mapping (0 = auto).
	CrawlBudget time.Duration

	// HopWorkers is parallelism for URL hop probes within one target.
	HopWorkers int

	// EvidenceDir when set saves HTML snapshots of cloaker/lander pages.
	EvidenceDir string
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
	return Config{
		Concurrency: 100,
		RateLimit:   50,
		Timeout:     3 * time.Second,
		Ports:       []int{80, 443, 22},
		Modules: Modules{
			DNS:    true,
			TLS:    true,
			Banner: true,
			HTTP:   true,
			Enrich: true,
		},
		Follow:      true,
		Depth:       5,
		MaxURLs:     25,
		Campaign:    true,
		CrawlBudget: 0, // auto from CrawlDeadline
		HopWorkers:  8,
	}
}

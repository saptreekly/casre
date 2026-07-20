package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/saptreekly/casre/internal/config"
	"github.com/saptreekly/casre/internal/ratelimit"
)

// Engine orchestrates concurrent recon across targets.
type Engine struct {
	cfg      config.Config
	limiter  *ratelimit.Limiter
	resolver *net.Resolver
	scanned  atomic.Int64
	failed   atomic.Int64
}

// NewEngine builds a scanner engine from config.
func NewEngine(cfg config.Config) *Engine {
	return &Engine{
		cfg:     cfg,
		limiter: ratelimit.New(cfg.RateLimit),
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}
}

// Stats returns progress counters.
func (e *Engine) Stats() (scanned, failed int64) {
	return e.scanned.Load(), e.failed.Load()
}

// Run scans all targets using a bounded worker pool.
// Results are sent on the returned channel; the channel is closed when done.
func (e *Engine) Run(ctx context.Context, targets []Target) <-chan Result {
	out := make(chan Result, e.cfg.Concurrency)
	jobs := make(chan Target, e.cfg.Concurrency)

	var wg sync.WaitGroup
	workers := e.cfg.Concurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(targets) && len(targets) > 0 {
		workers = len(targets)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if err := ctx.Err(); err != nil {
					return
				}
				out <- e.scanOne(ctx, t)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case <-ctx.Done():
				return
			case jobs <- t:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

func (e *Engine) scanOne(ctx context.Context, t Target) Result {
	start := time.Now()
	res := Result{
		Host:      t.Host,
		InputURL:  t.URL,
		RawInput:  t.RawInput,
		Fragment:  t.Fragment,
		ScannedAt: start.UTC(),
	}

	budget := e.cfg.Timeout * 4
	if t.URL != "" {
		if e.cfg.Follow {
			budget = CrawlDeadline(e.cfg)
		} else {
			budget = e.cfg.Timeout * 6
		}
	}
	scanCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	addErr := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		res.Errors = append(res.Errors, err.Error())
		mu.Unlock()
	}
	addFindings := func(f []Finding) {
		if len(f) == 0 {
			return
		}
		mu.Lock()
		res.Findings = append(res.Findings, f...)
		mu.Unlock()
	}

	waitRate := func(ctx context.Context) error {
		return e.limiter.Wait(ctx)
	}

	// URL investigation: auto-crawl the phishing hop graph when Follow is on.
	if t.URL != "" && e.cfg.Modules.HTTP {
		if e.cfg.Follow {
			graph, hops, graphFindings, ev := CrawlFollow(scanCtx, t, e.cfg, e.limiter, e.resolver)
			res.Graph = graph
			res.Hops = hops
			res.Evidence = ev
			if len(hops) > 0 {
				res.URLProbe = hops[0].Probe
				res.Page = hops[0].Page
			}
			if graph != nil {
				res.FinalHost = pickFinalHost(t.Host, graph.Nodes)
			}
			addFindings(graphFindings)
		} else if err := waitRate(scanCtx); err != nil {
			addErr(err)
		} else {
			probe := ProbeURL(scanCtx, t.URL, e.cfg.Timeout, e.cfg.InsecureTLS)
			res.URLProbe = &probe
			if probe.Page != nil {
				res.Page = probe.Page
				addFindings(PageFindings(probe.FinalURL, probe.Page))
				for _, dest := range probe.Page.Destinations {
					dh := HostFromURL(dest)
					if dh != "" && !HostEqual(dh, t.Host) {
						res.FinalHost = dh
						break
					}
				}
			}
			if res.FinalHost == "" && probe.FinalHost != "" && !HostEqual(probe.FinalHost, t.Host) {
				res.FinalHost = probe.FinalHost
			}
			addFindings(URLFindings(t, &probe))
			if e.cfg.EvidenceDir != "" && len(probe.Body) > 0 {
				role := ClassifyNodeRoleCtx(t.Host, t.URL, probe.Page, &probe, RoleContext{Via: "seed"})
				if ev, err := SaveEvidenceHTML(e.cfg.EvidenceDir, role, firstNonEmpty(t.RawInput, t.URL), t.Host,
					pageTitle(probe.Page), pageCT(probe.Page), probe.Body); err == nil && ev != nil {
					res.Evidence = append(res.Evidence, *ev)
				}
			}
		}
	} else if t.Fragment != "" {
		addFindings(URLFindings(t, nil))
	}

	if e.cfg.Modules.DNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := waitRate(scanCtx); err != nil {
				addErr(err)
				return
			}
			dns := ResolveDNS(scanCtx, t.Host, e.resolver)
			mu.Lock()
			res.DNS = dns
			mu.Unlock()
			addFindings(DNSFindings(t.Host, dns))
		}()
	}

	if e.cfg.Modules.TLS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := waitRate(scanCtx); err != nil {
				addErr(err)
				return
			}
			tlsRes, err := ProbeTLS(scanCtx, t.Host, e.cfg.Timeout, e.cfg.InsecureTLS)
			if err != nil {
				addErr(err)
				return
			}
			mu.Lock()
			res.TLS = tlsRes
			mu.Unlock()
			addFindings(TLSFindings(tlsRes))
		}()
	}

	if e.cfg.Modules.Banner {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bannerTimeout := e.cfg.Timeout
			if bannerTimeout > 1500*time.Millisecond {
				bannerTimeout = 1500 * time.Millisecond
			}
			banners := GrabBanners(scanCtx, t.Host, e.cfg.Ports, bannerTimeout, waitRate)
			mu.Lock()
			for _, b := range banners {
				if b.Open {
					res.Banners = append(res.Banners, b)
				}
			}
			mu.Unlock()
			addFindings(BannerFindings(banners))
		}()
	}

	// Root HTTP header audit is noisy for URL/phish triage — skip when probing a full URL.
	if e.cfg.Modules.HTTP && t.URL == "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := waitRate(scanCtx); err != nil {
				addErr(err)
				return
			}
			httpRes := AuditHTTP(scanCtx, t.Host, e.cfg.Timeout, e.cfg.InsecureTLS)
			mu.Lock()
			res.HTTP = httpRes
			mu.Unlock()
			addFindings(HTTPFindings(httpRes))
		}()
	}

	wg.Wait()

	// Destination enrich is handled inside CrawlFollow when graph mapping is enabled.
	if res.FinalHost != "" && e.cfg.Modules.Enrich && res.Graph == nil {
		fh := res.FinalHost
		addFindings([]Finding{{
			Severity: "info",
			Category: "url",
			Message:  "enriching destination host: " + fh,
		}})
		if err := waitRate(scanCtx); err == nil {
			fdns := ResolveDNS(scanCtx, fh, e.resolver)
			httpStub := res.HTTP
			if res.URLProbe != nil {
				httpStub = append([]HTTPResult{*res.URLProbe}, httpStub...)
			}
			enrichFinal := Enrich(scanCtx, fh, fdns, httpStub, e.resolver)
			if enrichFinal != nil {
				for _, h := range enrichFinal.Hints {
					addFindings([]Finding{{Severity: "info", Category: "url", Message: "dest: " + h}})
				}
				for _, a := range enrichFinal.ASN {
					msg := fmt.Sprintf("dest ASN: %s → AS%s", a.IP, a.ASN)
					if a.ASName != "" {
						msg += " " + a.ASName
					}
					addFindings([]Finding{{Severity: "info", Category: "url", Message: msg}})
				}
				if len(enrichFinal.CDN) > 0 {
					addFindings([]Finding{{
						Severity: "info",
						Category: "url",
						Message:  "dest CDN: " + strings.Join(enrichFinal.CDN, ", "),
					}})
				}
			}
			if e.cfg.Modules.TLS {
				if tlsRes, err := ProbeTLS(scanCtx, fh, e.cfg.Timeout, e.cfg.InsecureTLS); err == nil && len(tlsRes.Chain) > 0 {
					addFindings([]Finding{{
						Severity: "info",
						Category: "url",
						Message:  fmt.Sprintf("dest TLS: %s (expires %s)", shortSubject(tlsRes.Chain[0].Subject), expiryDays(tlsRes.Chain[0].DaysUntilExp)),
					}})
				}
			}
		}
	}

	if e.cfg.Modules.Enrich {
		if err := waitRate(scanCtx); err == nil {
			enrich := Enrich(scanCtx, t.Host, res.DNS, res.HTTP, e.resolver)
			res.Enrich = enrich
			addFindings(EnrichFindings(enrich))
		}
	}

	res.Duration = time.Since(start).Round(time.Millisecond).String()
	res.Findings = AnnotateMitre(res.Findings)
	res.Mitre = MitreRollup(res.Findings)
	res.Verdict = BuildVerdict(res)
	res.IOCs = ExtractIOCs(res)
	e.scanned.Add(1)
	if len(res.Errors) > 0 && res.DNS == nil && res.TLS == nil && len(res.Banners) == 0 && res.URLProbe == nil {
		e.failed.Add(1)
	}
	return res
}

func shortSubject(dn string) string {
	for _, p := range strings.Split(dn, ",") {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToUpper(p), "CN=") {
			return p[3:]
		}
	}
	if len(dn) > 48 {
		return dn[:45] + "..."
	}
	return dn
}

func expiryDays(days int) string {
	if days < 0 {
		return "EXPIRED"
	}
	return fmt.Sprintf("in %dd", days)
}

func pickFinalHost(seedHost string, nodes []GraphNode) string {
	rank := func(role string) int {
		switch role {
		case RoleLander:
			return 4
		case RoleCloaker:
			return 3
		case RoleDeepview:
			return 2
		case RoleTracker:
			return 1
		default:
			return 0
		}
	}
	bestHost, bestRank, bestDepth := "", -1, -1
	for _, n := range nodes {
		if n.Host == "" || HostEqual(n.Host, seedHost) {
			continue
		}
		if n.Role == RoleDecoy {
			continue
		}
		r := rank(n.Role)
		if r > bestRank || (r == bestRank && n.Depth >= bestDepth) {
			bestRank, bestDepth, bestHost = r, n.Depth, n.Host
		}
	}
	if bestHost != "" {
		return bestHost
	}
	// Fallback: deepest non-seed.
	deepHost, deep := "", -1
	for _, n := range nodes {
		if n.Host != "" && !HostEqual(n.Host, seedHost) && n.Depth >= deep {
			deep, deepHost = n.Depth, n.Host
		}
	}
	return deepHost
}

func pageTitle(p *PageAnalysis) string {
	if p == nil {
		return ""
	}
	return p.Title
}

func pageCT(p *PageAnalysis) string {
	if p == nil {
		return ""
	}
	return p.ContentType
}

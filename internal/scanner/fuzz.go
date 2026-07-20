package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/saptreekly/casre/internal/config"
	"github.com/saptreekly/casre/internal/ratelimit"
)

// High-signal paths always probed (cheap lite GETs).
var fuzzPathsCore = []string{
	"/admin",
	"/admin/login",
	"/login",
	"/signin",
	"/wp-login.php",
	"/wp-admin/",
	"/owa",
	"/webmail",
	"/panel",
	"/gate",
	"/.env",
	"/.git/HEAD",
	"/backup.zip",
	"/config",
	"/api",
	"/cpanel",
}

// Extra paths only after a core hit (or Deep/Wide budgets).
var fuzzPathsExtra = []string{
	"/sign-in",
	"/account",
	"/accounts/login",
	"/administrator",
	"/user/login",
	"/portal",
	"/owa/auth/logon.aspx",
	"/exchange",
	"/api/v1",
	"/graphql",
	"/drop",
	"/payload",
	"/backup",
	"/robots.txt",
	"/sitemap.xml",
	"/.git/config",
	"/server-status",
	"/cgi-bin/",
	"/debug",
	"/test",
	"/tmp",
}

type fuzzHost struct {
	scheme string
	host   string
	role   string
}

type soft404Baseline struct {
	status int
	size   int
}

// FuzzInterestingPaths probes kit/admin paths on cloaker/lander hosts using
// lite GETs, soft-404 baselines, crawl skip-lists, and tiered path expansion.
func FuzzInterestingPaths(ctx context.Context, cfg config.Config, limiter *ratelimit.Limiter, res Result) []Finding {
	if !cfg.FuzzPaths || !cfg.Modules.HTTP {
		return nil
	}
	hosts := collectFuzzHosts(res)
	maxHosts := cfg.FuzzMaxHosts
	if maxHosts <= 0 {
		maxHosts = 2
	}
	if len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}
	if len(hosts) == 0 {
		return nil
	}

	seenPaths := crawledPathKeys(res)
	timeout := cfg.Timeout
	if timeout <= 0 || timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}

	workers := cfg.HopWorkers
	if workers < 4 {
		workers = 4
	}
	if workers > 16 {
		workers = 16
	}

	var (
		mu       sync.Mutex
		findings []Finding
	)

	for _, h := range hosts {
		if err := ctx.Err(); err != nil {
			break
		}
		hostFindings := fuzzOneHost(ctx, h, cfg, limiter, seenPaths, timeout, workers)
		if len(hostFindings) > 0 {
			mu.Lock()
			findings = append(findings, hostFindings...)
			mu.Unlock()
		}
	}
	return findings
}

func fuzzOneHost(
	ctx context.Context,
	h fuzzHost,
	cfg config.Config,
	limiter *ratelimit.Limiter,
	seenPaths map[string]struct{},
	timeout time.Duration,
	workers int,
) []Finding {
	baseline, ok := learnSoft404(ctx, h, limiter, timeout, cfg.InsecureTLS)
	if !ok {
		return nil
	}

	paths := append([]string{}, fuzzPathsCore...)
	// Deep/Wide (higher MaxURLs) get extras up front; otherwise expand after a core hit.
	eagerExtra := cfg.MaxURLs >= 60 || cfg.Depth >= 10
	if eagerExtra {
		paths = append(paths, fuzzPathsExtra...)
	}

	var (
		mu       sync.Mutex
		findings []Finding
		wg       sync.WaitGroup
		sem      = make(chan struct{}, workers)
		misses   atomic.Int32
		hits     atomic.Int32
		abort    atomic.Bool
	)

	const missAbort = 8 // consecutive soft-404 / uninteresting → stop host

	runPath := func(path string) {
		if abort.Load() || ctx.Err() != nil {
			return
		}
		key := pathKey(h.host, path)
		if _, ok := seenPaths[key]; ok {
			return
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if abort.Load() {
				return
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			if err := limiter.Wait(ctx); err != nil {
				return
			}
			if abort.Load() {
				return
			}

			raw := h.scheme + "://" + h.host + path
			probe := ProbeURLLite(ctx, raw, timeout, cfg.InsecureTLS, 2048)
			if looksLikeSoft404(baseline, probe) {
				if misses.Add(1) >= missAbort && hits.Load() == 0 {
					abort.Store(true)
				}
				return
			}
			f := fuzzFinding(h, path, probe)
			if f == nil {
				if misses.Add(1) >= missAbort && hits.Load() == 0 {
					abort.Store(true)
				}
				return
			}
			misses.Store(0)
			hits.Add(1)
			mu.Lock()
			findings = append(findings, *f)
			mu.Unlock()
		}()
	}

	for _, path := range paths {
		runPath(path)
	}
	wg.Wait()

	// Adaptive expand: core hit on shallow presets → probe extras.
	if !eagerExtra && hits.Load() > 0 && !abort.Load() && ctx.Err() == nil {
		misses.Store(0)
		for _, path := range fuzzPathsExtra {
			runPath(path)
		}
		wg.Wait()
	}

	return findings
}

func learnSoft404(ctx context.Context, h fuzzHost, limiter *ratelimit.Limiter, timeout time.Duration, insecure bool) (soft404Baseline, bool) {
	if err := limiter.Wait(ctx); err != nil {
		return soft404Baseline{}, false
	}
	// Two canaries reduce false soft-404 on flaky hosts.
	canaries := []string{
		"/casre-fuzz-" + shortNonce() + ".html",
		"/." + shortNonce() + "/missing",
	}
	var statuses []int
	var sizes []int
	for _, path := range canaries {
		if ctx.Err() != nil {
			return soft404Baseline{}, false
		}
		raw := h.scheme + "://" + h.host + path
		probe := ProbeURLLite(ctx, raw, timeout, insecure, 2048)
		if probe.Error != "" || probe.StatusCode == 0 {
			continue
		}
		statuses = append(statuses, probe.StatusCode)
		sizes = append(sizes, bodySampleSize(probe))
		_ = limiter.Wait(ctx)
	}
	if len(statuses) == 0 {
		// Host unreachable for fuzz — skip rather than burn paths.
		return soft404Baseline{}, false
	}
	// Prefer shared status; use median-ish size of samples.
	status := statuses[0]
	size := sizes[0]
	if len(statuses) > 1 && statuses[0] == statuses[1] {
		status = statuses[0]
		size = (sizes[0] + sizes[1]) / 2
	}
	return soft404Baseline{status: status, size: size}, true
}

func shortNonce() string {
	return fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)
}

func bodySampleSize(probe HTTPResult) int {
	if n := len(probe.Body); n > 0 {
		return n
	}
	if probe.ContentLength > 0 {
		return int(probe.ContentLength)
	}
	return 0
}

func looksLikeSoft404(base soft404Baseline, probe HTTPResult) bool {
	if probe.Error != "" || probe.StatusCode == 0 {
		return true
	}
	code := probe.StatusCode
	if code == 404 || code == 410 {
		return true
	}
	if base.status == 0 {
		return false
	}
	// Soft-404: same status as canary and similar body size.
	if code == base.status {
		sz := bodySampleSize(probe)
		if base.size == 0 && sz == 0 {
			return true
		}
		if base.size > 0 && sz > 0 {
			diff := sz - base.size
			if diff < 0 {
				diff = -diff
			}
			tol := base.size / 10
			if tol < 64 {
				tol = 64
			}
			if diff <= tol {
				return true
			}
		}
		// Same catch-all status with empty bodies.
		if base.size == 0 && sz < 32 {
			return true
		}
	}
	return false
}

func crawledPathKeys(res Result) map[string]struct{} {
	out := map[string]struct{}{}
	add := func(raw string) {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return
		}
		out[pathKey(u.Hostname(), u.Path)] = struct{}{}
	}
	if res.Graph != nil {
		for _, n := range res.Graph.Nodes {
			add(n.URL)
		}
	}
	for _, h := range res.Hops {
		add(h.URL)
	}
	if res.URLProbe != nil {
		add(res.URLProbe.URL)
		add(res.URLProbe.FinalURL)
	}
	return out
}

func pathKey(host, path string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.TrimSuffix(strings.ToLower(path), "/")
	if path == "" {
		path = "/"
	}
	return host + "|" + path
}

func collectFuzzHosts(res Result) []fuzzHost {
	seen := map[string]struct{}{}
	var out []fuzzHost
	add := func(host, role, schemeHint string) {
		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" || isDecoyHost(host) || isLikelyBenignBrand(host) {
			return
		}
		// Cloud object hosts don't expose kit admin paths — skip.
		if isCloudStorageHost(host) {
			return
		}
		switch role {
		case RoleCloaker, RoleLander, RoleUnknown, "":
		default:
			if !IsIPHost(host) {
				return
			}
		}
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		scheme := "https"
		if schemeHint == "http" || IsIPHost(host) {
			scheme = "http"
		}
		out = append(out, fuzzHost{scheme: scheme, host: host, role: role})
	}

	if res.Graph != nil {
		for _, n := range res.Graph.Nodes {
			scheme := "https"
			if u, err := url.Parse(n.URL); err == nil && u.Scheme != "" {
				scheme = u.Scheme
			}
			add(n.Host, n.Role, scheme)
		}
	}
	for _, h := range res.Hops {
		scheme := "https"
		if u, err := url.Parse(h.URL); err == nil && u.Scheme != "" {
			scheme = u.Scheme
		}
		add(h.Host, h.Role, scheme)
	}
	if res.FinalHost != "" {
		add(res.FinalHost, RoleLander, "https")
	}
	if res.Host != "" && res.Page != nil && (len(res.Page.BrandImpersonation) > 0 || len(res.Page.Kits) > 0) {
		add(res.Host, RoleCloaker, "https")
	}
	return out
}

func fuzzFinding(h fuzzHost, path string, probe HTTPResult) *Finding {
	if probe.Error != "" || probe.StatusCode == 0 {
		return nil
	}
	code := probe.StatusCode
	interesting := false
	sev := "info"
	switch {
	case code == 200 || code == 201:
		interesting = true
		sev = fuzzSeverityForPath(path, true)
	case code == 301 || code == 302 || code == 303 || code == 307 || code == 308:
		finalPath := ""
		if u, err := url.Parse(probe.FinalURL); err == nil {
			finalPath = u.Path
		}
		if !pathsEquivalent(path, finalPath) {
			interesting = true
			sev = "medium"
		}
	case code == 401 || code == 403:
		interesting = true
		sev = "medium"
	case code == 404 || code == 410:
		return nil
	default:
		if code >= 500 {
			return nil
		}
	}
	if !interesting {
		return nil
	}

	msg := fmt.Sprintf("fuzz %s on %s (%s) → HTTP %d", path, h.host, roleOrUnknown(h.role), code)
	if probe.FinalURL != "" && !sameWire(probe.FinalURL, h.scheme+"://"+h.host+path) {
		msg += " → " + CompactURLForFinding(probe.FinalURL)
	}
	return &Finding{Severity: sev, Category: "fuzz", Message: msg}
}

func roleOrUnknown(role string) string {
	if role == "" {
		return "host"
	}
	return role
}

func fuzzSeverityForPath(path string, hit200 bool) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, ".env"), strings.Contains(p, ".git"),
		strings.Contains(p, "backup"), strings.HasSuffix(p, ".zip"):
		return "high"
	case strings.Contains(p, "admin"), strings.Contains(p, "login"),
		strings.Contains(p, "signin"), strings.Contains(p, "wp-"),
		strings.Contains(p, "owa"), strings.Contains(p, "panel"),
		strings.Contains(p, "cpanel"), strings.Contains(p, "webmail"):
		return "high"
	case strings.Contains(p, "api"), strings.Contains(p, "graphql"),
		strings.Contains(p, "gate"), strings.Contains(p, "payload"):
		return "medium"
	default:
		if hit200 {
			return "medium"
		}
		return "info"
	}
}

func pathsEquivalent(a, b string) bool {
	norm := func(p string) string {
		p = strings.TrimSuffix(strings.ToLower(p), "/")
		if p == "" {
			return "/"
		}
		return p
	}
	return norm(a) == norm(b)
}

// CompactURLForFinding is a tiny local helper to avoid importing output from scanner.
func CompactURLForFinding(u string) string {
	if len(u) <= 96 {
		return u
	}
	return u[:93] + "…"
}

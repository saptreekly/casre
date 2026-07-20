package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/saptreekly/casre/internal/config"
	"github.com/saptreekly/casre/internal/ratelimit"
)

// Built-in path list aimed at phishing kits, admin panels, and leaked files.
var defaultFuzzPaths = []string{
	"/",
	"/login",
	"/signin",
	"/sign-in",
	"/account",
	"/accounts/login",
	"/admin",
	"/admin/",
	"/admin/login",
	"/administrator",
	"/wp-admin/",
	"/wp-login.php",
	"/user/login",
	"/portal",
	"/webmail",
	"/owa",
	"/owa/auth/logon.aspx",
	"/exchange",
	"/api",
	"/api/v1",
	"/graphql",
	"/panel",
	"/gate",
	"/drop",
	"/payload",
	"/cpanel",
	"/config",
	"/backup",
	"/backup.zip",
	"/robots.txt",
	"/sitemap.xml",
	"/.env",
	"/.git/HEAD",
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

// FuzzInterestingPaths probes common kit/admin paths on cloaker/lander (and similar) hosts.
func FuzzInterestingPaths(ctx context.Context, cfg config.Config, limiter *ratelimit.Limiter, res Result) []Finding {
	if !cfg.FuzzPaths || !cfg.Modules.HTTP {
		return nil
	}
	hosts := collectFuzzHosts(res)
	maxHosts := cfg.FuzzMaxHosts
	if maxHosts <= 0 {
		maxHosts = 3
	}
	if len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}
	if len(hosts) == 0 {
		return nil
	}

	paths := defaultFuzzPaths
	var (
		mu       sync.Mutex
		findings []Finding
		wg       sync.WaitGroup
		sem      = make(chan struct{}, max(2, cfg.HopWorkers/2))
	)

	for _, h := range hosts {
		h := h
		for _, path := range paths {
			path := path
			// Skip probing bare "/" — seed crawl already hit it; keep list for completeness.
			if path == "/" {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()

				if err := limiter.Wait(ctx); err != nil {
					return
				}
				raw := h.scheme + "://" + h.host + path
				probe := ProbeURL(ctx, raw, cfg.Timeout, cfg.InsecureTLS, "")
				if f := fuzzFinding(h, path, probe); f != nil {
					mu.Lock()
					findings = append(findings, *f)
					mu.Unlock()
				}
			}()
		}
	}
	wg.Wait()
	return findings
}

func collectFuzzHosts(res Result) []fuzzHost {
	seen := map[string]struct{}{}
	var out []fuzzHost
	add := func(host, role, schemeHint string) {
		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" || isDecoyHost(host) || isLikelyBenignBrand(host) {
			return
		}
		// Prefer interesting roles; allow unknown cloud-storage / IP cloakers.
		switch role {
		case RoleCloaker, RoleLander, RoleUnknown, "":
		default:
			if !isCloudStorageHost(host) && !IsIPHost(host) {
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
	if res.Host != "" && (res.Page != nil && (res.Page.CloudStorageHost || len(res.Page.BrandImpersonation) > 0 || len(res.Page.Kits) > 0)) {
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
		// Redirect away from the probe path often means the route exists.
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

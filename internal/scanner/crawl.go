package scanner

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/saptreekly/casre/internal/config"
	"github.com/saptreekly/casre/internal/ratelimit"
)

// GraphNode is one URL visited while mapping a phishing chain.
type GraphNode struct {
	ID         string `json:"id"`
	URL        string `json:"url"`
	Host       string `json:"host"`
	Depth      int    `json:"depth"`
	StatusCode int    `json:"status_code,omitempty"`
	Title      string `json:"title,omitempty"`
	Error      string `json:"error,omitempty"`
	Seed       bool   `json:"seed,omitempty"`
	Terminal   bool   `json:"terminal,omitempty"`
}

// GraphEdge is a discovered transition between URLs.
type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Via  string `json:"via"` // http, js, meta, form
}

// AttackGraph is the mapped redirect/JS hop network for one investigation.
type AttackGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// HopDetail is per-URL probe data collected during a crawl.
type HopDetail struct {
	URL      string        `json:"url"`
	Host     string        `json:"host"`
	Depth    int           `json:"depth"`
	Probe    *HTTPResult   `json:"probe,omitempty"`
	Page     *PageAnalysis `json:"page,omitempty"`
	Findings []Finding     `json:"findings,omitempty"`
}

type crawlItem struct {
	raw   string // may include fragment for analysis
	wire  string // URL fetched on the wire
	depth int
	via   string
	from  string // parent wire/id
}

// CrawlFollow maps HTTP/JS/meta/form hops starting from a seed URL target.
func CrawlFollow(
	ctx context.Context,
	seed Target,
	cfg config.Config,
	limiter *ratelimit.Limiter,
	resolver *net.Resolver,
) (*AttackGraph, []HopDetail, []Finding) {
	if seed.URL == "" {
		return nil, nil, nil
	}
	depthLimit := cfg.Depth
	if depthLimit < 1 {
		depthLimit = 1
	}
	maxURLs := cfg.MaxURLs
	if maxURLs < 1 {
		maxURLs = 10
	}

	visited := map[string]struct{}{}
	hostSeen := map[string]struct{}{}
	var nodes []GraphNode
	var edges []GraphEdge
	var hops []HopDetail
	var findings []Finding
	edgeSet := map[string]struct{}{}

	queue := []crawlItem{{
		raw:   firstNonEmpty(seed.RawInput, seed.URL),
		wire:  seed.URL,
		depth: 0,
		via:   "seed",
	}}

	wait := func() error {
		if limiter == nil {
			return ctx.Err()
		}
		return limiter.Wait(ctx)
	}

	for len(queue) > 0 && len(hops) < maxURLs {
		if err := ctx.Err(); err != nil {
			break
		}
		item := queue[0]
		queue = queue[1:]

		key := normalizeVisitKey(item.wire)
		if _, ok := visited[key]; ok {
			continue
		}
		visited[key] = struct{}{}

		if err := wait(); err != nil {
			break
		}

		// One hop at a time so intermediaries (ESP click trackers, etc.) become graph nodes.
		probe := ProbeURLHop(ctx, item.wire, cfg.Timeout, cfg.InsecureTLS)
		host := HostFromURL(item.wire)

		// Stitch seed fragment onto destinations when JS uses location.hash.
		frag := fragmentOf(item.raw)
		if frag == "" {
			frag = seed.Fragment
		}

		page := probe.Page
		var hopFindings []Finding
		if item.depth == 0 {
			hopFindings = append(hopFindings, URLFindings(seed, &probe)...)
		} else {
			t := Target{Host: host, URL: item.wire, RawInput: item.raw, Fragment: frag}
			hopFindings = append(hopFindings, URLFindings(t, &probe)...)
		}
		pageURL := item.wire
		if page != nil {
			hopFindings = append(hopFindings, PageFindings(pageURL, page)...)
		}

		nodeID := item.wire
		node := GraphNode{
			ID:         nodeID,
			URL:        firstNonEmpty(item.raw, item.wire),
			Host:       host,
			Depth:      item.depth,
			StatusCode: probe.StatusCode,
			Error:      probe.Error,
			Seed:       item.depth == 0,
		}
		if page != nil {
			node.Title = firstNonEmpty(page.Title, page.OGTitle)
		}

		// Discover next hops.
		type nextHop struct {
			url string
			via string
		}
		var next []nextHop

		// HTTP Location from this response only (no auto-follow).
		if probe.StatusCode >= 300 && probe.StatusCode < 400 &&
			probe.FinalURL != "" && !sameWire(probe.FinalURL, item.wire) {
			next = append(next, nextHop{url: probe.FinalURL, via: "http"})
		}

		if page != nil {
			viaOf := func(u string) string {
				for _, m := range page.MetaRefresh {
					if sameWire(m, u) {
						return "meta"
					}
				}
				for _, j := range page.JSRedirects {
					if sameWire(j, u) {
						return "js"
					}
				}
				return "link"
			}
			// Follow explicit redirects always; follow deepview embeds only on linker hosts.
			follow := append([]string{}, page.MetaRefresh...)
			follow = append(follow, page.JSRedirects...)
			if page.Deepview != "" {
				follow = append(follow, page.Destinations...)
			}
			seenF := map[string]struct{}{}
			for _, u := range follow {
				vk := normalizeVisitKey(u)
				if _, ok := seenF[vk]; ok {
					continue
				}
				seenF[vk] = struct{}{}
				next = append(next, nextHop{url: stitchFragment(u, frag), via: viaOf(u)})
			}
			for _, f := range page.Forms {
				if f.Action != "" {
					ah := HostFromURL(f.Action)
					if ah != "" && !HostEqual(ah, host) {
						next = append(next, nextHop{url: f.Action, via: "form"})
					}
				}
			}
		}

		// Dedup next and enqueue.
		seenNext := map[string]struct{}{}
		childCount := 0
		for _, n := range next {
			n.url = strings.TrimSpace(n.url)
			if n.url == "" || !crawlableURL(n.url) {
				continue
			}
			// Normalize wire URL (strip fragment for fetch key / fetch).
			wire, rawKeep := splitWire(n.url)
			vk := normalizeVisitKey(wire)
			if _, ok := seenNext[vk]; ok {
				continue
			}
			seenNext[vk] = struct{}{}

			addEdge(&edges, edgeSet, nodeID, wire, n.via)
			childCount++

			if item.depth+1 > depthLimit {
				continue
			}
			if _, ok := visited[vk]; ok {
				continue
			}
			// Avoid already queued.
			queued := false
			for _, q := range queue {
				if normalizeVisitKey(q.wire) == vk {
					queued = true
					break
				}
			}
			if queued {
				continue
			}
			if len(hops)+len(queue)+1 >= maxURLs {
				continue
			}
			queue = append(queue, crawlItem{
				raw:   rawKeep,
				wire:  wire,
				depth: item.depth + 1,
				via:   n.via,
				from:  nodeID,
			})
		}

		node.Terminal = childCount == 0 && probe.Error == ""
		nodes = append(nodes, node)
		hops = append(hops, HopDetail{
			URL:      node.URL,
			Host:     host,
			Depth:    item.depth,
			Probe:    &probe,
			Page:     page,
			Findings: hopFindings,
		})
		findings = append(findings, hopFindings...)

		// Light host enrichment once per host.
		if cfg.Modules.Enrich && host != "" {
			hk := strings.ToLower(host)
			if _, ok := hostSeen[hk]; !ok {
				hostSeen[hk] = struct{}{}
				if err := wait(); err == nil {
					dns := ResolveDNS(ctx, host, resolver)
					en := Enrich(ctx, host, dns, nil, resolver)
					findings = append(findings, EnrichFindings(en)...)
					if en != nil {
						for _, a := range en.ASN {
							msg := fmt.Sprintf("hop %s ASN: AS%s", host, a.ASN)
							if a.ASName != "" {
								msg += " " + a.ASName
							}
							findings = append(findings, Finding{Severity: "info", Category: "graph", Message: msg})
						}
					}
				}
				if cfg.Modules.TLS {
					if err := wait(); err == nil {
						if tlsRes, err := ProbeTLS(ctx, host, cfg.Timeout, cfg.InsecureTLS); err == nil && len(tlsRes.Chain) > 0 {
							findings = append(findings, Finding{
								Severity: "info",
								Category: "graph",
								Message:  fmt.Sprintf("hop %s TLS: %s", host, shortSubject(tlsRes.Chain[0].Subject)),
							})
						}
					}
				}
			}
		}
	}

	// Mark terminals: nodes with no outgoing edges.
	outCount := map[string]int{}
	for _, e := range edges {
		outCount[e.From]++
	}
	for i := range nodes {
		if outCount[nodes[i].ID] == 0 {
			nodes[i].Terminal = true
		}
	}

	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Depth != nodes[j].Depth {
			return nodes[i].Depth < nodes[j].Depth
		}
		return nodes[i].URL < nodes[j].URL
	})

	findings = append(findings, Finding{
		Severity: "info",
		Category: "graph",
		Message:  fmt.Sprintf("mapped %d URL node(s), %d edge(s), depth≤%d", len(nodes), len(edges), depthLimit),
	})

	return &AttackGraph{Nodes: nodes, Edges: edges}, hops, dedupeFindings(findings)
}

func dedupeFindings(in []Finding) []Finding {
	seen := map[string]struct{}{}
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		key := f.Severity + "\x00" + f.Category + "\x00" + f.Message
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

func addEdge(edges *[]GraphEdge, set map[string]struct{}, from, to, via string) {
	if from == "" || to == "" || sameWire(from, to) {
		return
	}
	key := from + "\x00" + to + "\x00" + via
	if _, ok := set[key]; ok {
		return
	}
	set[key] = struct{}{}
	*edges = append(*edges, GraphEdge{From: from, To: to, Via: via})
}

func crawlableURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func normalizeVisitKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	u.Fragment = ""
	// Ignore default ports.
	u.Host = strings.ToLower(u.Host)
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

func sameWire(a, b string) bool {
	return normalizeVisitKey(a) == normalizeVisitKey(b)
}

func splitWire(raw string) (wire, keep string) {
	u, err := url.Parse(raw)
	if err != nil {
		return raw, raw
	}
	keep = raw
	u.Fragment = ""
	return u.String(), keep
}

func fragmentOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Fragment
}

func stitchFragment(dest, frag string) string {
	if frag == "" {
		return dest
	}
	if strings.Contains(dest, "#") {
		return dest
	}
	return dest + "#" + frag
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// CrawlDeadline returns a generous timeout budget for graph crawling.
func CrawlDeadline(cfg config.Config) time.Duration {
	n := cfg.MaxURLs
	if n < 1 {
		n = 10
	}
	d := cfg.Timeout * time.Duration(n+2)
	if d < 30*time.Second {
		d = 30 * time.Second
	}
	if d > 3*time.Minute {
		d = 3 * time.Minute
	}
	return d
}

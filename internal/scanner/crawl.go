package scanner

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
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
	Role       string `json:"role,omitempty"` // tracker, cloaker, deepview, lander, decoy
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
	Via  string `json:"via"` // http, js, meta, form, link
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
	Role     string        `json:"role,omitempty"`
	Probe    *HTTPResult   `json:"probe,omitempty"`
	Page     *PageAnalysis `json:"page,omitempty"`
	Findings []Finding     `json:"findings,omitempty"`
}

type crawlItem struct {
	raw        string
	wire       string
	depth      int
	via        string
	from       string
	parentRole string
	expand     bool // if false, visit but do not enqueue children (decoy terminal)
}

type hopOutcome struct {
	item        crawlItem
	probe       HTTPResult
	page        *PageAnalysis
	host        string
	role        string
	hopFindings []Finding
	next        []queuedHop
	evidence    *Evidence
}

type queuedHop struct {
	url    string
	via    string
	expand bool
}

// CrawlFollow maps HTTP/JS/meta/form hops starting from a seed URL target.
// Probes run in parallel waves under cfg.HopWorkers, bounded by max URLs and ctx deadline.
func CrawlFollow(
	ctx context.Context,
	seed Target,
	cfg config.Config,
	limiter *ratelimit.Limiter,
	resolver *net.Resolver,
) (*AttackGraph, []HopDetail, []Finding, []Evidence) {
	if seed.URL == "" {
		return nil, nil, nil, nil
	}
	depthLimit := cfg.Depth
	if depthLimit < 1 {
		depthLimit = 1
	}
	maxURLs := cfg.MaxURLs
	if maxURLs < 1 {
		maxURLs = 10
	}
	workers := config.ClampHopWorkers(cfg.HopWorkers)
	campaign := cfg.Campaign
	fullCrawl := !campaign

	visited := map[string]struct{}{}
	hostSeen := map[string]struct{}{}
	var nodes []GraphNode
	var edges []GraphEdge
	var hops []HopDetail
	var findings []Finding
	var evidence []Evidence
	edgeSet := map[string]struct{}{}

	queue := []crawlItem{{
		raw:    firstNonEmpty(seed.RawInput, seed.URL),
		wire:   seed.URL,
		depth:  0,
		via:    "seed",
		expand: true,
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

		// Take a parallel batch; mark visited up front to avoid duplicate probes.
		batchSize := workers
		if batchSize > len(queue) {
			batchSize = len(queue)
		}
		if batchSize > maxURLs-len(hops) {
			batchSize = maxURLs - len(hops)
		}
		var batch []crawlItem
		for len(queue) > 0 && len(batch) < batchSize {
			item := queue[0]
			queue = queue[1:]
			key := normalizeVisitKey(item.wire)
			if _, ok := visited[key]; ok {
				continue
			}
			visited[key] = struct{}{}
			batch = append(batch, item)
		}
		if len(batch) == 0 {
			continue
		}

		outcomes := make([]hopOutcome, len(batch))
		var wg sync.WaitGroup
		for i, item := range batch {
			wg.Add(1)
			go func(i int, item crawlItem) {
				defer wg.Done()
				if err := ctx.Err(); err != nil {
					outcomes[i] = hopOutcome{item: item, probe: HTTPResult{URL: item.wire, Error: err.Error()}}
					return
				}
				if err := wait(); err != nil {
					outcomes[i] = hopOutcome{item: item, probe: HTTPResult{URL: item.wire, Error: err.Error()}}
					return
				}

				frag := fragmentOf(item.raw)
				if frag == "" {
					frag = seed.Fragment
				}
				probe := ProbeURLHop(ctx, item.wire, cfg.Timeout, cfg.InsecureTLS, frag)
				host := HostFromURL(item.wire)
				page := probe.Page

				if page != nil && item.expand {
					EnrichPageFromScripts(ctx, page, item.wire, frag, cfg.Timeout, cfg.InsecureTLS, scriptFetchCap(cfg), wait)
					probe.Page = page
				}

				var hopFindings []Finding
				if item.depth == 0 {
					hopFindings = append(hopFindings, URLFindings(seed, &probe)...)
				} else {
					t := Target{Host: host, URL: item.wire, RawInput: item.raw, Fragment: frag}
					hopFindings = append(hopFindings, URLFindings(t, &probe)...)
				}
				if page != nil {
					hopFindings = append(hopFindings, PageFindings(item.wire, page)...)
				}

				role := ClassifyNodeRoleCtx(host, item.wire, page, &probe, RoleContext{
					ParentRole: item.parentRole,
					Via:        item.via,
				})
				if isDecoyHost(host) {
					role = RoleDecoy
				} else if isLikelyBenignBrand(host) && role == RoleLander {
					role = RoleUnknown
				}

				out := hopOutcome{
					item:        item,
					probe:       probe,
					page:        page,
					host:        host,
					role:        role,
					hopFindings: hopFindings,
				}

				if cfg.EvidenceDir != "" && ShouldSnapshot(role) && len(probe.Body) > 0 {
					title := ""
					ct := ""
					if page != nil {
						title = page.Title
						ct = page.ContentType
					}
					if ev, err := SaveEvidenceHTML(cfg.EvidenceDir, role, firstNonEmpty(item.raw, item.wire), host, title, ct, probe.Body); err == nil && ev != nil {
						out.evidence = ev
					}
				}

				// Discover next hops.
				type nextHop struct {
					url string
					via string
				}
				var next []nextHop

				// Always advance HTTP redirects unless this node is a terminal decoy.
				if role != RoleDecoy && item.expand &&
					probe.StatusCode >= 300 && probe.StatusCode < 400 &&
					probe.FinalURL != "" && !sameWire(probe.FinalURL, item.wire) {
					next = append(next, nextHop{url: probe.FinalURL, via: "http"})
				}

				// Page/JS follows only for delivery roles (or full crawl).
				if page != nil && item.expand && (fullCrawl || CampaignShouldExpand(role)) {
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
					follow := append([]string{}, page.MetaRefresh...)
					follow = append(follow, page.JSRedirects...)
					if page.Deepview != "" || role == RoleDeepview || role == RoleCloaker {
						follow = append(follow, page.Destinations...)
					}
					if campaign && role == RoleLander {
						follow = append([]string{}, page.MetaRefresh...)
						follow = append(follow, page.JSRedirects...)
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

				for _, n := range next {
					n.url = strings.TrimSpace(n.url)
					if n.url == "" || !crawlableURL(n.url) {
						continue
					}
					childHost := HostFromURL(n.url)
					visit, expandLater := CampaignShouldEnqueueChild(role, childHost, fullCrawl)
					if !visit {
						continue
					}
					if isNoiseDestination(n.url) {
						continue
					}
					out.next = append(out.next, queuedHop{url: n.url, via: n.via, expand: expandLater || fullCrawl})
				}

				// Enrichment is applied serially after the batch to dedupe hosts.
				outcomes[i] = out
			}(i, item)
		}
		wg.Wait()

		// Merge outcomes in batch order for stable graphs.
		for _, out := range outcomes {
			if out.item.wire == "" && out.probe.URL == "" {
				continue
			}
			nodeID := out.item.wire
			node := GraphNode{
				ID:         nodeID,
				URL:        firstNonEmpty(out.item.raw, out.item.wire),
				Host:       out.host,
				Depth:      out.item.depth,
				Role:       out.role,
				StatusCode: out.probe.StatusCode,
				Error:      out.probe.Error,
				Seed:       out.item.depth == 0,
			}
			if out.page != nil {
				node.Title = firstNonEmpty(out.page.Title, out.page.OGTitle)
			}

			childCount := 0
			for _, n := range out.next {
				wire, rawKeep := splitWire(n.url)
				vk := normalizeVisitKey(wire)
				addEdge(&edges, edgeSet, nodeID, wire, n.via)
				childCount++

				if out.item.depth+1 > depthLimit {
					continue
				}
				if _, ok := visited[vk]; ok {
					continue
				}
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
					raw:        rawKeep,
					wire:       wire,
					depth:      out.item.depth + 1,
					via:        n.via,
					from:       nodeID,
					parentRole: out.role,
					expand:     n.expand,
				})
			}

			node.Terminal = childCount == 0 && out.probe.Error == ""
			if out.role == RoleDecoy {
				node.Terminal = true
			}
			nodes = append(nodes, node)
			hops = append(hops, HopDetail{
				URL:      node.URL,
				Host:     out.host,
				Depth:    out.item.depth,
				Role:     out.role,
				Probe:    &out.probe,
				Page:     out.page,
				Findings: out.hopFindings,
			})
			findings = append(findings, out.hopFindings...)
			if out.evidence != nil {
				evidence = append(evidence, *out.evidence)
			}

			if cfg.Modules.Enrich && out.host != "" && !(campaign && out.role == RoleDecoy) {
				hk := strings.ToLower(out.host)
				if _, ok := hostSeen[hk]; !ok {
					hostSeen[hk] = struct{}{}
					findings = append(findings, lightHopEnrich(ctx, out.host, cfg, wait, resolver)...)
				}
			}
		}
	}

	outCount := map[string]int{}
	for _, e := range edges {
		outCount[e.From]++
	}
	for i := range nodes {
		if outCount[nodes[i].ID] == 0 || nodes[i].Role == RoleDecoy {
			nodes[i].Terminal = true
		}
	}

	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Depth != nodes[j].Depth {
			return nodes[i].Depth < nodes[j].Depth
		}
		return nodes[i].URL < nodes[j].URL
	})

	mode := "full"
	if campaign {
		mode = "campaign"
	}
	findings = append(findings, Finding{
		Severity: "info",
		Category: "graph",
		Message:  fmt.Sprintf("mapped %d URL node(s), %d edge(s), depth≤%d, mode=%s, hop-workers=%d", len(nodes), len(edges), depthLimit, mode, workers),
	})

	return &AttackGraph{Nodes: nodes, Edges: edges}, hops, dedupeFindings(findings), evidence
}

func scriptFetchCap(cfg config.Config) int {
	if cfg.ScriptFetchMax > 0 {
		return cfg.ScriptFetchMax
	}
	return 3
}

func lightHopEnrich(
	ctx context.Context,
	host string,
	cfg config.Config,
	wait func() error,
	resolver *net.Resolver,
) []Finding {
	var findings []Finding
	if err := wait(); err != nil {
		return nil
	}
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
	return findings
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
	// Already carries tracking as a query (JS reconstruction used the fragment).
	payload := strings.TrimPrefix(strings.TrimSpace(frag), "?")
	if payload != "" && (strings.Contains(dest, payload) || strings.Contains(dest, frag)) {
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

// CrawlDeadline returns the wall-clock budget for graph crawling.
func CrawlDeadline(cfg config.Config) time.Duration {
	if cfg.CrawlBudget > 0 {
		return cfg.CrawlBudget
	}
	n := cfg.MaxURLs
	if n < 1 {
		n = 10
	}
	// Parallel hops finish faster — keep a sane floor/ceiling.
	d := cfg.Timeout * time.Duration(n/2+3)
	if d < 20*time.Second {
		d = 20 * time.Second
	}
	if d > 90*time.Second {
		d = 90 * time.Second
	}
	return d
}

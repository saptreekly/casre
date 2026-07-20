package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// Investigation holds analyst-facing analytics derived from a scan result.
type Investigation struct {
	KillChain     string          `json:"kill_chain,omitempty"`
	Timeline      []TimelinePhase `json:"timeline,omitempty"`
	Confidence    ConfidenceBand  `json:"confidence"`
	BlastRadius   BlastRadius     `json:"blast_radius"`
	Attributions  []Attribution   `json:"attributions,omitempty"`
	Gaps          []CoverageGap   `json:"gaps,omitempty"`
	Techniques    TechniqueMix    `json:"techniques"`
}

// TimelinePhase is one step in the attack-chain / kill-chain view.
type TimelinePhase struct {
	Phase  string `json:"phase"`            // delivery, cloaker, relay, lander, harvest, payload
	Host   string `json:"host,omitempty"`
	Detail string `json:"detail,omitempty"`
	Via    string `json:"via,omitempty"`
	Status string `json:"status"` // observed, inferred, missing
}

// ConfidenceBand describes how much we trust the verdict.
type ConfidenceBand struct {
	Level   string   `json:"level"` // high, medium, low
	Score   int      `json:"score"` // 0–100
	Reasons []string `json:"reasons,omitempty"`
	Caveats []string `json:"caveats,omitempty"`
}

// BlastRadius summarizes what else an analyst may want to block or hunt.
type BlastRadius struct {
	Hosts   []string `json:"hosts,omitempty"`
	IPs     []string `json:"ips,omitempty"`
	ASNs    []string `json:"asns,omitempty"`
	CDNs    []string `json:"cdns,omitempty"`
	Summary string   `json:"summary,omitempty"`
}

// Attribution links a Story claim to the evidence that supports it.
type Attribution struct {
	Claim  string `json:"claim"`
	Source string `json:"source"`
	Kind   string `json:"kind"` // finding, hop, page, graph, kit
}

// CoverageGap is something the scan could not fully observe.
type CoverageGap struct {
	Gap    string `json:"gap"`
	Impact string `json:"impact"` // low, medium, high
}

// TechniqueMix counts how victims were moved between hops.
type TechniqueMix struct {
	HTTP    int    `json:"http"`
	Meta    int    `json:"meta"`
	JS      int    `json:"js"`
	Form    int    `json:"form"`
	Link    int    `json:"link"`
	Kit     int    `json:"kit"` // kit fingerprints / atob / obfuscation
	Summary string `json:"summary,omitempty"`
}

// BuildInvestigation derives timeline, confidence, blast radius, attributions, gaps, and technique mix.
func BuildInvestigation(r Result) *Investigation {
	inv := &Investigation{}
	inv.Timeline = buildTimeline(r)
	inv.KillChain = buildKillChainNarrative(inv.Timeline, r)
	inv.Techniques = buildTechniqueMix(r)
	inv.BlastRadius = buildBlastRadius(r)
	inv.Attributions = buildAttributions(r)
	inv.Gaps = buildCoverageGaps(r)
	inv.Confidence = buildConfidence(r, inv)
	return inv
}

func buildTimeline(r Result) []TimelinePhase {
	type node struct {
		host, role, via, detail string
		depth                   int
	}
	var nodes []node
	viaByHost := map[string]string{}

	if r.Graph != nil {
		idHost := map[string]string{}
		for _, n := range r.Graph.Nodes {
			idHost[n.ID] = n.Host
		}
		for _, e := range r.Graph.Edges {
			if to, ok := idHost[e.To]; ok && e.Via != "" {
				viaByHost[strings.ToLower(to)] = e.Via
			}
		}
		for _, n := range r.Graph.Nodes {
			if n.Host == "" {
				continue
			}
			detail := n.Role
			if n.Title != "" {
				detail = n.Title
			}
			nodes = append(nodes, node{
				host: n.Host, role: n.Role, via: viaByHost[strings.ToLower(n.Host)],
				detail: detail, depth: n.Depth,
			})
		}
	}
	if len(nodes) == 0 {
		for _, h := range r.Hops {
			if h.Host == "" {
				continue
			}
			nodes = append(nodes, node{host: h.Host, role: h.Role, detail: h.Role, depth: h.Depth})
		}
	}

	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].depth != nodes[j].depth {
			return nodes[i].depth < nodes[j].depth
		}
		return nodes[i].host < nodes[j].host
	})

	phaseOf := func(role string) string {
		switch role {
		case RoleTracker:
			return "delivery"
		case RoleCloaker:
			return "cloaker"
		case RoleDeepview:
			return "relay"
		case RoleLander:
			return "lander"
		case RoleDecoy:
			return "decoy"
		default:
			return "hop"
		}
	}

	var out []TimelinePhase
	seenPhaseHost := map[string]struct{}{}
	for _, n := range nodes {
		phase := phaseOf(n.role)
		key := phase + "\x00" + strings.ToLower(n.host)
		if _, ok := seenPhaseHost[key]; ok {
			continue
		}
		seenPhaseHost[key] = struct{}{}
		detail := n.detail
		if detail == n.role || detail == "" {
			detail = rolePhaseDetail(n.role, n.host)
		}
		out = append(out, TimelinePhase{
			Phase:  phase,
			Host:   n.host,
			Detail: truncateRunes(detail, 48),
			Via:    n.via,
			Status: "observed",
		})
	}

	// Append terminal harvest/payload phases when findings imply them.
	if hasFindingContains(r, "password") || hasFindingContains(r, "form posts off-site") {
		host := r.FinalHost
		if host == "" {
			host = lastTimelineHost(out)
		}
		out = append(out, TimelinePhase{
			Phase:  "harvest",
			Host:   host,
			Detail: "credential collection signals",
			Status: "observed",
		})
	}
	if hasFindingContains(r, "download / payload") {
		host := r.FinalHost
		if host == "" {
			host = lastTimelineHost(out)
		}
		out = append(out, TimelinePhase{
			Phase:  "payload",
			Host:   host,
			Detail: "download / payload link",
			Status: "observed",
		})
	}

	// If we never saw a lander but have destinations, mark lander missing.
	hasLander := false
	for _, p := range out {
		if p.Phase == "lander" {
			hasLander = true
			break
		}
	}
	if !hasLander && (hasFindingContains(r, "js/meta redirect") || hasFindingContains(r, "meta refresh")) {
		out = append(out, TimelinePhase{
			Phase:  "lander",
			Detail: "external redirect seen; lander not fully mapped",
			Status: "missing",
		})
	}

	return out
}

func rolePhaseDetail(role, host string) string {
	switch role {
	case RoleTracker:
		return "email/click tracker"
	case RoleCloaker:
		return "interstitial / cloaker"
	case RoleDeepview:
		return "deepview / deferred link"
	case RoleLander:
		return "campaign lander"
	case RoleDecoy:
		return "brand/CDN decoy"
	default:
		if host != "" {
			return host
		}
		return "hop"
	}
}

func lastTimelineHost(phases []TimelinePhase) string {
	for i := len(phases) - 1; i >= 0; i-- {
		if phases[i].Host != "" {
			return phases[i].Host
		}
	}
	return ""
}

func buildKillChainNarrative(phases []TimelinePhase, r Result) string {
	var parts []string
	for _, p := range phases {
		if p.Status == "missing" {
			continue
		}
		label := p.Phase
		switch p.Phase {
		case "delivery":
			label = "Delivery"
		case "cloaker":
			label = "Cloaker"
		case "relay":
			label = "Relay"
		case "lander":
			label = "Lander"
		case "harvest":
			label = "Harvest"
		case "payload":
			label = "Payload"
		case "decoy":
			continue
		default:
			label = "Hop"
			if p.Phase != "" {
				label = strings.ToUpper(p.Phase[:1]) + p.Phase[1:]
			}
		}
		if p.Host != "" {
			parts = append(parts, fmt.Sprintf("%s (%s)", label, p.Host))
		} else {
			parts = append(parts, label)
		}
	}
	if len(parts) == 0 {
		if r.Verdict != nil && r.Verdict.Narrative != "" {
			return r.Verdict.Narrative
		}
		return "insufficient chain to map kill-chain phases"
	}
	return strings.Join(parts, " → ")
}

func buildTechniqueMix(r Result) TechniqueMix {
	m := TechniqueMix{}
	countVia := func(via string) {
		switch strings.ToLower(via) {
		case "http":
			m.HTTP++
		case "meta":
			m.Meta++
		case "js":
			m.JS++
		case "form":
			m.Form++
		case "link":
			m.Link++
		}
	}
	if r.Graph != nil {
		for _, e := range r.Graph.Edges {
			countVia(e.Via)
		}
	}
	// Page-level techniques not always edged yet.
	pages := []*PageAnalysis{r.Page}
	for _, h := range r.Hops {
		if h.Page != nil {
			pages = append(pages, h.Page)
		}
	}
	seenKit := map[string]struct{}{}
	for _, p := range pages {
		if p == nil {
			continue
		}
		if len(p.MetaRefresh) > 0 && m.Meta == 0 {
			m.Meta += len(p.MetaRefresh)
		}
		if len(p.JSRedirects) > 0 && m.JS == 0 {
			m.JS += len(p.JSRedirects)
		}
		for _, k := range p.Kits {
			if _, ok := seenKit[k]; ok {
				continue
			}
			seenKit[k] = struct{}{}
			m.Kit++
		}
	}
	for _, f := range r.Findings {
		msg := strings.ToLower(f.Message)
		if strings.Contains(msg, "phishing kit fingerprint") || strings.Contains(msg, "atob") {
			m.Kit++
		}
	}

	var bits []string
	addBit := func(n int, name string) {
		if n > 0 {
			bits = append(bits, fmt.Sprintf("%s×%d", name, n))
		}
	}
	addBit(m.HTTP, "http")
	addBit(m.Meta, "meta")
	addBit(m.JS, "js")
	addBit(m.Form, "form")
	addBit(m.Link, "link")
	addBit(m.Kit, "kit")
	if len(bits) == 0 {
		m.Summary = "no redirect techniques recorded"
	} else {
		m.Summary = strings.Join(bits, " · ")
	}
	return m
}

func buildBlastRadius(r Result) BlastRadius {
	br := BlastRadius{}
	hostSet := map[string]struct{}{}
	addHost := func(h string) {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" || isDecoyHost(h) || isLikelyBenignBrand(h) {
			return
		}
		if _, ok := hostSet[h]; ok {
			return
		}
		hostSet[h] = struct{}{}
		br.Hosts = append(br.Hosts, h)
	}

	addHost(r.Host)
	addHost(r.FinalHost)
	if r.Graph != nil {
		for _, n := range r.Graph.Nodes {
			if n.Role == RoleDecoy {
				continue
			}
			addHost(n.Host)
		}
	}
	for _, h := range r.Hops {
		if h.Role == RoleDecoy {
			continue
		}
		addHost(h.Host)
	}

	ipSet := map[string]struct{}{}
	if r.DNS != nil {
		for _, ip := range append(append([]string{}, r.DNS.A...), r.DNS.AAAA...) {
			if _, ok := ipSet[ip]; ok {
				continue
			}
			ipSet[ip] = struct{}{}
			br.IPs = append(br.IPs, ip)
		}
	}
	asnSet := map[string]struct{}{}
	if r.Enrich != nil {
		br.CDNs = append([]string{}, r.Enrich.CDN...)
		for _, a := range r.Enrich.ASN {
			if a.IP != "" {
				if _, ok := ipSet[a.IP]; !ok {
					ipSet[a.IP] = struct{}{}
					br.IPs = append(br.IPs, a.IP)
				}
			}
			key := "AS" + strings.TrimPrefix(a.ASN, "AS")
			if a.ASName != "" {
				key += " " + a.ASName
			}
			if _, ok := asnSet[key]; ok || a.ASN == "" {
				continue
			}
			asnSet[key] = struct{}{}
			br.ASNs = append(br.ASNs, key)
		}
	}

	sort.Strings(br.Hosts)
	sort.Strings(br.IPs)
	sort.Strings(br.ASNs)
	sort.Strings(br.CDNs)

	// Cap display lists; full set stays for JSON consumers who want more later.
	const maxH, maxIP = 12, 8
	extraH, extraIP := 0, 0
	if len(br.Hosts) > maxH {
		extraH = len(br.Hosts) - maxH
		br.Hosts = br.Hosts[:maxH]
	}
	if len(br.IPs) > maxIP {
		extraIP = len(br.IPs) - maxIP
		br.IPs = br.IPs[:maxIP]
	}

	var parts []string
	if n := len(hostSet); n > 0 {
		parts = append(parts, fmt.Sprintf("%d host(s)", n))
	}
	if n := len(ipSet); n > 0 {
		parts = append(parts, fmt.Sprintf("%d IP(s)", n))
	}
	if len(asnSet) > 0 {
		parts = append(parts, fmt.Sprintf("%d ASN(s)", len(asnSet)))
	}
	if len(br.CDNs) > 0 {
		parts = append(parts, "CDN: "+strings.Join(br.CDNs, ", "))
	}
	if extraH > 0 || extraIP > 0 {
		parts = append(parts, "truncated for display")
	}
	br.Summary = strings.Join(parts, " · ")
	return br
}

func buildAttributions(r Result) []Attribution {
	var out []Attribution
	add := func(claim, source, kind string) {
		if claim == "" || source == "" {
			return
		}
		out = append(out, Attribution{Claim: claim, Source: source, Kind: kind})
	}

	if r.Page != nil {
		if r.Page.CloudStorageHost {
			add("Cloud-bucket lure", "page on "+r.Host, "page")
		}
		for _, b := range r.Page.BrandImpersonation {
			add("Brand impersonation: "+b, "page body / assets on "+r.Host, "page")
		}
		for _, k := range r.Page.Kits {
			add("Kit: "+k, "page fingerprint on "+r.Host, "kit")
		}
		if len(r.Page.JSRedirects) > 0 {
			add("JS redirect", r.Page.JSRedirects[0], "page")
		}
		if len(r.Page.MetaRefresh) > 0 {
			add("Meta refresh", r.Page.MetaRefresh[0], "page")
		}
	}

	if r.Graph != nil {
		for _, n := range r.Graph.Nodes {
			switch n.Role {
			case RoleCloaker:
				add("Cloaker hop", n.Host+" ("+n.URL+")", "graph")
			case RoleLander:
				add("Lander hop", n.Host+" ("+n.URL+")", "graph")
			case RoleTracker:
				add("Delivery tracker", n.Host, "graph")
			}
		}
	}

	for _, f := range r.Findings {
		msg := strings.ToLower(f.Message)
		switch {
		case f.Severity != "high" && f.Severity != "medium":
			continue
		case f.Category == "phish" && strings.Contains(msg, "password"):
			add("Credential harvest", f.Message, "finding")
		case f.Category == "phish" && strings.Contains(msg, "form posts"):
			add("Off-site form", f.Message, "finding")
		case f.Category == "fuzz" && f.Severity == "high":
			add("Fuzz sensitive path", f.Message, "finding")
		case f.Category == "url" && strings.Contains(msg, "sendgrid"):
			add("ESP delivery", f.Message, "finding")
		}
	}

	// Dedup by claim, keep first.
	seen := map[string]struct{}{}
	var dedup []Attribution
	for _, a := range out {
		key := strings.ToLower(a.Claim)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		dedup = append(dedup, a)
		if len(dedup) >= 10 {
			break
		}
	}
	return dedup
}

func buildCoverageGaps(r Result) []CoverageGap {
	var gaps []CoverageGap
	add := func(gap, impact string) {
		gaps = append(gaps, CoverageGap{Gap: gap, Impact: impact})
	}

	hasBody := false
	if r.Page != nil && r.Page.Bytes > 0 {
		hasBody = true
	}
	for _, h := range r.Hops {
		if h.Page != nil && h.Page.Bytes > 0 {
			hasBody = true
			break
		}
		if h.Probe != nil && len(h.Probe.Body) > 0 {
			hasBody = true
			break
		}
	}
	if !hasBody && r.URLProbe == nil && len(r.Hops) == 0 {
		add("No HTML body captured for seed URL", "high")
	}

	extScripts := 0
	if r.Page != nil {
		extScripts += len(r.Page.ExternalScripts)
	}
	for _, h := range r.Hops {
		if h.Page != nil {
			extScripts += len(h.Page.ExternalScripts)
		}
	}
	if extScripts > 0 {
		add(fmt.Sprintf("%d external script(s) referenced but not fetched", extScripts), "medium")
	}

	if r.Graph != nil {
		stopped := false
		for _, n := range r.Graph.Nodes {
			if n.Role == RoleDecoy {
				stopped = true
				break
			}
		}
		if stopped {
			add("Campaign mode stopped expansion at brand/CDN decoy", "low")
		}
	}

	fuzzEnabled := false
	for _, f := range r.Findings {
		if f.Category == "fuzz" {
			fuzzEnabled = true
			break
		}
	}
	// If we have cloaker/lander but no fuzz findings, fuzz may have been off or empty.
	hasInteresting := false
	if r.Graph != nil {
		for _, n := range r.Graph.Nodes {
			if n.Role == RoleCloaker || n.Role == RoleLander {
				hasInteresting = true
				break
			}
		}
	}
	if hasInteresting && !fuzzEnabled {
		add("Path fuzzing not run (enable Deep/Wide or Path fuzzing in options)", "medium")
	}

	if r.Fragment != "" && r.Page != nil && len(r.Page.JSRedirects) == 0 {
		add("URL fragment present but no JS redirect reconstructed", "medium")
	}

	if len(r.Errors) > 0 {
		add(fmt.Sprintf("%d probe error(s) during scan", len(r.Errors)), "medium")
	}

	if r.DNS == nil {
		add("DNS module returned no data", "low")
	}
	if r.TLS == nil && r.Host != "" && !IsIPHost(r.Host) {
		add("TLS not collected for seed host", "low")
	}

	return gaps
}

func buildConfidence(r Result, inv *Investigation) ConfidenceBand {
	score := 40 // baseline
	var reasons, caveats []string

	addReason := func(pts int, msg string) {
		score += pts
		if msg != "" {
			reasons = append(reasons, msg)
		}
	}
	addCaveat := func(pts int, msg string) {
		score += pts // pts usually negative
		if msg != "" {
			caveats = append(caveats, msg)
		}
	}

	if r.Graph != nil && len(r.Graph.Nodes) >= 2 {
		addReason(15, "multi-hop graph mapped")
	}
	if r.Graph != nil && len(r.Graph.Edges) > 0 {
		addReason(10, "redirect edges observed")
	}
	highFindings := 0
	for _, f := range r.Findings {
		if f.Severity == "high" {
			highFindings++
		}
	}
	if highFindings >= 3 {
		addReason(15, "multiple high-severity findings")
	} else if highFindings >= 1 {
		addReason(8, "high-severity finding present")
	}
	if r.Page != nil && (len(r.Page.BrandImpersonation) > 0 || len(r.Page.Kits) > 0) {
		addReason(10, "kit/brand fingerprint matched")
	}
	if inv != nil && len(inv.Timeline) >= 3 {
		addReason(8, "kill-chain has 3+ phases")
	}
	techTotal := 0
	if inv != nil {
		techTotal = inv.Techniques.HTTP + inv.Techniques.Meta + inv.Techniques.JS + inv.Techniques.Kit
	}
	if techTotal >= 2 {
		addReason(5, "multiple redirect techniques")
	}

	for _, g := range inv.Gaps {
		switch g.Impact {
		case "high":
			addCaveat(-18, g.Gap)
		case "medium":
			addCaveat(-8, g.Gap)
		default:
			addCaveat(-3, g.Gap)
		}
	}
	if r.Verdict != nil && r.Verdict.Label == "clean" && highFindings == 0 {
		addReason(5, "no strong phish signals (clean may be correct)")
	}
	if r.Verdict != nil && r.Verdict.Score >= 70 && highFindings == 0 {
		addCaveat(-12, "high score without high-severity findings")
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	level := "medium"
	switch {
	case score >= 70:
		level = "high"
	case score < 40:
		level = "low"
	}

	// Cap reason/caveat lists for UI.
	if len(reasons) > 5 {
		reasons = reasons[:5]
	}
	if len(caveats) > 5 {
		caveats = caveats[:5]
	}
	return ConfidenceBand{Level: level, Score: score, Reasons: reasons, Caveats: caveats}
}

func hasFindingContains(r Result, substr string) bool {
	substr = strings.ToLower(substr)
	for _, f := range r.Findings {
		if strings.Contains(strings.ToLower(f.Message), substr) {
			return true
		}
	}
	return false
}

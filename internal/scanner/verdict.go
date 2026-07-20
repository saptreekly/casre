package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// Verdict is a compact analyst-facing assessment of a target.
type Verdict struct {
	Score     int      `json:"score"`               // 0–100 phish/recon risk
	Label     string   `json:"label"`               // clean, noteworthy, suspicious, malicious
	Narrative string   `json:"narrative,omitempty"` // short chain story
	Signals   []string `json:"signals,omitempty"`   // top contributing reasons
}

// BuildVerdict derives score + narrative from findings and graph roles.
func BuildVerdict(r Result) *Verdict {
	v := &Verdict{Score: 0, Label: "clean"}
	points := map[string]int{} // signal → points (deduped)

	add := func(pts int, sig string) {
		if pts <= 0 || sig == "" {
			return
		}
		if prev, ok := points[sig]; !ok || pts > prev {
			points[sig] = pts
		}
	}

	for _, f := range r.Findings {
		msg := strings.ToLower(f.Message)
		switch {
		case f.Category == "phish" && f.Severity == "high":
			switch {
			case strings.Contains(msg, "cloud object storage"):
				add(20, "cloud-bucket lure")
			case strings.Contains(msg, "turnstile"), strings.Contains(msg, "fake browser"):
				add(18, "fake browser check")
			case strings.Contains(msg, "brand impersonation"):
				add(12, "brand impersonation")
			case strings.Contains(msg, "password"):
				add(18, "credential harvest form")
			case strings.Contains(msg, "form posts off-site"):
				add(16, "off-site credential form")
			case strings.Contains(msg, "js/meta redirect") && strings.Contains(msg, "cleartext"):
				add(16, "JS redirect to cleartext")
			case strings.Contains(msg, "js/meta redirect"), strings.Contains(msg, "meta refresh"):
				add(10, "external JS/meta redirect")
			case strings.Contains(msg, "download"):
				add(14, "payload download link")
			default:
				add(8, "high phishing signal")
			}
		case f.Category == "phish" && f.Severity == "medium":
			switch {
			case strings.Contains(msg, "interstitial"), strings.Contains(msg, "browser-check"):
				add(4, "interstitial language")
			case strings.Contains(msg, "deepview"):
				add(5, "deepview wrapper")
			case strings.Contains(msg, "external brand/logo"):
				add(4, "external brand asset")
			default:
				add(3, "medium phishing signal")
			}
		case f.Category == "url" && (strings.Contains(msg, "sendgrid") || strings.Contains(msg, "mailchimp") ||
			strings.Contains(msg, "click-tracking") || strings.Contains(msg, "sparkpost") ||
			strings.Contains(msg, "mailgun") || strings.Contains(msg, "amazon ses")):
			add(6, "ESP click tracker")
		case f.Category == "url" && strings.Contains(msg, "cross-domain"):
			add(4, "cross-domain redirects")
		case f.Category == "url" && strings.Contains(msg, "cleartext"):
			add(10, "HTTPS→HTTP downgrade")
		case f.Category == "url" && strings.Contains(msg, "hidden query"):
			add(3, "fragment tracking params")
		case f.Category == "url" && strings.Contains(msg, "userinfo"):
			add(12, "URL userinfo obfuscation")
		case f.Category == "url" && strings.Contains(msg, "punycode"):
			add(8, "punycode/IDN host")
		}
	}

	roles := map[string]int{}
	cleartextLander := false
	if r.Graph != nil {
		for _, n := range r.Graph.Nodes {
			if n.Role != "" {
				roles[n.Role]++
			}
			if n.Role == RoleLander && strings.HasPrefix(strings.ToLower(n.URL), "http://") {
				cleartextLander = true
			}
		}
	}
	for _, h := range r.Hops {
		if h.Role == RoleLander && strings.HasPrefix(strings.ToLower(h.URL), "http://") {
			cleartextLander = true
		}
	}

	// Combo bonuses — require real delivery structure, not ESP→brand alone.
	if roles[RoleCloaker] > 0 && roles[RoleLander] > 0 {
		add(12, "cloaker→lander chain")
	}
	if roles[RoleCloaker] > 0 && cleartextLander {
		add(10, "cloaker→cleartext lander")
	}
	if roles[RoleTracker] > 0 && roles[RoleCloaker] > 0 {
		add(8, "tracker→cloaker chain")
	}
	if roles[RoleTracker] > 0 && roles[RoleDeepview] > 0 && roles[RoleCloaker] == 0 && roles[RoleLander] == 0 {
		// ESP → Branch → brand is common legit marketing; keep mild.
		add(4, "tracker→deepview (no cloaker)")
	}
	if roles[RoleDeepview] > 0 && (roles[RoleCloaker] > 0 || roles[RoleLander] > 0) {
		add(6, "deepview in phish chain")
	}

	for _, pts := range points {
		v.Score += pts
	}
	if v.Score > 100 {
		v.Score = 100
	}

	// Soften ESP-only / deepview-only without cloaker/lander/credential signals.
	if roles[RoleCloaker] == 0 && roles[RoleLander] == 0 && !hasCredentialSignal(points) {
		if v.Score > 35 {
			v.Score = 35
		}
	}

	switch {
	case v.Score >= 70:
		v.Label = "malicious"
	case v.Score >= 40:
		v.Label = "suspicious"
	case v.Score >= 15:
		v.Label = "noteworthy"
	default:
		v.Label = "clean"
	}

	// Stable signal order by points desc.
	type kv struct {
		k string
		v int
	}
	var ordered []kv
	for k, p := range points {
		ordered = append(ordered, kv{k, p})
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].v != ordered[j].v {
			return ordered[i].v > ordered[j].v
		}
		return ordered[i].k < ordered[j].k
	})
	for _, o := range ordered {
		if len(v.Signals) >= 6 {
			break
		}
		v.Signals = append(v.Signals, o.k)
	}

	v.Narrative = buildNarrative(r)
	return v
}

func hasCredentialSignal(points map[string]int) bool {
	for _, s := range []string{"credential harvest form", "off-site credential form", "payload download link", "fake browser check", "cloud-bucket lure"} {
		if points[s] > 0 {
			return true
		}
	}
	return false
}

func buildNarrative(r Result) string {
	if r.Graph != nil && len(r.Graph.Nodes) > 0 {
		nodes := append([]GraphNode(nil), r.Graph.Nodes...)
		sort.SliceStable(nodes, func(i, j int) bool {
			if nodes[i].Depth != nodes[j].Depth {
				return nodes[i].Depth < nodes[j].Depth
			}
			return nodes[i].URL < nodes[j].URL
		})
		var parts []string
		seenRole := map[string]struct{}{}
		for _, n := range nodes {
			role := n.Role
			if role == "" || role == RoleUnknown || role == RoleDecoy {
				continue
			}
			if _, ok := seenRole[role]; ok {
				continue
			}
			seenRole[role] = struct{}{}
			label := role
			switch role {
			case RoleCloaker:
				if n.Title != "" && reCheckingBrowser.MatchString(n.Title) {
					label = "fake CF interstitial"
				} else if strings.Contains(strings.ToLower(n.Host), "storage.googleapis.com") ||
					strings.Contains(strings.ToLower(n.Host), "amazonaws.com") {
					label = "cloud-bucket cloaker"
				} else {
					label = "cloaker"
				}
			case RoleTracker:
				label = "ESP/tracker"
			case RoleDeepview:
				label = "deepview"
			case RoleLander:
				scheme := "lander"
				for _, h := range r.Hops {
					u := strings.ToLower(firstNonEmpty(h.URL, ""))
					if (h.Host == n.Host || sameWire(h.URL, n.URL)) && strings.HasPrefix(u, "http://") {
						scheme = "cleartext lander"
						break
					}
				}
				if strings.HasPrefix(strings.ToLower(n.URL), "http://") {
					scheme = "cleartext lander"
				}
				if n.Title != "" {
					label = scheme + ` ("` + truncateRunes(n.Title, 28) + `")`
				} else {
					label = scheme
				}
			}
			parts = append(parts, label)
		}
		if len(parts) > 0 {
			return strings.Join(parts, " → ")
		}
	}

	var bits []string
	if r.Page != nil {
		if r.Page.HasTurnstile || len(r.Page.BrandImpersonation) > 0 {
			bits = append(bits, "fake CF interstitial")
		}
		if r.Page.CloudStorageHost {
			bits = append(bits, "cloud-bucket lure")
		}
		for _, d := range r.Page.Destinations {
			if strings.HasPrefix(strings.ToLower(d), "http://") {
				bits = append(bits, "cleartext lander")
				break
			}
		}
	}
	if r.FinalHost != "" && r.Host != "" && !HostEqual(r.FinalHost, r.Host) {
		bits = append(bits, fmt.Sprintf("%s → %s", r.Host, r.FinalHost))
	}
	if len(bits) == 0 {
		if len(r.Findings) == 0 {
			return "no strong phishing signals"
		}
		return "recon complete"
	}
	return strings.Join(bits, " → ")
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

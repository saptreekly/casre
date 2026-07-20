package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/saptreekly/casre/internal/scanner"
)

// Report is a savable scan snapshot.
type Report struct {
	Version   int              `json:"version"`
	CreatedAt time.Time        `json:"created_at"`
	Results   []scanner.Result `json:"results"`
}

// Change is one diff entry.
type Change struct {
	Host    string `json:"host"`
	Kind    string `json:"kind"` // added, removed, changed
	Field   string `json:"field"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}

// LoadReport reads a previously saved JSON report.
func LoadReport(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse report: %w", err)
	}
	if rep.Version == 0 {
		rep.Version = 1
	}
	return &rep, nil
}

// SaveReport writes results to path as a JSON report.
func SaveReport(path string, results []scanner.Result) error {
	rep := Report{
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Results:   results,
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// Compare returns changes from old → new keyed by host (or input URL when present).
func Compare(old, neu *Report) []Change {
	oldMap := indexResults(old.Results)
	newMap := indexResults(neu.Results)

	keys := map[string]struct{}{}
	for k := range oldMap {
		keys[k] = struct{}{}
	}
	for k := range newMap {
		keys[k] = struct{}{}
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)

	var changes []Change
	for _, k := range names {
		o, okOld := oldMap[k]
		n, okNew := newMap[k]
		display := displayHost(o, n, k)
		switch {
		case !okOld:
			changes = append(changes, Change{Host: display, Kind: "added", Field: "host", After: display})
		case !okNew:
			changes = append(changes, Change{Host: display, Kind: "removed", Field: "host", Before: display})
		default:
			changes = append(changes, diffHost(display, o, n)...)
		}
	}
	return changes
}

func indexResults(results []scanner.Result) map[string]scanner.Result {
	m := make(map[string]scanner.Result, len(results))
	for _, r := range results {
		m[resultKey(r)] = r
	}
	return m
}

func resultKey(r scanner.Result) string {
	if r.InputURL != "" {
		return "url:" + strings.ToLower(r.InputURL)
	}
	if r.RawInput != "" {
		return "raw:" + strings.ToLower(r.RawInput)
	}
	return "host:" + strings.ToLower(r.Host)
}

func displayHost(old, neu scanner.Result, key string) string {
	if neu.Host != "" {
		return neu.Host
	}
	if old.Host != "" {
		return old.Host
	}
	return strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(key, "url:"), "raw:"), "host:")
}

func diffHost(host string, old, neu scanner.Result) []Change {
	var out []Change
	add := func(field, before, after string) {
		if before == after {
			return
		}
		out = append(out, Change{
			Host:   host,
			Kind:   "changed",
			Field:  field,
			Before: before,
			After:  after,
		})
	}

	add("dns.a", join(old.DNS, func(d *scanner.DNSResult) []string { return d.A }),
		join(neu.DNS, func(d *scanner.DNSResult) []string { return d.A }))
	add("dns.aaaa", join(old.DNS, func(d *scanner.DNSResult) []string { return d.AAAA }),
		join(neu.DNS, func(d *scanner.DNSResult) []string { return d.AAAA }))
	add("dns.mx", join(old.DNS, func(d *scanner.DNSResult) []string { return d.MX }),
		join(neu.DNS, func(d *scanner.DNSResult) []string { return d.MX }))
	add("dns.ns", join(old.DNS, func(d *scanner.DNSResult) []string { return d.NS }),
		join(neu.DNS, func(d *scanner.DNSResult) []string { return d.NS }))

	oldLeaf, oldExp := leafSummary(old.TLS)
	newLeaf, newExp := leafSummary(neu.TLS)
	add("tls.leaf", oldLeaf, newLeaf)
	add("tls.expires", oldExp, newExp)

	add("ports", portsSummary(old.Banners), portsSummary(neu.Banners))

	add("http.final", httpFinals(old.HTTP), httpFinals(neu.HTTP))
	add("http.server", httpServers(old.HTTP), httpServers(neu.HTTP))

	add("enrich.cdn", enrichCDN(old.Enrich), enrichCDN(neu.Enrich))
	add("enrich.asn", enrichASN(old.Enrich), enrichASN(neu.Enrich))

	add("verdict.score", verdictScore(old), verdictScore(neu))
	add("verdict.label", verdictLabel(old), verdictLabel(neu))
	add("final_host", old.FinalHost, neu.FinalHost)
	add("campaign.path", campaignPath(old), campaignPath(neu))
	add("hops", hopHosts(old), hopHosts(neu))
	add("brands", brandsSummary(old), brandsSummary(neu))
	add("kits", kitsSummary(old), kitsSummary(neu))

	out = append(out, diffFindings(host, old.Findings, neu.Findings)...)

	return out
}

func verdictScore(r scanner.Result) string {
	if r.Verdict == nil {
		return ""
	}
	return fmt.Sprintf("%d", r.Verdict.Score)
}

func verdictLabel(r scanner.Result) string {
	if r.Verdict == nil {
		return ""
	}
	return r.Verdict.Label
}

func campaignPath(r scanner.Result) string {
	var hosts []string
	if r.Graph != nil {
		for _, n := range r.Graph.Nodes {
			if n.Host != "" {
				hosts = append(hosts, n.Host)
			}
		}
	}
	if len(hosts) == 0 {
		for _, h := range r.Hops {
			if h.Host != "" {
				hosts = append(hosts, h.Host)
			}
		}
	}
	return strings.Join(hosts, " → ")
}

func hopHosts(r scanner.Result) string {
	var hosts []string
	seen := map[string]struct{}{}
	for _, h := range r.Hops {
		if h.Host == "" {
			continue
		}
		key := strings.ToLower(h.Host)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		hosts = append(hosts, h.Host)
	}
	if len(hosts) == 0 && r.Graph != nil {
		for _, n := range r.Graph.Nodes {
			if n.Host == "" {
				continue
			}
			key := strings.ToLower(n.Host)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			hosts = append(hosts, n.Host)
		}
	}
	return strings.Join(hosts, ",")
}

func brandsSummary(r scanner.Result) string {
	if r.Page == nil {
		return ""
	}
	vals := append([]string{}, r.Page.BrandImpersonation...)
	sort.Strings(vals)
	return strings.Join(vals, "; ")
}

func kitsSummary(r scanner.Result) string {
	if r.Page == nil {
		return ""
	}
	vals := append([]string{}, r.Page.Kits...)
	sort.Strings(vals)
	return strings.Join(vals, "; ")
}

func diffFindings(host string, old, neu []scanner.Finding) []Change {
	oldSet := map[string]struct{}{}
	newSet := map[string]struct{}{}
	for _, f := range old {
		oldSet[findingKey(f)] = struct{}{}
	}
	for _, f := range neu {
		newSet[findingKey(f)] = struct{}{}
	}
	var out []Change
	var added, removed []string
	for k := range newSet {
		if _, ok := oldSet[k]; !ok {
			added = append(added, k)
		}
	}
	for k := range oldSet {
		if _, ok := newSet[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	for _, k := range added {
		out = append(out, Change{Host: host, Kind: "added", Field: "finding", After: k})
	}
	for _, k := range removed {
		out = append(out, Change{Host: host, Kind: "removed", Field: "finding", Before: k})
	}
	return out
}

func findingKey(f scanner.Finding) string {
	return strings.ToUpper(f.Severity) + " · " + f.Category + " · " + f.Message
}

func join(d *scanner.DNSResult, fn func(*scanner.DNSResult) []string) string {
	if d == nil {
		return ""
	}
	vals := append([]string{}, fn(d)...)
	sort.Strings(vals)
	return strings.Join(vals, ",")
}

func leafSummary(t *scanner.TLSResult) (subject, expires string) {
	if t == nil || len(t.Chain) == 0 {
		return "", ""
	}
	return t.Chain[0].Subject, fmt.Sprintf("%dd", t.Chain[0].DaysUntilExp)
}

func portsSummary(banners []scanner.Banner) string {
	var ports []string
	for _, b := range banners {
		if b.Open {
			ports = append(ports, fmt.Sprintf("%d", b.Port))
		}
	}
	sort.Strings(ports)
	return strings.Join(ports, ",")
}

func httpFinals(hs []scanner.HTTPResult) string {
	var parts []string
	for _, h := range hs {
		if h.Error != "" {
			continue
		}
		parts = append(parts, h.URL+"→"+h.FinalURL)
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func httpServers(hs []scanner.HTTPResult) string {
	var parts []string
	for _, h := range hs {
		if h.Server != "" {
			parts = append(parts, h.URL+":"+h.Server)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func enrichCDN(e *scanner.Enrichment) string {
	if e == nil {
		return ""
	}
	vals := append([]string{}, e.CDN...)
	sort.Strings(vals)
	return strings.Join(vals, ",")
}

func enrichASN(e *scanner.Enrichment) string {
	if e == nil {
		return ""
	}
	var parts []string
	for _, a := range e.ASN {
		parts = append(parts, a.IP+":AS"+a.ASN)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// FormatText renders a human-readable diff.
func FormatText(changes []Change, color bool) string {
	if len(changes) == 0 {
		return "diff: no changes detected\n"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("diff: %d change(s)\n", len(changes)))

	bold, red, green, reset := "", "", "", ""
	if color {
		bold, red, green, reset = "\033[1m", "\033[31m", "\033[32m", "\033[0m"
	}

	byHost := map[string][]Change{}
	for _, c := range changes {
		byHost[c.Host] = append(byHost[c.Host], c)
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	for _, h := range hosts {
		fmt.Fprintf(&b, "\n%s%s%s\n", bold, h, reset)
		for _, c := range byHost[h] {
			switch c.Kind {
			case "added":
				if c.Field == "finding" {
					fmt.Fprintf(&b, "  %s+ finding%s %s\n", green, reset, truncate(c.After, 100))
				} else {
					fmt.Fprintf(&b, "  %s+ %s%s\n", green, c.Field, reset)
					if c.After != "" {
						fmt.Fprintf(&b, "      %s+ %s%s\n", green, truncate(c.After, 100), reset)
					}
				}
			case "removed":
				if c.Field == "finding" {
					fmt.Fprintf(&b, "  %s- finding%s %s\n", red, reset, truncate(c.Before, 100))
				} else {
					fmt.Fprintf(&b, "  %s- %s%s\n", red, c.Field, reset)
					if c.Before != "" {
						fmt.Fprintf(&b, "      %s- %s%s\n", red, truncate(c.Before, 100), reset)
					}
				}
			default:
				fmt.Fprintf(&b, "  ~ %s\n", c.Field)
				if c.Before != "" {
					fmt.Fprintf(&b, "      %s- %s%s\n", red, truncate(c.Before, 100), reset)
				}
				if c.After != "" {
					fmt.Fprintf(&b, "      %s+ %s%s\n", green, truncate(c.After, 100), reset)
				}
			}
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

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

// Compare returns changes from old → new keyed by host.
func Compare(old, neu *Report) []Change {
	oldMap := indexByHost(old.Results)
	newMap := indexByHost(neu.Results)

	hosts := map[string]struct{}{}
	for h := range oldMap {
		hosts[h] = struct{}{}
	}
	for h := range newMap {
		hosts[h] = struct{}{}
	}
	names := make([]string, 0, len(hosts))
	for h := range hosts {
		names = append(names, h)
	}
	sort.Strings(names)

	var changes []Change
	for _, h := range names {
		o, okOld := oldMap[h]
		n, okNew := newMap[h]
		switch {
		case !okOld:
			changes = append(changes, Change{Host: h, Kind: "added", Field: "host", After: h})
		case !okNew:
			changes = append(changes, Change{Host: h, Kind: "removed", Field: "host", Before: h})
		default:
			changes = append(changes, diffHost(h, o, n)...)
		}
	}
	return changes
}

func indexByHost(results []scanner.Result) map[string]scanner.Result {
	m := make(map[string]scanner.Result, len(results))
	for _, r := range results {
		m[strings.ToLower(r.Host)] = r
	}
	return m
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

	return out
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
				fmt.Fprintf(&b, "  %s+ added%s\n", green, reset)
			case "removed":
				fmt.Fprintf(&b, "  %s- removed%s\n", red, reset)
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

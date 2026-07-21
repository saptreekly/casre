package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/saptreekly/casre/internal/output"
	"github.com/saptreekly/casre/internal/scanner"
)

func (m model) viewFindings() string {
	all := m.result().Findings
	items := m.visibleFindings()
	hidden := len(all) - len(items)
	w := max(40, m.vp.Width)

	if len(items) == 0 {
		msg := "No important alerts."
		if hidden > 0 {
			msg = fmt.Sprintf("No high/medium alerts. Press i to show %d info notes.", hidden)
		}
		return styleMuted.Render(msg)
	}

	counts := countBySeverity(items)
	var b strings.Builder
	b.WriteString(pageChrome("Alerts", len(items), severitySummary(counts, hidden, m.showInfo), w))

	idx := clamp(m.findIdx, 0, len(items)-1)
	prevSev := ""

	for i, f := range items {
		sevKey := strings.ToLower(f.Severity)
		if sevKey != prevSev {
			if prevSev != "" {
				b.WriteString("\n")
			}
			b.WriteString(severityGroupHeader(f.Severity, counts[sevKey], w) + "\n")
			prevSev = sevKey
		}

		selected := i == idx
		b.WriteString(formatAlertRow(selected, f, w) + "\n")
		if selected {
			if tags := scanner.FormatMitreIDs(f.Mitre); tags != "" {
				b.WriteString(mutedDetail("MITRE  "+tags, w) + "\n")
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

func formatAlertRow(selected bool, f scanner.Finding, w int) string {
	cat := categoryLabel(f.Category)
	lab := fmt.Sprintf("%-*s", labelCol, cat)
	rest := max(8, w-2-labelCol-2)

	if !selected {
		return gutter(false) + sevStyle(f.Severity).Render(lab) + "  " + styleText.Render(fit(f.Message, rest))
	}

	// Highlight every wrapped line so the message stays in the selection.
	msgLines := strings.Split(wrap(f.Message, rest), "\n")
	indent := strings.Repeat(" ", 2+labelCol+2)
	var b strings.Builder
	for i, line := range msgLines {
		if i == 0 {
			b.WriteString(selectRow(true, gutter(true)+lab+"  "+line, w))
		} else {
			b.WriteString("\n" + selectRow(true, indent+line, w))
		}
	}
	return b.String()
}

func severitySummary(counts map[string]int, hidden int, showInfo bool) string {
	order := []string{"high", "medium", "low", "info"}
	var parts []string
	for _, s := range order {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	// Any unexpected severities
	for s, n := range counts {
		switch s {
		case "high", "medium", "low", "info":
		default:
			if n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, s))
			}
		}
	}
	out := strings.Join(parts, " · ")
	if hidden > 0 && !showInfo {
		if out != "" {
			out += "  ·  "
		}
		out += fmt.Sprintf("%d info hidden — press i", hidden)
	}
	return out
}

func severityGroupHeader(sev string, n, w int) string {
	label := severityTitle(sev)
	title := fmt.Sprintf("%s · %d", label, n)
	ruleBudget := w - lipgloss.Width(title) - 3
	if ruleBudget < 2 {
		return sevStyle(sev).Render(title)
	}
	return sevStyle(sev).Render(title) + " " + styleRule.Render(strings.Repeat("─", ruleBudget))
}

func severityTitle(sev string) string {
	switch strings.ToLower(sev) {
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "info":
		return "Info"
	default:
		if sev == "" {
			return "Other"
		}
		return strings.ToUpper(sev[:1]) + strings.ToLower(sev[1:])
	}
}

func countBySeverity(items []scanner.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range items {
		out[strings.ToLower(f.Severity)]++
	}
	return out
}

func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "high", "critical", "malicious":
		return 0
	case "medium", "suspicious":
		return 1
	case "low", "noteworthy":
		return 2
	case "info":
		return 3
	default:
		return 4
	}
}

func catRank(c string) int {
	switch strings.ToLower(c) {
	case "phish":
		return 0
	case "fuzz":
		return 1
	case "url":
		return 2
	case "http":
		return 3
	case "tls":
		return 4
	case "dns":
		return 5
	case "port":
		return 6
	case "graph":
		return 7
	case "intel":
		return 8
	case "enrich":
		return 9
	default:
		return 10
	}
}

func categoryLabel(c string) string {
	switch strings.ToLower(c) {
	case "phish":
		return "Phishing"
	case "fuzz":
		return "Fuzz"
	case "url":
		return "URL"
	case "http":
		return "HTTP"
	case "tls":
		return "TLS"
	case "dns":
		return "DNS"
	case "port":
		return "Ports"
	case "graph":
		return "Campaign"
	case "intel":
		return "Intel"
	case "enrich":
		return "Enrichment"
	case "":
		return "Other"
	default:
		return c
	}
}

func (m model) viewIOCs() string {
	items := flatIOCs(m.result().IOCs)
	if len(items) == 0 {
		return styleMuted.Render("No IOCs.")
	}

	w := max(40, m.vp.Width)
	idx := clamp(m.iocIdx, 0, len(items)-1)

	var b strings.Builder
	b.WriteString(pageChrome("Indicators", len(items), "↑↓ select  ·  enter/f full url  ·  c copy", w))

	prevType := ""
	for i, ioc := range items {
		if ioc.Type != prevType {
			if prevType != "" {
				b.WriteString("\n")
			}
			label := iocTypeTitle(ioc.Type)
			n := countIOCType(items, ioc.Type)
			b.WriteString(sectionRule(fmt.Sprintf("%s · %d", label, n), w) + "\n")
			prevType = ioc.Type
		}

		val := ioc.Value
		if ioc.Type == "url" && !m.showFull {
			val = output.CompactURL(val)
		}

		selected := i == idx
		if selected {
			b.WriteString(selectRow(true, gutter(true)+val, w) + "\n")
			if ioc.Context != "" {
				b.WriteString(mutedDetail(ioc.Context, w) + "\n")
			}
			if ioc.Type == "url" && m.showFull {
				b.WriteString(styleMuted.Render(wrap(ioc.Value, max(40, w-len(detailPad)))) + "\n")
			}
			b.WriteString("\n")
			continue
		}

		line := gutter(false) + val
		if ioc.Context != "" {
			rest := w - lipgloss.Width(line) - 3
			if rest > 8 {
				line = fit(line+"  ·  "+ioc.Context, w)
			} else {
				line = fit(line, w)
			}
		} else {
			line = fit(line, w)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func iocTypeTitle(t string) string {
	switch strings.ToLower(t) {
	case "domain":
		return "Domains"
	case "ip":
		return "IPs"
	case "url":
		return "URLs"
	case "asn":
		return "ASNs"
	default:
		return t
	}
}

func countIOCType(items []scanner.IOC, typ string) int {
	n := 0
	for _, ioc := range items {
		if ioc.Type == typ {
			n++
		}
	}
	return n
}

func (m model) viewInfra() string {
	items := m.infraItems()
	if len(items) == 0 {
		return styleMuted.Render("No infrastructure data.")
	}

	w := max(40, m.vp.Width)
	idx := clamp(m.hostIdx, 0, len(items)-1)

	var b strings.Builder
	b.WriteString(pageChrome("Host", len(items), "↑↓ select  ·  enter expand/collapse  ·  c copy", w))

	prevSec := ""
	for i, it := range items {
		if it.section != prevSec {
			if prevSec != "" {
				b.WriteString("\n")
			}
			b.WriteString(sectionRule(it.section, w) + "\n")
			prevSec = it.section
		}

		mutedVal := it.kind == "expand" || it.kind == "collapse"
		b.WriteString(labeledRow(i == idx, it.label, it.value, hostLabelCol, w, mutedVal) + "\n")
	}
	return b.String()
}

type infraItem struct {
	section string
	label   string
	value   string
	kind    string // "", "expand", "collapse"
	group   string // e.g. "dns:A"
}

func (m *model) toggleHostExpand() {
	items := m.infraItems()
	if m.hostIdx < 0 || m.hostIdx >= len(items) {
		return
	}
	it := items[m.hostIdx]
	if it.kind != "expand" && it.kind != "collapse" {
		return
	}
	if m.hostExpanded == nil {
		m.hostExpanded = map[string]bool{}
	}
	m.hostExpanded[it.group] = !m.hostExpanded[it.group]
	// Keep selection on the group's toggle row after rebuild.
	items = m.infraItems()
	for i, x := range items {
		if x.group == it.group && (x.kind == "expand" || x.kind == "collapse") {
			m.hostIdx = i
			return
		}
	}
}

func (m model) infraExpanded(group string) bool {
	return m.hostExpanded != nil && m.hostExpanded[group]
}

func (m model) infraItems() []infraItem {
	r := m.result()
	var out []infraItem
	add := func(section, label, value, kind, group string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		out = append(out, infraItem{
			section: section,
			label:   label,
			value:   value,
			kind:    kind,
			group:   group,
		})
	}

	if r.DNS != nil {
		addRR := func(label string, vals []string, limit int) {
			group := "dns:" + label
			show := vals
			if !m.infraExpanded(group) && limit > 0 && len(show) > limit {
				hidden := len(show) - limit
				show = show[:limit]
				for i, v := range show {
					if i == 0 {
						add("DNS", label, v, "", group)
					} else {
						add("DNS", "", v, "", group)
					}
				}
				add("DNS", "", fmt.Sprintf("… +%d more  (enter to expand)", hidden), "expand", group)
				return
			}
			for i, v := range show {
				if i == 0 {
					add("DNS", label, v, "", group)
				} else {
					add("DNS", "", v, "", group)
				}
			}
			if m.infraExpanded(group) && limit > 0 && len(vals) > limit {
				add("DNS", "", "▴ show less  (enter to collapse)", "collapse", group)
			}
		}
		addRR("A", r.DNS.A, 4)
		addRR("AAAA", r.DNS.AAAA, 2)
		addRR("CNAME", r.DNS.CNAME, 3)
		addRR("MX", r.DNS.MX, 3)
		addRR("NS", r.DNS.NS, 3)
	}

	if r.TLS != nil {
		add("TLS", "proto", r.TLS.Version, "", "")
		add("TLS", "cipher", r.TLS.CipherSuite, "", "")
		if len(r.TLS.ALPN) > 0 {
			add("TLS", "alpn", strings.Join(r.TLS.ALPN, ", "), "", "")
		}
		if len(r.TLS.Chain) > 0 {
			leaf := r.TLS.Chain[0]
			add("TLS", "leaf", leaf.Subject, "", "")
			add("TLS", "issuer", leaf.Issuer, "", "")
			add("TLS", "expires", fmt.Sprintf("in %d days", leaf.DaysUntilExp), "", "")
		}
	}

	for _, bn := range r.Banners {
		if !bn.Open {
			continue
		}
		label := fmt.Sprintf("%d", bn.Port)
		val := bn.Service
		if bn.Banner != "" {
			val += "  " + truncate(bn.Banner, 48)
		}
		add("Ports", label, val, "", "")
	}

	if r.Enrich != nil {
		if len(r.Enrich.CDN) > 0 {
			add("Enrich", "CDN", strings.Join(r.Enrich.CDN, ", "), "", "")
		}
		const asnLimit = 3
		asns := r.Enrich.ASN
		group := "enrich:asn"
		if !m.infraExpanded(group) && len(asns) > asnLimit {
			for i, a := range asns[:asnLimit] {
				label := "ASN"
				if i > 0 {
					label = ""
				}
				add("Enrich", label, fmt.Sprintf("%s · AS%s %s · %s", a.IP, a.ASN, a.ASName, a.CC), "", group)
			}
			add("Enrich", "", fmt.Sprintf("… +%d more  (enter to expand)", len(asns)-asnLimit), "expand", group)
		} else {
			for i, a := range asns {
				label := "ASN"
				if i > 0 {
					label = ""
				}
				add("Enrich", label, fmt.Sprintf("%s · AS%s %s · %s", a.IP, a.ASN, a.ASName, a.CC), "", group)
			}
			if m.infraExpanded(group) && len(asns) > asnLimit {
				add("Enrich", "", "▴ show less  (enter to collapse)", "collapse", group)
			}
		}
	}

	return out
}

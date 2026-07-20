package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/saptreekly/casre/internal/scanner"
)

func (m model) viewOverview() string {
	items := m.storyItems()
	if len(items) == 0 {
		return styleMuted.Render("No investigation data yet.")
	}

	w := max(40, m.vp.Width)
	idx := clamp(m.storyIdx, 0, len(items)-1)

	var b strings.Builder
	b.WriteString(pageChrome("Investigation", len(items), "↑↓ select  ·  c copy", w))

	prevSec := ""
	for i, it := range items {
		if it.section != prevSec {
			if prevSec != "" {
				b.WriteString("\n")
			}
			b.WriteString(sectionRule(it.section, w) + "\n")
			prevSec = it.section
		}

		selected := i == idx
		b.WriteString(labeledRow(selected, it.label, it.value, labelCol, w, false) + "\n")
		if selected && it.detail != "" {
			b.WriteString(mutedDetail(it.detail, w) + "\n")
		}
	}

	if m.compared {
		b.WriteString("\n" + styleMuted.Render(fit(fmt.Sprintf("Last rescan: %d change(s) — press 6 for Diff", len(m.changes)), w)) + "\n")
	}
	return b.String()
}

type storyItem struct {
	section string
	label   string
	value   string
	detail  string
}

func (m model) storyItems() []storyItem {
	r := m.result()
	var out []storyItem
	add := func(section, label, value, detail string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		out = append(out, storyItem{section: section, label: label, value: value, detail: detail})
	}

	if r.Verdict != nil {
		add("Verdict", "score", fmt.Sprintf("%d/100 · %s", r.Verdict.Score, r.Verdict.Label), "")
		if r.Verdict.Narrative != "" {
			add("Verdict", "story", r.Verdict.Narrative, "")
		}
		if len(r.Verdict.Signals) > 0 {
			add("Verdict", "signals", strings.Join(r.Verdict.Signals, " · "), "")
		}
	}

	inv := r.Investigation
	if inv != nil {
		c := inv.Confidence
		add("Confidence", "band", fmt.Sprintf("%s · %d/100", c.Level, c.Score), "")
		if len(c.Reasons) > 0 {
			add("Confidence", "why", strings.Join(c.Reasons, " · "), "")
		}
		if len(c.Caveats) > 0 {
			add("Confidence", "caveats", strings.Join(c.Caveats, " · "), "")
		}

		if inv.KillChain != "" {
			add("Kill chain", "path", inv.KillChain, "")
		}

		for _, p := range inv.Timeline {
			host := p.Host
			if host == "" {
				host = "—"
			}
			val := host
			if p.Via != "" {
				val += "  ·  " + p.Via
			}
			detail := p.Detail
			if p.Status == "missing" {
				if detail != "" {
					detail += " · "
				}
				detail += "not fully observed"
			}
			add("Timeline", p.Phase, val, detail)
		}

		if inv.Techniques.Summary != "" && inv.Techniques.Summary != "no redirect techniques recorded" {
			add("Techniques", "mix", inv.Techniques.Summary, "")
		}

		if inv.BlastRadius.Summary != "" {
			add("Blast radius", "summary", inv.BlastRadius.Summary, "")
		}
		for i, h := range inv.BlastRadius.Hosts {
			label := "host"
			if i > 0 {
				label = ""
			}
			add("Blast radius", label, h, "")
		}
		for i, ip := range inv.BlastRadius.IPs {
			label := "ip"
			if i > 0 {
				label = ""
			}
			add("Blast radius", label, ip, "")
		}
		for i, asn := range inv.BlastRadius.ASNs {
			label := "asn"
			if i > 0 {
				label = ""
			}
			add("Blast radius", label, asn, "")
		}
		for i, cdn := range inv.BlastRadius.CDNs {
			label := "cdn"
			if i > 0 {
				label = ""
			}
			add("Blast radius", label, cdn, "")
		}

		for _, a := range inv.Attributions {
			add("Attribution", a.Kind, a.Claim, a.Source)
		}

		for _, g := range inv.Gaps {
			add("Gaps", g.Impact, g.Gap, "")
		}
	}

	seed := r.Host
	final := r.FinalHost
	if final == "" {
		final = seed
	}
	add("Facts", "started", seed, "")
	add("Facts", "ended", final, "")
	if r.Page != nil && r.Page.CloudStorageHost {
		add("Facts", "hosting", "cloud storage", "")
	}
	if r.Page != nil && len(r.Page.BrandImpersonation) > 0 {
		add("Facts", "lure", strings.Join(r.Page.BrandImpersonation, " · "), "")
	}
	if r.Page != nil && len(r.Page.Kits) > 0 {
		add("Facts", "kit", strings.Join(r.Page.Kits, " · "), "")
	}
	if r.Page != nil && len(r.Page.JSRedirects) > 0 {
		add("Facts", "js", r.Page.JSRedirects[0], "")
	}
	if r.Page != nil && len(r.Page.MetaRefresh) > 0 {
		add("Facts", "meta", r.Page.MetaRefresh[0], "")
	}
	if r.Fragment != "" {
		if decoded, ok := scanner.DecodeBase64QueryFragment(r.Fragment); ok {
			add("Facts", "tracking", decoded, "")
		} else {
			add("Facts", "fragment", r.Fragment, "")
		}
	}
	if r.RawInput != "" {
		add("Facts", "input", r.RawInput, "")
	} else if r.InputURL != "" {
		add("Facts", "input", r.InputURL, "")
	}

	return out
}

func confidenceBadge(c scanner.ConfidenceBand) string {
	text := fmt.Sprintf("%s conf · %d", c.Level, c.Score)
	base := lipgloss.NewStyle().Bold(true).Padding(0, 1)
	switch c.Level {
	case "high":
		return base.Foreground(colAccentFg).Background(colOK).Render(text)
	case "low":
		return base.Foreground(colAccentFg).Background(colMedium).Render(text)
	default:
		return base.Foreground(colAccentFg).Background(colAccent).Render(text)
	}
}

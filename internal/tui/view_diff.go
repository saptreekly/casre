package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/saptreekly/casre/internal/diff"
)

func (m model) viewDiff() string {
	w := max(40, m.vp.Width)
	if len(m.changes) == 0 {
		if m.compared {
			return styleMuted.Render("No changes since last scan.")
		}
		return styleMuted.Render("No comparison yet.\n\nPress r to rescan and compare against this result.")
	}

	var b strings.Builder
	b.WriteString(pageChrome("Changes", len(m.changes), "Compared to previous scan  ·  r to rescan again", w))

	byHost := map[string][]diff.Change{}
	var hosts []string
	seen := map[string]struct{}{}
	for _, c := range m.changes {
		byHost[c.Host] = append(byHost[c.Host], c)
		if _, ok := seen[c.Host]; !ok {
			seen[c.Host] = struct{}{}
			hosts = append(hosts, c.Host)
		}
	}

	for _, h := range hosts {
		b.WriteString(sectionRule(fit(h, w), w) + "\n")
		for _, c := range byHost[h] {
			b.WriteString(renderChange(c, w) + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func renderChange(c diff.Change, w int) string {
	switch c.Kind {
	case "added":
		label := "+ " + c.Field
		rest := max(12, w-lipgloss.Width(label)-4)
		return gutter(false) + styleOK.Render(label) + "  " + styleText.Render(fit(c.After, rest))
	case "removed":
		label := "- " + c.Field
		rest := max(12, w-lipgloss.Width(label)-4)
		return gutter(false) + styleHigh.Render(label) + "  " + styleMuted.Render(fit(c.Before, rest))
	default:
		var b strings.Builder
		b.WriteString(gutter(false) + styleMed.Render("~ "+c.Field) + "\n")
		rest := max(12, w-len(detailPad)-2)
		if c.Before != "" {
			b.WriteString(detailPad + styleHigh.Render("-") + " " + styleMuted.Render(fit(c.Before, rest)) + "\n")
		}
		if c.After != "" {
			b.WriteString(detailPad + styleOK.Render("+") + " " + styleText.Render(fit(c.After, rest)))
		}
		return strings.TrimRight(b.String(), "\n")
	}
}

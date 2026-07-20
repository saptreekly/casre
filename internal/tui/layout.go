package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
)

const (
	labelCol     = 10 // Story / Alerts category / Chain detail
	hostLabelCol = 8  // Host facts (AAAA, expires, CNAME)
	optLabelCol  = 22 // Options screen
	detailPad    = "    "
)

func gutter(selected bool) string {
	if selected {
		return "▸ "
	}
	return "  "
}

func selectRow(selected bool, plain string, w int) string {
	plain = fit(plain, w)
	if selected {
		return styleSelected.Render(padBlock(plain, w))
	}
	return plain
}

func mutedDetail(text string, w int) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	return styleMuted.Render(fit(detailPad+text, w))
}

func pageChrome(title string, n int, hint string, w int) string {
	head := title
	if n > 0 {
		head = fmt.Sprintf("%s · %d", title, n)
	}
	var b strings.Builder
	b.WriteString(styleText.Render(head) + "\n")
	if hint != "" {
		b.WriteString(styleMuted.Render(fit(hint, w)) + "\n")
	}
	b.WriteString("\n")
	return b.String()
}

func sectionRule(title string, w int) string {
	ruleBudget := w - lipgloss.Width(title) - 3
	if ruleBudget < 2 {
		return styleSection.Render(title)
	}
	return styleSection.Render(title) + " " + styleRule.Render(strings.Repeat("─", ruleBudget))
}

// labeledRow renders "▸ label  value" with aligned labels.
// mutedVal styles the value as secondary (expand/collapse hints).
func labeledRow(selected bool, label, value string, labelW, w int, mutedVal bool) string {
	if labelW <= 0 {
		labelW = labelCol
	}
	lab := fmt.Sprintf("%-*s", labelW, label)
	rest := max(8, w-2-labelW-2)
	val := fit(value, rest)
	plain := gutter(selected) + lab + "  " + val
	if selected {
		return selectRow(true, plain, w)
	}
	if mutedVal {
		return gutter(false) + lab + "  " + styleMuted.Render(val)
	}
	if label != "" {
		return gutter(false) + styleMuted.Render(lab) + "  " + styleText.Render(val)
	}
	return gutter(false) + lab + "  " + styleText.Render(val)
}

// fit truncates s to at most w terminal columns, appending "…" when needed.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}
	// Walk runes until we fill w-1 columns.
	var b strings.Builder
	cols := 0
	for _, r := range s {
		rw := lipgloss.Width(string(r))
		if cols+rw > w-1 {
			break
		}
		b.WriteRune(r)
		cols += rw
	}
	b.WriteRune('…')
	return b.String()
}

// wrap soft-wraps s to width w, preferring breaks at URL delimiters.
func wrap(s string, w int) string {
	if w < 8 {
		w = 8
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	var lines []string
	for lipgloss.Width(s) > w {
		cut := cutIndex(s, w)
		lines = append(lines, s[:cut])
		s = s[cut:]
	}
	if s != "" {
		lines = append(lines, s)
	}
	return strings.Join(lines, "\n")
}

func cutIndex(s string, w int) int {
	// Prefer a break near the end of the line at URL-ish delimiters.
	best := -1
	cols := 0
	byteIdx := 0
	limit := w
	minKeep := w / 3
	if minKeep < 8 {
		minKeep = 8
	}
	for byteIdx < len(s) {
		r, size := utf8.DecodeRuneInString(s[byteIdx:])
		rw := lipgloss.Width(string(r))
		if cols+rw > limit {
			break
		}
		cols += rw
		byteIdx += size
		if r == '?' || r == '#' || r == '/' || r == '&' || r == '=' || r == ' ' {
			if cols >= minKeep {
				best = byteIdx
			}
		}
	}
	if best > 0 {
		return best
	}
	if byteIdx == 0 {
		// Pathological: single wide rune — take one rune.
		_, size := utf8.DecodeRuneInString(s)
		return size
	}
	return byteIdx
}

func hrule(w int) string {
	if w < 1 {
		w = 1
	}
	return styleRule.Render(strings.Repeat("─", w))
}

// placeLR puts left and right on one line of width w without overflowing.
func placeLR(left, right string, w int) string {
	if w < 10 {
		return fit(left+" "+right, w)
	}
	lw := lipgloss.Width(left)
	rw := lipgloss.Width(right)
	if lw+rw+1 > w {
		// Prefer keeping the right badge intact.
		avail := w - rw - 1
		if avail < 8 {
			return fit(left, w)
		}
		return fit(left, avail) + " " + right
	}
	gap := w - lw - rw
	return left + strings.Repeat(" ", gap) + right
}

func padBlock(s string, w int) string {
	if w <= 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lw := lipgloss.Width(line)
		if lw < w {
			lines[i] = line + strings.Repeat(" ", w-lw)
		} else if lw > w {
			lines[i] = fit(line, w)
		}
	}
	return strings.Join(lines, "\n")
}

func indentLines(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n")
}

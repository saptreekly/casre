package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/lipgloss"
)

// Palette: cool slate + teal accent (readable in light/dark terminals).
var (
	colDim      = lipgloss.AdaptiveColor{Light: "#64748B", Dark: "#94A3B8"}
	colMuted    = lipgloss.AdaptiveColor{Light: "#94A3B8", Dark: "#64748B"}
	colText     = lipgloss.AdaptiveColor{Light: "#0F172A", Dark: "#E2E8F0"}
	colAccent   = lipgloss.AdaptiveColor{Light: "#0F766E", Dark: "#2DD4BF"}
	colAccentFg = lipgloss.AdaptiveColor{Light: "#F0FDFA", Dark: "#042F2E"}
	colHigh     = lipgloss.AdaptiveColor{Light: "#B91C1C", Dark: "#F87171"}
	colMedium   = lipgloss.AdaptiveColor{Light: "#C2410C", Dark: "#FB923C"}
	colOK       = lipgloss.AdaptiveColor{Light: "#047857", Dark: "#34D399"}
	colBorder   = lipgloss.AdaptiveColor{Light: "#CBD5E1", Dark: "#334155"}
	colPanel    = lipgloss.AdaptiveColor{Light: "#F1F5F9", Dark: "#1E293B"}
	colSelectBg = lipgloss.AdaptiveColor{Light: "#CCFBF1", Dark: "#134E4A"}
	colSelectFg = lipgloss.AdaptiveColor{Light: "#134E4A", Dark: "#CCFBF1"}

	styleTitle = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	styleDim   = lipgloss.NewStyle().Foreground(colDim)
	styleMuted = lipgloss.NewStyle().Foreground(colMuted)
	styleText  = lipgloss.NewStyle().Foreground(colText)
	styleKey   = lipgloss.NewStyle().Foreground(colDim)

	styleTab = lipgloss.NewStyle().
			Foreground(colDim).
			Padding(0, 2)
	styleTabOn = lipgloss.NewStyle().
			Bold(true).
			Foreground(colAccentFg).
			Background(colAccent).
			Padding(0, 2)

	styleHeader  = lipgloss.NewStyle().Bold(true).Foreground(colText)
	styleSection = lipgloss.NewStyle().Bold(true).Foreground(colAccent)

	stylePanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colBorder).
			Padding(0, 1)

	styleFrame = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colBorder).
			Padding(0, 1)

	styleSelected = lipgloss.NewStyle().
			Background(colSelectBg).
			Foreground(colSelectFg).
			Bold(true)

	styleFooter = lipgloss.NewStyle().Foreground(colMuted)
	styleRule   = lipgloss.NewStyle().Foreground(colBorder)

	styleHigh = lipgloss.NewStyle().Foreground(colHigh).Bold(true)
	styleMed  = lipgloss.NewStyle().Foreground(colMedium).Bold(true)
	styleOK   = lipgloss.NewStyle().Foreground(colOK).Bold(true)

	// styleHint is an alias of muted secondary text (kept for call-site clarity).
	styleHint = styleMuted
	styleDot  = lipgloss.NewStyle().Foreground(colAccent).Bold(true)

	styleScanBtn = lipgloss.NewStyle().
			Bold(true).
			Foreground(colAccentFg).
			Background(colAccent).
			Padding(0, 3)

	styleScanBtnPulse = lipgloss.NewStyle().
				Bold(true).
				Foreground(colAccent).
				Background(colSelectBg).
				Padding(0, 3)

	styleScanBtnOff = lipgloss.NewStyle().
			Foreground(colDim).
			Border(lipgloss.NormalBorder()).
			BorderForeground(colBorder).
			Padding(0, 2)
)

func sevStyle(sev string) lipgloss.Style {
	switch sev {
	case "high", "malicious":
		return styleHigh
	case "medium", "suspicious", "noteworthy":
		return styleMed
	case "ok", "clean":
		return styleOK
	default:
		return styleText
	}
}

func scoreBadge(score int, label string) string {
	text := fmt.Sprintf("%d/100 · %s", score, label)
	base := lipgloss.NewStyle().Bold(true).Padding(0, 1)
	switch label {
	case "malicious":
		return base.Foreground(colAccentFg).Background(colHigh).Render(text)
	case "suspicious", "noteworthy":
		return base.Foreground(colAccentFg).Background(colMedium).Render(text)
	default:
		return base.Foreground(colAccentFg).Background(colOK).Render(text)
	}
}

func kv(key, val string) string {
	return styleKey.Width(labelCol).Render(key) + "  " + styleText.Render(val)
}

func applyTextareaStyles(ta *textarea.Model) {
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle().Background(colPanel)
	ta.FocusedStyle.Placeholder = lipgloss.NewStyle().Foreground(colMuted)
	ta.FocusedStyle.Text = lipgloss.NewStyle().Foreground(colText)
	ta.BlurredStyle.Placeholder = lipgloss.NewStyle().Foreground(colMuted)
	ta.BlurredStyle.Text = lipgloss.NewStyle().Foreground(colDim)
	ta.Prompt = " "
	ta.FocusedStyle.Prompt = lipgloss.NewStyle().Foreground(colAccent)
	ta.BlurredStyle.Prompt = lipgloss.NewStyle().Foreground(colBorder)
}

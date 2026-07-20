package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/saptreekly/casre/internal/config"
	"github.com/saptreekly/casre/internal/scanner"
)

// Setup has two screens: home (URLs + Scan) and options (advanced knobs).
type setupScreen int

const (
	screenHome setupScreen = iota
	screenOptions
)

type setupFocus int

const (
	focusURLs setupFocus = iota
	focusScan
)

type setupModel struct {
	cfg    config.Config
	urls   textarea.Model
	screen setupScreen
	focus  setupFocus
	optIdx int
	err    string
	width  int
	height int
	flash  string
	pulse  bool
}

type setupPulseMsg struct{}

func newSetupModel(cfg config.Config, seed string) setupModel {
	ta := textarea.New()
	ta.Placeholder = "https://suspicious-link.example/path"
	ta.Focus()
	ta.CharLimit = 0
	ta.SetWidth(64)
	ta.SetHeight(4)
	ta.ShowLineNumbers = false
	applyTextareaStyles(&ta)
	if seed != "" {
		ta.SetValue(seed)
	}

	return setupModel{
		cfg:    cfg,
		urls:   ta,
		screen: screenHome,
		focus:  focusURLs,
	}
}

func (m setupModel) Init() tea.Cmd {
	return setupPulse()
}

func setupPulse() tea.Cmd {
	return tea.Tick(700*time.Millisecond, func(time.Time) tea.Msg {
		return setupPulseMsg{}
	})
}

func (m setupModel) applyConfig() config.Config {
	cfg := m.cfg
	if !cfg.Follow {
		cfg.Campaign = false
	}
	if cfg.CrawlPreset == "" {
		cfg.CrawlPreset = config.DetectCrawlPreset(cfg)
	}
	if cfg.FuzzMaxHosts <= 0 {
		cfg.FuzzMaxHosts = 2
	}
	return cfg
}

type launchSubmitMsg struct {
	targets []scanner.Target
	cfg     config.Config
}

type launchCancelMsg struct{}
type setupErrMsg struct{ text string }

func (m setupModel) Update(msg tea.Msg) (setupModel, tea.Cmd) {
	switch msg := msg.(type) {
	case setupPulseMsg:
		m.pulse = !m.pulse
		return m, setupPulse()
	case setupErrMsg:
		m.err = msg.text
		return m, nil
	case tea.KeyMsg:
		m.err = ""
		m.flash = ""

		if m.screen == screenOptions {
			return m.updateOptions(msg)
		}
		return m.updateHome(msg)
	}
	return m, nil
}

func (m setupModel) updateHome(msg tea.KeyMsg) (setupModel, tea.Cmd) {
	switch msg.String() {
	case "ctrl+s":
		return m.submit()
	case "tab":
		if m.focus == focusURLs {
			m.urls.Blur()
			m.focus = focusScan
		} else {
			m.focus = focusURLs
			m.urls.Focus()
		}
		return m, nil
	case "shift+tab":
		if m.focus == focusScan {
			m.focus = focusURLs
			m.urls.Focus()
		} else {
			m.urls.Blur()
			m.focus = focusScan
		}
		return m, nil
	case "enter":
		if m.focus == focusScan {
			return m.submit()
		}
	case "o", "ctrl+o":
		m.urls.Blur()
		m.screen = screenOptions
		m.optIdx = 0
		m.flash = ""
		if m.cfg.CrawlPreset == "" {
			m.cfg.CrawlPreset = config.DetectCrawlPreset(m.cfg)
		}
		return m, nil
	case " ":
		if m.focus == focusScan {
			return m.submit()
		}
	}

	var cmd tea.Cmd
	if m.focus == focusURLs {
		m.urls, cmd = m.urls.Update(msg)
	}
	return m, cmd
}

func (m setupModel) updateOptions(msg tea.KeyMsg) (setupModel, tea.Cmd) {
	const nOpts = 7 // preset, depth, maxurls, timeout, follow, campaign, fuzz
	switch msg.String() {
	case "esc", "o", "q":
		m.screen = screenHome
		m.focus = focusURLs
		m.urls.Focus()
		m.flash = "Back — ready to scan"
		return m, nil
	case "j", "down", "tab":
		m.optIdx = (m.optIdx + 1) % nOpts
		return m, nil
	case "k", "up", "shift+tab":
		m.optIdx--
		if m.optIdx < 0 {
			m.optIdx = nOpts - 1
		}
		return m, nil
	case "left", "h":
		m.nudgeOption(-1)
		return m, nil
	case "right", "l", "enter", " ":
		m.nudgeOption(1)
		return m, nil
	}
	return m, nil
}

func (m *setupModel) nudgeOption(delta int) {
	switch m.optIdx {
	case 0:
		config.CycleCrawlPreset(&m.cfg, delta)
	case 1:
		m.cfg.Depth = clampInt(m.cfg.Depth+delta, 1, 20)
		config.MarkCustomPreset(&m.cfg)
	case 2:
		step := 5
		if delta < 0 {
			step = -5
		}
		m.cfg.MaxURLs = clampInt(m.cfg.MaxURLs+step, 1, 200)
		config.MarkCustomPreset(&m.cfg)
	case 3:
		sec := int(m.cfg.Timeout.Seconds()) + delta
		m.cfg.Timeout = time.Duration(clampInt(sec, 1, 60)) * time.Second
	case 4:
		m.cfg.Follow = !m.cfg.Follow
		if !m.cfg.Follow {
			m.cfg.Campaign = false
		} else if !m.cfg.Campaign {
			m.cfg.Campaign = true
		}
		config.MarkCustomPreset(&m.cfg)
	case 5:
		if m.cfg.Follow {
			m.cfg.Campaign = !m.cfg.Campaign
			config.MarkCustomPreset(&m.cfg)
		}
	case 6:
		m.cfg.FuzzPaths = !m.cfg.FuzzPaths
		config.MarkCustomPreset(&m.cfg)
	}
}

func (m setupModel) submit() (setupModel, tea.Cmd) {
	targets, err := parseTargetLines(m.urls.Value())
	if err != nil {
		m.err = err.Error()
		return m, nil
	}
	if len(targets) == 0 {
		m.err = "Paste a URL above, then press Scan"
		m.focus = focusURLs
		m.urls.Focus()
		return m, nil
	}
	cfg := m.applyConfig()
	return m, func() tea.Msg {
		return launchSubmitMsg{targets: targets, cfg: cfg}
	}
}

func parseTargetLines(raw string) ([]scanner.Target, error) {
	seen := map[string]struct{}{}
	var out []scanner.Target
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t, err := scanner.ParseTarget(line)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse %q", truncate(line, 40))
		}
		key := strings.ToLower(t.Host) + "\x00" + t.URL
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, t)
	}
	return out, nil
}

func (m setupModel) View() string {
	if m.screen == screenOptions {
		return m.viewOptions()
	}
	return m.viewHome()
}

func (m setupModel) viewHome() string {
	w := max(m.width, 40)
	// Total visual columns for the URL panel (borders included).
	panelCols := min(w-2, 72)
	if panelCols < 28 {
		panelCols = 28
	}
	// Border is outside Width; padding is inside Width.
	innerW := panelCols - 2
	m.urls.SetWidth(max(16, innerW-2))

	var b strings.Builder
	b.WriteString(placeLR(styleTitle.Render("CASRE"), styleMuted.Render("investigate a link"), w) + "\n")
	b.WriteString(hrule(w) + "\n\n")

	step1 := "1 · Paste the URL"
	if m.focus == focusURLs {
		step1 = "▸ 1 · Paste the URL"
	}
	b.WriteString(styleSection.Render(step1) + "\n")
	b.WriteString(styleMuted.Render("  One link per line") + "\n")
	panel := stylePanel.
		Width(innerW).
		BorderForeground(focusBorder(m.focus == focusURLs)).
		Render(m.urls.View())
	b.WriteString(panel + "\n\n")

	step2 := "2 · Start the scan"
	if m.focus == focusScan {
		step2 = "▸ 2 · Start the scan"
	}
	b.WriteString(styleSection.Render(step2) + "\n")
	btn := styleScanBtnOff.Render("  Scan  ")
	if m.focus == focusScan {
		if m.pulse {
			btn = styleScanBtnPulse.Render("  Scan  ")
		} else {
			btn = styleScanBtn.Render("  Scan  ")
		}
	}
	b.WriteString(indentLines(btn, "  ") + "\n")
	b.WriteString(styleMuted.Render("  Tab → Scan · Enter · or Ctrl+S") + "\n")

	if m.err != "" {
		b.WriteString("\n" + styleHigh.Render(fit("  "+m.err, w)) + "\n")
	}
	if m.flash != "" {
		b.WriteString("\n" + styleMuted.Render(fit("  "+m.flash, w)) + "\n")
	}

	b.WriteString("\n")
	b.WriteString(styleFooter.Render(fit("o  options   ·   ctrl+c  quit", w)))
	return b.String()
}

func (m setupModel) viewOptions() string {
	w := max(m.width, 40)
	preset := m.cfg.CrawlPreset
	if preset == "" {
		preset = config.DetectCrawlPreset(m.cfg)
	}
	rows := []struct {
		label string
		value string
		help  string
	}{
		{"Crawl profile", presetLabel(preset), "Quick / Deep / Wide / Custom"},
		{"How deep to follow", strconv.Itoa(m.cfg.Depth) + " hops", "← → change (switches to Custom)"},
		{"Max pages to visit", strconv.Itoa(m.cfg.MaxURLs), "← → change (switches to Custom)"},
		{"Connection timeout", fmt.Sprintf("%g s", m.cfg.Timeout.Seconds()), "← → change"},
		{"Follow redirects & JS", onOffWords(m.cfg.Follow), "space toggle"},
		{"Campaign mode", campaignWords(m.cfg), "stops at brand/CDN decoys"},
		{"Path fuzzing", fuzzWords(m.cfg), "probe admin/kit paths on landers"},
	}

	var b strings.Builder
	b.WriteString(placeLR(styleTitle.Render("CASRE"), styleMuted.Render("options"), w) + "\n")
	b.WriteString(hrule(w) + "\n\n")
	b.WriteString(styleText.Render(fit("Profiles set depth + fuzz. Tune knobs anytime.", w)) + "\n\n")

	labelW := optLabelCol
	for i, row := range rows {
		valBudget := max(8, w-labelW-8)
		line := fmt.Sprintf("%-*s  %s", labelW, row.label, fit(row.value, valBudget))
		selected := i == m.optIdx
		b.WriteString(selectRow(selected, gutter(selected)+line, w) + "\n")
		if selected {
			b.WriteString(mutedDetail(row.help, w) + "\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(styleMuted.Render(fit(presetBlurb(preset), w)) + "\n")
	b.WriteString("\n" + styleFooter.Render(fit("↑↓ choose  ·  ←→ change  ·  esc back", w)))
	return b.String()
}

func presetLabel(p string) string {
	switch p {
	case config.PresetQuick:
		return "Quick"
	case config.PresetDeep:
		return "Deep"
	case config.PresetWide:
		return "Wide"
	default:
		return "Custom"
	}
}

func presetBlurb(p string) string {
	switch p {
	case config.PresetQuick:
		return "Quick: 3 hops · 12 pages · campaign on · lite fuzz"
	case config.PresetDeep:
		return "Deep: 12 hops · 60 pages · campaign on · full fuzz"
	case config.PresetWide:
		return "Wide: 6 hops · 100 pages · campaign off · full fuzz"
	default:
		return "Custom: manual depth / pages / fuzz"
	}
}

func fuzzWords(cfg config.Config) string {
	if !cfg.Follow {
		return "—"
	}
	if cfg.FuzzPaths {
		return "On"
	}
	return "Off"
}

func focusBorder(on bool) lipgloss.TerminalColor {
	if on {
		return colAccent
	}
	return colBorder
}

func onOffWords(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
}

func campaignWords(cfg config.Config) string {
	if !cfg.Follow {
		return "—"
	}
	if cfg.Campaign {
		return "On (recommended)"
	}
	return "Off (crawl more)"
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

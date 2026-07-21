package tui

import (
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/saptreekly/casre/internal/diff"
	"github.com/saptreekly/casre/internal/scanner"
)

type tabID int

const (
	tabStory tabID = iota
	tabChain
	tabAlerts
	tabIndicators
	tabHost
	tabDiff
)

// Plain-language tabs + number shortcuts shown in the bar.
var tabNames = []string{"Story", "Chain", "Alerts", "Indicators", "Host", "Diff"}
var tabKeys = []string{"1", "2", "3", "4", "5", "6"}

type model struct {
	results []scanner.Result
	ri      int

	tab      tabID
	width    int
	height   int
	ready    bool
	status   string
	showFull bool
	showInfo bool // Alerts: include INFO findings

	hopIdx   int
	findIdx  int
	iocIdx   int
	hostIdx  int
	storyIdx int
	// hostExpanded tracks which Host-page groups are fully shown (e.g. "dns:A").
	hostExpanded map[string]bool

	vp viewport.Model

	picking bool
	pickIdx int

	changes  []diff.Change
	compared bool
}

func newModel(results []scanner.Result) model {
	return newModelWithDiff(results, nil, false)
}

func newModelWithDiff(results []scanner.Result, changes []diff.Change, compared bool) model {
	// Annotate cross-target campaign links (shared IP/ASN/cert/favicon/kit).
	scanner.CorrelateCampaigns(results)
	m := model{
		results:  results,
		picking:  len(results) > 1,
		tab:      tabStory,
		changes:  changes,
		compared: compared,
	}
	if compared {
		m.tab = tabDiff
	}
	m.vp = viewport.New(80, 20)
	m.refreshViewport()
	return m
}

func (m model) result() scanner.Result {
	if m.ri < 0 || m.ri >= len(m.results) {
		return scanner.Result{}
	}
	return m.results[m.ri]
}

func (m model) Init() tea.Cmd {
	return nil
}

type statusMsg struct{ text string }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case statusMsg:
		m.status = msg.text
		return m, nil

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.sizeViewport()
		m.ready = true
		m.refreshViewport()
		return m, nil

	case tea.KeyMsg:
		m.status = ""
		if m.picking {
			return m.updatePicker(msg)
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "esc":
			// Let app intercept esc for "new scan"; if we get it here, quit picker.
			if m.picking {
				m.picking = false
				m.refreshViewport()
				return m, nil
			}
			return m, tea.Quit
		case "tab":
			m.tab = (m.tab + 1) % tabID(len(tabNames))
			m.showFull = false
			m.findIdx = 0
			m.refreshViewport()
		case "shift+tab":
			m.tab--
			if m.tab < 0 {
				m.tab = tabID(len(tabNames) - 1)
			}
			m.showFull = false
			m.findIdx = 0
			m.refreshViewport()
		case "1", "2", "3", "4", "5", "6":
			idx := int(msg.String()[0] - '1')
			if idx < len(tabNames) {
				m.tab = tabID(idx)
				m.showFull = false
				m.findIdx = 0
				m.refreshViewport()
			}
		case "j", "down":
			m.moveSel(1)
			m.refreshViewport()
		case "k", "up":
			m.moveSel(-1)
			m.refreshViewport()
		case "f":
			m.showFull = !m.showFull
			m.refreshViewport()
		case "i":
			if m.tab == tabAlerts {
				m.showInfo = !m.showInfo
				m.findIdx = 0
				m.refreshViewport()
			}
		case "c":
			if u := m.selectedURL(); u != "" {
				return m, copyURLCmd(u)
			}
		case "e":
			return m, exportIOCsCmd(m.result())
		case "enter":
			switch m.tab {
			case tabChain, tabIndicators:
				m.showFull = !m.showFull
				m.refreshViewport()
			case tabHost:
				m.toggleHostExpand()
				m.refreshViewport()
			}
		default:
			var cmd tea.Cmd
			m.vp, cmd = m.vp.Update(msg)
			return m, cmd
		}
	}
	return m, nil
}

func (m model) updatePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "j", "down":
		if m.pickIdx < len(m.results)-1 {
			m.pickIdx++
		}
	case "k", "up":
		if m.pickIdx > 0 {
			m.pickIdx--
		}
	case "enter":
		m.ri = m.pickIdx
		m.picking = false
		m.tab = tabStory
		m.hopIdx = 0
		m.findIdx = 0
		m.iocIdx = 0
		m.hostIdx = 0
		m.storyIdx = 0
		m.showFull = false
		m.refreshViewport()
	}
	return m, nil
}

func (m *model) moveSel(delta int) {
	switch m.tab {
	case tabStory:
		n := len(m.storyItems())
		if n == 0 {
			return
		}
		m.storyIdx = clamp(m.storyIdx+delta, 0, n-1)
	case tabChain:
		n := len(m.result().Hops)
		if n == 0 && m.result().Graph != nil {
			n = len(m.result().Graph.Nodes)
		}
		if n == 0 {
			return
		}
		m.hopIdx = clamp(m.hopIdx+delta, 0, n-1)
		m.showFull = false
	case tabAlerts:
		n := len(m.visibleFindings())
		if n == 0 {
			return
		}
		m.findIdx = clamp(m.findIdx+delta, 0, n-1)
	case tabIndicators:
		n := iocCount(m.result().IOCs)
		if n == 0 {
			return
		}
		m.iocIdx = clamp(m.iocIdx+delta, 0, n-1)
		m.showFull = false
	case tabHost:
		n := len(m.infraItems())
		if n == 0 {
			return
		}
		m.hostIdx = clamp(m.hostIdx+delta, 0, n-1)
	default:
		if delta > 0 {
			m.vp.LineDown(1)
		} else {
			m.vp.LineUp(1)
		}
	}
}

func (m model) selectedURL() string {
	r := m.result()
	switch m.tab {
	case tabChain:
		if len(r.Hops) > 0 && m.hopIdx < len(r.Hops) {
			return r.Hops[m.hopIdx].URL
		}
		if r.Graph != nil && m.hopIdx < len(r.Graph.Nodes) {
			return r.Graph.Nodes[m.hopIdx].URL
		}
	case tabIndicators:
		items := flatIOCs(r.IOCs)
		if m.iocIdx < len(items) && items[m.iocIdx].Type == "url" {
			return items[m.iocIdx].Value
		}
	case tabHost:
		items := m.infraItems()
		if m.hostIdx < len(items) && items[m.hostIdx].kind == "" {
			return items[m.hostIdx].value
		}
	case tabStory:
		items := m.storyItems()
		if m.storyIdx < len(items) {
			return items[m.storyIdx].value
		}
	}
	return ""
}

func (m *model) refreshViewport() {
	if m.picking {
		m.vp.SetContent(m.viewPicker())
		return
	}
	var body string
	switch m.tab {
	case tabStory:
		body = m.viewOverview()
	case tabChain:
		body = m.viewGraph()
	case tabAlerts:
		body = m.viewFindings()
	case tabIndicators:
		body = m.viewIOCs()
	case tabHost:
		body = m.viewInfra()
	case tabDiff:
		body = m.viewDiff()
	}
	m.vp.SetContent(body)
	m.ensureSelectionVisible(body)
}

// ensureSelectionVisible scrolls the viewport so the ▸ selection stays on screen.
func (m *model) ensureSelectionVisible(body string) {
	switch m.tab {
	case tabChain, tabAlerts, tabIndicators, tabHost, tabStory:
	default:
		return
	}
	selLine := -1
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		// Strip ANSI for a reliable marker search.
		if strings.Contains(line, "▸") {
			selLine = i
			break
		}
	}
	if selLine < 0 {
		return
	}
	h := m.vp.Height
	if h <= 0 {
		return
	}
	// Leave a little context above the selection when scrolling down.
	if selLine < m.vp.YOffset {
		m.vp.SetYOffset(selLine)
	} else if selLine >= m.vp.YOffset+h {
		m.vp.SetYOffset(selLine - h + 1)
	}
}

func (m model) visibleFindings() []scanner.Finding {
	var out []scanner.Finding
	for _, f := range m.result().Findings {
		if !m.showInfo && strings.EqualFold(f.Severity, "info") {
			continue
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := sevRank(out[i].Severity), sevRank(out[j].Severity)
		if si != sj {
			return si < sj
		}
		ci, cj := catRank(out[i].Category), catRank(out[j].Category)
		if ci != cj {
			return ci < cj
		}
		return out[i].Message < out[j].Message
	})
	return out
}

func (m model) footerHelp() string {
	base := "1–6 tabs  ·  r rescan  ·  e export IOCs  ·  esc new scan  ·  q quit"
	switch m.tab {
	case tabStory:
		return "↑↓ move  ·  c copy  ·  " + base
	case tabChain:
		return "↑↓ hops  ·  f full url  ·  c copy  ·  " + base
	case tabAlerts:
		return "↑↓ move  ·  i show info  ·  " + base
	case tabIndicators:
		return "↑↓ move  ·  f full url  ·  c copy  ·  " + base
	case tabHost:
		return "↑↓ move  ·  enter expand  ·  c copy  ·  " + base
	case tabDiff:
		return "r rescan again  ·  " + base
	default:
		return base
	}
}

// chromeLines is the fixed vertical budget above/below the viewport.
const (
	chromeHeaderLines = 2 // title row + narrative (or blank)
	chromeTabsLines   = 2 // tabs + blank
	chromeFooterLines = 2 // blank + footer
	chromeRules       = 1 // top rule
)

func (m model) chromeHeight() int {
	return chromeHeaderLines + chromeTabsLines + chromeFooterLines + chromeRules
}

func (m *model) sizeViewport() {
	w := max(20, m.width)
	h := max(5, m.height-m.chromeHeight())
	m.vp.Width = w
	m.vp.Height = h
}

func (m model) View() string {
	if !m.ready {
		return styleMuted.Render("loading…")
	}
	w := max(20, m.width)

	if m.picking {
		return lipgloss.JoinVertical(lipgloss.Left,
			placeLR(styleTitle.Render("CASRE"), styleMuted.Render("select a target"), w),
			hrule(w),
			"",
			m.vp.View(),
			"",
			styleFooter.Render(fit("↑↓ move  ·  enter open  ·  q quit", w)),
		)
	}

	r := m.result()
	footer := m.footerHelp()
	if m.status != "" {
		footer = m.status + "  ·  " + footer
	}
	return lipgloss.JoinVertical(lipgloss.Left,
		m.viewHeader(r, w),
		hrule(w),
		m.viewTabs(w),
		"",
		m.vp.View(),
		"",
		styleFooter.Render(fit(footer, w)),
	)
}

func (m model) viewHeader(r scanner.Result, w int) string {
	left := styleTitle.Render("CASRE")
	if r.Host != "" {
		left += "  " + styleHeader.Render(fit(r.Host, max(8, w/3)))
	}
	right := ""
	if r.Verdict != nil {
		right = scoreBadge(r.Verdict.Score, r.Verdict.Label)
	}
	if r.Investigation != nil && r.Investigation.Confidence.Level != "" {
		if right != "" {
			right += "  "
		}
		right += confidenceBadge(r.Investigation.Confidence)
	}
	if r.Duration != "" {
		if right != "" {
			right += " "
		}
		right += styleMuted.Render(r.Duration)
	}
	line1 := placeLR(left, right, w)
	narr := ""
	if r.Verdict != nil && r.Verdict.Narrative != "" {
		narr = styleMuted.Render(fit(r.Verdict.Narrative, w))
	} else {
		narr = " " // keep header height stable
	}
	return line1 + "\n" + narr
}

func (m model) viewTabs(w int) string {
	var parts []string
	for i, name := range tabNames {
		label := tabKeys[i] + " " + name
		if tabID(i) == m.tab {
			parts = append(parts, styleTabOn.Render(label))
		} else {
			parts = append(parts, styleTab.Render(label))
		}
	}
	row := strings.Join(parts, "")
	if lipgloss.Width(row) > w {
		// Narrow terminals: numbers only for inactive tabs.
		parts = parts[:0]
		for i, name := range tabNames {
			if tabID(i) == m.tab {
				parts = append(parts, styleTabOn.Render(tabKeys[i]+" "+name))
			} else {
				parts = append(parts, styleTab.Render(tabKeys[i]))
			}
		}
		row = strings.Join(parts, "")
	}
	return row
}

func (m model) viewPicker() string {
	var b strings.Builder
	for i, r := range m.results {
		label := r.Host
		if r.Verdict != nil {
			label += fmt.Sprintf("  %d/100 %s", r.Verdict.Score, r.Verdict.Label)
		}
		if r.FinalHost != "" {
			label += " → " + r.FinalHost
		}
		line := fmt.Sprintf("%s%d. %s", gutter(i == m.pickIdx), i+1, label)
		if i == m.pickIdx {
			line = selectRow(true, line, max(40, m.vp.Width))
		} else {
			line = fit(line, max(40, m.vp.Width))
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func exportIOCsCmd(r scanner.Result) tea.Cmd {
	return func() tea.Msg {
		if r.IOCs == nil {
			return statusMsg{text: "no IOCs to export"}
		}
		host := r.Host
		if host == "" {
			host = "target"
		}
		safe := strings.Map(func(rr rune) rune {
			switch {
			case rr >= 'a' && rr <= 'z', rr >= 'A' && rr <= 'Z', rr >= '0' && rr <= '9', rr == '-', rr == '.':
				return rr
			default:
				return '_'
			}
		}, host)
		stamp := time.Now().Format("20060102-150405")
		base := fmt.Sprintf("casre-iocs-%s-%s", safe, stamp)

		csvPath := base + ".csv"
		stixPath := base + ".stix.json"
		if err := os.WriteFile(csvPath, []byte(scanner.ExportIOCsCSV(r.IOCs)), 0o644); err != nil {
			return statusMsg{text: "export failed: " + err.Error()}
		}
		if err := os.WriteFile(stixPath, []byte(scanner.ExportIOCsSTIX(r.IOCs, host)), 0o644); err != nil {
			return statusMsg{text: "export failed: " + err.Error()}
		}
		return statusMsg{text: fmt.Sprintf("exported %d IOC(s) → %s + %s", len(r.IOCs.All), csvPath, stixPath)}
	}
}

func copyURLCmd(s string) tea.Cmd {
	payload := base64.StdEncoding.EncodeToString([]byte(s))
	msg := "copied"
	if len(s) > 48 {
		msg = "copied (" + truncate(s, 48) + ")"
	}
	return tea.Batch(
		tea.Printf("\033]52;c;%s\a", payload),
		func() tea.Msg { return statusMsg{text: msg} },
	)
}

func truncate(s string, n int) string {
	return fit(s, n)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func iocCount(set *scanner.IOCSet) int {
	return len(flatIOCs(set))
}

func flatIOCs(set *scanner.IOCSet) []scanner.IOC {
	if set == nil {
		return nil
	}
	if len(set.All) > 0 {
		return set.All
	}
	var out []scanner.IOC
	out = append(out, set.Domains...)
	out = append(out, set.IPs...)
	out = append(out, set.URLs...)
	out = append(out, set.ASNs...)
	return out
}

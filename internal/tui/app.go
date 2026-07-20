package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/saptreekly/casre/internal/config"
	"github.com/saptreekly/casre/internal/diff"
	"github.com/saptreekly/casre/internal/scanner"
)

type phase int

const (
	phaseSetup phase = iota
	phaseScanning
	phaseResults
)

// ScanFunc runs a scan and returns results (called from the TUI during the scanning phase).
type ScanFunc func(ctx context.Context, cfg config.Config, targets []scanner.Target) ([]scanner.Result, error)

type appModel struct {
	phase  phase
	setup  setupModel
	result model
	spin   spinner.Model

	cfg     config.Config
	seed    string
	targets []scanner.Target
	scanFn  ScanFunc

	width  int
	height int
	status string
	cancel context.CancelFunc

	scanStage  int
	scanFrames int

	baseline   []scanner.Result // previous results for compare
	rescanning bool
}

type scanDoneMsg struct {
	results []scanner.Result
	err     error
	took    time.Duration
}

type scanPulseMsg struct{}

var scanStages = []string{
	"Resolving DNS…",
	"Checking TLS…",
	"Fetching the page…",
	"Reading redirects & JS…",
	"Mapping the campaign…",
	"Path fuzzing…",
	"Scoring verdict…",
}

var rescanStages = []string{
	"Re-checking DNS…",
	"Re-fetching the page…",
	"Re-reading redirects…",
	"Path fuzzing…",
	"Comparing to last scan…",
}

// RunApp opens the setup UI, runs the scan, then shows the results browser.
// seed pre-fills the target textarea (optional positional URLs).
func RunApp(cfg config.Config, seed string, scanFn ScanFunc) error {
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = lipgloss.NewStyle().Foreground(colAccent)

	m := appModel{
		phase:  phaseSetup,
		setup:  newSetupModel(cfg, seed),
		spin:   s,
		cfg:    cfg,
		seed:   seed,
		scanFn: scanFn,
	}
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithOutput(os.Stdout))
	_, err := p.Run()
	return err
}

func (m appModel) Init() tea.Cmd {
	return m.setup.Init()
}

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.setup.width = msg.Width
		m.setup.height = msg.Height
		if m.phase == phaseResults {
			nm, cmd := m.result.Update(msg)
			m.result = nm.(model)
			return m, cmd
		}
		return m, nil

	case launchCancelMsg:
		return m, tea.Quit

	case setupErrMsg:
		m.setup.err = msg.text
		return m, nil

	case launchSubmitMsg:
		m.cfg = msg.cfg
		m.targets = msg.targets
		m.baseline = nil
		m.rescanning = false
		m.phase = phaseScanning
		m.scanStage = 0
		m.scanFrames = 0
		ctx, cancel := context.WithCancel(context.Background())
		m.cancel = cancel
		return m, tea.Batch(m.spin.Tick, scanPulse(), m.startScan(ctx, msg.cfg, msg.targets))

	case scanPulseMsg:
		if m.phase != phaseScanning {
			return m, nil
		}
		m.scanFrames++
		if m.scanFrames%4 == 0 {
			n := len(scanStages)
			if m.rescanning {
				n = len(rescanStages)
			}
			m.scanStage = (m.scanStage + 1) % n
		}
		return m, scanPulse()

	case scanDoneMsg:
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		if msg.err != nil {
			m.phase = phaseSetup
			m.setup.err = msg.err.Error()
			m.rescanning = false
			return m, nil
		}
		if len(msg.results) == 0 {
			m.phase = phaseSetup
			m.setup.err = "scan returned no results"
			m.rescanning = false
			return m, nil
		}

		var changes []diff.Change
		compared := false
		if m.rescanning && len(m.baseline) > 0 {
			old := &diff.Report{Version: 1, Results: m.baseline}
			neu := &diff.Report{Version: 1, Results: msg.results}
			changes = diff.Compare(old, neu)
			compared = true
		}
		m.baseline = msg.results
		m.rescanning = false

		m.result = newModelWithDiff(msg.results, changes, compared)
		m.result.width = m.width
		m.result.height = m.height
		m.result.ready = true
		m.result.sizeViewport()
		m.result.refreshViewport()
		m.phase = phaseResults
		if compared {
			m.status = fmt.Sprintf("%d change(s) · scanned in %s", len(changes), msg.took.Round(time.Millisecond))
			m.result.status = m.status
		} else {
			m.status = fmt.Sprintf("scanned in %s", msg.took.Round(time.Millisecond))
		}
		return m, nil

	case spinner.TickMsg:
		if m.phase != phaseScanning {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		switch m.phase {
		case phaseScanning:
			if msg.String() == "ctrl+c" || msg.String() == "q" {
				if m.cancel != nil {
					m.cancel()
				}
				return m, tea.Quit
			}
			return m, nil
		case phaseSetup:
			if msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
			var cmd tea.Cmd
			m.setup, cmd = m.setup.Update(msg)
			return m, cmd
		case phaseResults:
			if msg.String() == "esc" {
				m.phase = phaseSetup
				m.baseline = nil
				m.rescanning = false
				m.setup = newSetupModel(m.cfg, m.setup.urls.Value())
				m.setup.width = m.width
				m.setup.height = m.height
				return m, m.setup.Init()
			}
			if msg.String() == "r" && len(m.targets) > 0 {
				// Snapshot current results as the compare baseline, then rescan.
				m.baseline = append([]scanner.Result(nil), m.result.results...)
				m.rescanning = true
				m.phase = phaseScanning
				m.scanStage = 0
				m.scanFrames = 0
				ctx, cancel := context.WithCancel(context.Background())
				m.cancel = cancel
				return m, tea.Batch(m.spin.Tick, scanPulse(), m.startScan(ctx, m.cfg, m.targets))
			}
			nm, cmd := m.result.Update(msg)
			m.result = nm.(model)
			return m, cmd
		}
	}

	if m.phase == phaseSetup {
		var cmd tea.Cmd
		m.setup, cmd = m.setup.Update(msg)
		return m, cmd
	}
	if m.phase == phaseResults {
		nm, cmd := m.result.Update(msg)
		m.result = nm.(model)
		return m, cmd
	}
	return m, nil
}

func scanPulse() tea.Cmd {
	return tea.Tick(280*time.Millisecond, func(time.Time) tea.Msg {
		return scanPulseMsg{}
	})
}

func (m appModel) startScan(ctx context.Context, cfg config.Config, targets []scanner.Target) tea.Cmd {
	return func() tea.Msg {
		start := time.Now()
		results, err := m.scanFn(ctx, cfg, targets)
		return scanDoneMsg{results: results, err: err, took: time.Since(start)}
	}
}

func (m appModel) View() string {
	w := max(40, m.width)
	switch m.phase {
	case phaseSetup:
		return m.setup.View()
	case phaseScanning:
		return m.viewScanning(w)
	case phaseResults:
		return m.result.View()
	default:
		return ""
	}
}

func (m appModel) viewScanning(w int) string {
	n := len(m.targets)
	hosts := make([]string, 0, min(3, n))
	for i, t := range m.targets {
		if i >= 3 {
			break
		}
		hosts = append(hosts, t.Host)
	}
	extra := ""
	if n > 3 {
		extra = fmt.Sprintf(" +%d more", n-3)
	}

	stages := scanStages
	titleRight := "scanning"
	if m.rescanning {
		stages = rescanStages
		titleRight = "rescanning"
	}
	stage := stages[m.scanStage%len(stages)]

	var stageList strings.Builder
	for i, s := range stages {
		mark := "·"
		style := styleMuted
		if i < m.scanStage%len(stages) {
			mark = "✓"
			style = styleOK
		} else if i == m.scanStage%len(stages) {
			mark = "▸"
			style = styleSection
		}
		stageList.WriteString(style.Render(fit(fmt.Sprintf("  %s  %s", mark, s), w)) + "\n")
	}

	body := lipgloss.JoinVertical(lipgloss.Left,
		placeLR(styleTitle.Render("CASRE"), styleMuted.Render(titleRight), w),
		hrule(w),
		"",
		m.spin.View()+"  "+styleText.Render(stage),
		styleMuted.Render(fit(fmt.Sprintf("  %d target%s · %s%s", n, plural(n), strings.Join(hosts, " · "), extra), w)),
		"",
		stageList.String(),
		styleHint.Render("  ctrl+c cancel"),
	)
	return body
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

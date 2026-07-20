package tui

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/saptreekly/casre/internal/scanner"
)

// Run launches the post-scan interactive TUI. Blocks until quit.
func Run(results []scanner.Result) error {
	if len(results) == 0 {
		return fmt.Errorf("no results to display")
	}
	m := newModel(results)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithOutput(os.Stdout))
	_, err := p.Run()
	return err
}

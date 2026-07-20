package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestFitDoesNotExceedWidth(t *testing.T) {
	s := strings.Repeat("abcdefghij", 20)
	got := fit(s, 40)
	if lipgloss.Width(got) > 40 {
		t.Fatalf("fit width %d > 40: %q", lipgloss.Width(got), got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("expected ellipsis, got %q", got)
	}
}

func TestWrapBreaksAtDelimiters(t *testing.T) {
	s := "https://example.com/path?foo=1&bar=2#frag"
	got := wrap(s, 24)
	for _, line := range strings.Split(got, "\n") {
		if lipgloss.Width(line) > 24 {
			t.Fatalf("line too wide (%d): %q", lipgloss.Width(line), line)
		}
	}
	if !strings.Contains(got, "\n") {
		t.Fatalf("expected wrap, got %q", got)
	}
}

func TestPlaceLRFits(t *testing.T) {
	left := "CASRE  example.com"
	right := "85/100 · malicious"
	got := placeLR(left, right, 50)
	if lipgloss.Width(got) > 50 {
		t.Fatalf("placeLR width %d > 50: %q", lipgloss.Width(got), got)
	}
}

func TestBorderBoxFitsContainer(t *testing.T) {
	w := 60
	box := styleFrame.Width(w - 2).Render("hello\nworld")
	if lipgloss.Width(box) != w {
		t.Fatalf("bordered box width %d, want %d", lipgloss.Width(box), w)
	}
	for i, line := range strings.Split(box, "\n") {
		if lipgloss.Width(line) != w {
			t.Fatalf("line %d width %d, want %d: %q", i, lipgloss.Width(line), w, line)
		}
	}
}

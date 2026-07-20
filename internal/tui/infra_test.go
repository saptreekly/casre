package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/saptreekly/casre/internal/scanner"
)

func TestFormatInfraRowAlignsContinuations(t *testing.T) {
	first := labeledRow(false, "A", "1.2.3.4", hostLabelCol, 60, false)
	cont := labeledRow(false, "", "5.6.7.8", hostLabelCol, 60, false)
	sel := labeledRow(true, "", "9.9.9.9", hostLabelCol, 60, false)

	col := func(s, val string) int {
		plain := stripANSI(s)
		i := strings.Index(plain, val)
		if i < 0 {
			return -1
		}
		return lipgloss.Width(plain[:i])
	}

	want := col(first, "1.2.3.4")
	if want < 0 {
		t.Fatalf("first row: %q", stripANSI(first))
	}
	if got := col(cont, "5.6.7.8"); got != want {
		t.Fatalf("continuation value col %d, want %d\nfirst=%q\ncont =%q", got, want, stripANSI(first), stripANSI(cont))
	}
	if got := col(sel, "9.9.9.9"); got != want {
		t.Fatalf("selected value col %d, want %d\nsel=%q", got, want, stripANSI(sel))
	}
}

func TestInfraExpandCollapse(t *testing.T) {
	ips := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		ips = append(ips, fmt.Sprintf("1.1.1.%d", i))
	}
	m := model{
		results: []scanner.Result{{
			DNS: &scanner.DNSResult{A: ips},
		}},
		hostExpanded: map[string]bool{},
	}
	items := m.infraItems()
	var expandIdx = -1
	for i, it := range items {
		if it.kind == "expand" {
			expandIdx = i
			break
		}
	}
	if expandIdx < 0 {
		t.Fatalf("expected expand row, got %+v", items)
	}
	m.hostIdx = expandIdx
	m.toggleHostExpand()
	items = m.infraItems()
	if !m.hostExpanded["dns:A"] {
		t.Fatal("expected dns:A expanded")
	}
	foundCollapse := false
	shown := 0
	for _, it := range items {
		if it.group == "dns:A" && it.kind == "" {
			shown++
		}
		if it.kind == "collapse" && it.group == "dns:A" {
			foundCollapse = true
			m.hostIdx = 0 // will set below
		}
	}
	if shown != 8 {
		t.Fatalf("expected 8 A records when expanded, got %d", shown)
	}
	if !foundCollapse {
		t.Fatal("expected collapse row when expanded")
	}
	for i, it := range items {
		if it.kind == "collapse" && it.group == "dns:A" {
			m.hostIdx = i
			break
		}
	}
	m.toggleHostExpand()
	if m.hostExpanded["dns:A"] {
		t.Fatal("expected collapsed again")
	}
	items = m.infraItems()
	for _, it := range items {
		if it.kind == "collapse" {
			t.Fatal("collapse row should be gone")
		}
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case r == '\x1b':
			inEsc = true
		case inEsc:
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEsc = false
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

package tui

import (
	"strings"
	"testing"

	"github.com/saptreekly/casre/internal/scanner"
)

func TestVisibleFindingsSortedBySeverityThenCategory(t *testing.T) {
	m := model{
		results: []scanner.Result{{
			Findings: []scanner.Finding{
				{Severity: "info", Category: "dns", Message: "A records"},
				{Severity: "high", Category: "url", Message: "bad url"},
				{Severity: "medium", Category: "phish", Message: "lure"},
				{Severity: "high", Category: "phish", Message: "turnstile"},
				{Severity: "low", Category: "http", Message: "gap"},
			},
		}},
		showInfo: true,
	}
	got := m.visibleFindings()
	want := []struct{ sev, cat string }{
		{"high", "phish"},
		{"high", "url"},
		{"medium", "phish"},
		{"low", "http"},
		{"info", "dns"},
	}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Severity != want[i].sev || got[i].Category != want[i].cat {
			t.Fatalf("[%d] %s/%s, want %s/%s", i, got[i].Severity, got[i].Category, want[i].sev, want[i].cat)
		}
	}
}

func TestVisibleFindingsHidesInfoByDefault(t *testing.T) {
	m := model{
		results: []scanner.Result{{
			Findings: []scanner.Finding{
				{Severity: "high", Category: "phish", Message: "a"},
				{Severity: "info", Category: "dns", Message: "b"},
			},
		}},
	}
	got := m.visibleFindings()
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatalf("got %#v", got)
	}
}

func TestFormatAlertRowSelectionIncludesMessage(t *testing.T) {
	f := scanner.Finding{Severity: "high", Category: "phish", Message: "Cloudflare Turnstile challenge"}
	got := formatAlertRow(true, f, 60)
	plain := stripANSI(got)
	if !strings.HasPrefix(strings.TrimLeft(plain, " "), "▸") && !strings.Contains(plain, "▸") {
		t.Fatalf("expected selection gutter: %q", plain)
	}
	first := strings.Split(plain, "\n")[0]
	if !strings.Contains(first, "Phishing") || !strings.Contains(first, "Cloudflare") {
		t.Fatalf("category and message should share first line: %q", first)
	}
}

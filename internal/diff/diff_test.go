package diff_test

import (
	"strings"
	"testing"
	"time"

	"github.com/saptreekly/casre/internal/diff"
	"github.com/saptreekly/casre/internal/scanner"
)

func TestCompareDetectsDNSChange(t *testing.T) {
	old := &diff.Report{
		Version: 1,
		Results: []scanner.Result{{
			Host: "example.com",
			DNS:  &scanner.DNSResult{A: []string{"1.1.1.1"}},
		}},
	}
	neu := &diff.Report{
		Version:   1,
		CreatedAt: time.Now(),
		Results: []scanner.Result{{
			Host: "example.com",
			DNS:  &scanner.DNSResult{A: []string{"8.8.8.8"}},
		}},
	}
	changes := diff.Compare(old, neu)
	if len(changes) == 0 {
		t.Fatal("expected changes")
	}
	found := false
	for _, c := range changes {
		if c.Field == "dns.a" && c.Before == "1.1.1.1" && c.After == "8.8.8.8" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing dns.a change: %+v", changes)
	}
}

func TestCompareVerdictAndFindings(t *testing.T) {
	old := &diff.Report{Results: []scanner.Result{{
		Host:      "example.com",
		InputURL:  "https://example.com/lure",
		FinalHost: "a.example",
		Verdict:   &scanner.Verdict{Score: 40, Label: "suspicious"},
		Findings:  []scanner.Finding{{Severity: "high", Category: "phish", Message: "old alert"}},
		Hops:      []scanner.HopDetail{{Host: "example.com"}, {Host: "a.example"}},
	}}}
	neu := &diff.Report{Results: []scanner.Result{{
		Host:      "example.com",
		InputURL:  "https://example.com/lure",
		FinalHost: "b.example",
		Verdict:   &scanner.Verdict{Score: 85, Label: "malicious"},
		Findings: []scanner.Finding{
			{Severity: "high", Category: "phish", Message: "old alert"},
			{Severity: "high", Category: "phish", Message: "new alert"},
		},
		Hops: []scanner.HopDetail{{Host: "example.com"}, {Host: "b.example"}},
	}}}
	changes := diff.Compare(old, neu)
	wantFields := map[string]bool{"verdict.score": false, "verdict.label": false, "final_host": false, "finding": false}
	for _, c := range changes {
		if c.Field == "verdict.score" && c.Before == "40" && c.After == "85" {
			wantFields["verdict.score"] = true
		}
		if c.Field == "verdict.label" {
			wantFields["verdict.label"] = true
		}
		if c.Field == "final_host" && c.After == "b.example" {
			wantFields["final_host"] = true
		}
		if c.Field == "finding" && c.Kind == "added" && strings.Contains(c.After, "new alert") {
			wantFields["finding"] = true
		}
	}
	for k, ok := range wantFields {
		if !ok {
			t.Fatalf("missing %s in %+v", k, changes)
		}
	}
}

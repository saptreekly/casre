package diff_test

import (
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

func TestCompareAddedHost(t *testing.T) {
	old := &diff.Report{Results: nil}
	neu := &diff.Report{Results: []scanner.Result{{Host: "new.example"}}}
	changes := diff.Compare(old, neu)
	if len(changes) != 1 || changes[0].Kind != "added" {
		t.Fatalf("expected added host, got %+v", changes)
	}
}

package scanner_test

import (
	"testing"

	"github.com/saptreekly/casre/internal/scanner"
)

func TestAnnotateMitreCloudStorage(t *testing.T) {
	findings := []scanner.Finding{{
		Severity: "high",
		Category: "phish",
		Message:  "HTML hosted on cloud object storage (storage.googleapis.com) — common phishing lure pattern",
	}}
	findings = scanner.AnnotateMitre(findings)
	if len(findings[0].Mitre) == 0 {
		t.Fatal("expected MITRE tags")
	}
	ids := map[string]bool{}
	for _, m := range findings[0].Mitre {
		ids[m.ID] = true
	}
	for _, want := range []string{"T1583.006", "T1566.002"} {
		if !ids[want] {
			t.Fatalf("missing %s in %#v", want, findings[0].Mitre)
		}
	}
}

func TestMitreRollupDedupes(t *testing.T) {
	findings := scanner.AnnotateMitre([]scanner.Finding{
		{Severity: "high", Category: "phish", Message: "brand impersonation: Cloudflare interstitial/turnstile clone"},
		{Severity: "high", Category: "phish", Message: "Cloudflare Turnstile widget on non-Cloudflare host — likely fake browser check"},
		{Severity: "medium", Category: "url", Message: "SendGrid click-tracking URL — common email campaign / phishing delivery path"},
	})
	rollup := scanner.MitreRollup(findings)
	if len(rollup) == 0 {
		t.Fatal("expected rollup")
	}
	var spear *scanner.MitreHit
	for i := range rollup {
		if rollup[i].ID == "T1566.002" {
			spear = &rollup[i]
			break
		}
	}
	if spear == nil {
		t.Fatalf("expected T1566.002 in %#v", rollup)
	}
	if spear.Count < 2 {
		t.Fatalf("expected T1566.002 count>=2, got %d", spear.Count)
	}
	if spear.Confidence != "high" {
		t.Fatalf("expected high confidence, got %s", spear.Confidence)
	}
}

func TestFormatMitreIDs(t *testing.T) {
	s := scanner.FormatMitreIDs([]scanner.MitreRef{
		{ID: "T1566.002"},
		{ID: "T1656"},
	})
	if s != "T1566.002 · T1656" {
		t.Fatalf("got %q", s)
	}
}

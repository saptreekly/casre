package scanner_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saptreekly/casre/internal/scanner"
)

func TestClassifyRoles(t *testing.T) {
	if got := scanner.ClassifyNodeRole("u1.ct.sendgrid.net", "https://u1.ct.sendgrid.net/ls/click", nil, nil); got != scanner.RoleTracker {
		t.Fatalf("sendgrid: got %s", got)
	}
	if got := scanner.ClassifyNodeRole("kx2t.app.link", "https://kx2t.app.link/x", &scanner.PageAnalysis{Deepview: "branch"}, nil); got != scanner.RoleDeepview {
		t.Fatalf("branch: got %s", got)
	}
	if got := scanner.ClassifyNodeRole("www.facebook.com", "https://www.facebook.com/x", nil, nil); got != scanner.RoleDecoy {
		t.Fatalf("facebook: got %s", got)
	}
	page := &scanner.PageAnalysis{
		Title:              "Just a moment...",
		CloudStorageHost:   true,
		ContentType:        "text/html",
		HasTurnstile:       true,
		BrandImpersonation: []string{"Cloudflare interstitial/turnstile clone"},
	}
	if got := scanner.ClassifyNodeRole("storage.googleapis.com", "https://storage.googleapis.com/x", page, nil); got != scanner.RoleCloaker {
		t.Fatalf("gcs cloaker: got %s", got)
	}
}

func TestAlbertNotLander(t *testing.T) {
	page := &scanner.PageAnalysis{Title: "Albert | Your personal financial assistant", Bytes: 7000}
	got := scanner.ClassifyNodeRoleCtx("albert.com", "https://albert.com/?_branch=1", page, nil, scanner.RoleContext{
		ParentRole: scanner.RoleDeepview,
		Via:        "js",
	})
	if got == scanner.RoleLander {
		t.Fatalf("albert.com should not be lander, got %s", got)
	}
}

func TestCleartextFromCloakerIsLander(t *testing.T) {
	page := &scanner.PageAnalysis{Title: "DeskFlow — The Ticketing System", Bytes: 4000}
	got := scanner.ClassifyNodeRoleCtx("pociv.site", "http://pociv.site/", page, nil, scanner.RoleContext{
		ParentRole: scanner.RoleCloaker,
		Via:        "js",
	})
	if got != scanner.RoleLander {
		t.Fatalf("pociv.site cleartext from cloaker should be lander, got %s", got)
	}
}

func TestTitleAloneNotLander(t *testing.T) {
	page := &scanner.PageAnalysis{Title: "Welcome", Bytes: 1000}
	got := scanner.ClassifyNodeRole("random-corp.example", "https://random-corp.example/", page, nil)
	if got == scanner.RoleLander {
		t.Fatalf("title alone should not be lander")
	}
}

func TestCampaignStopsAtDecoy(t *testing.T) {
	visit, expand := scanner.CampaignShouldEnqueueChild(scanner.RoleLander, "www.youtube.com", false)
	if !visit || expand {
		t.Fatalf("decoy should visit once without expand: visit=%v expand=%v", visit, expand)
	}
	visit, expand = scanner.CampaignShouldEnqueueChild(scanner.RoleTracker, "app.albrt.co", false)
	if !visit || !expand {
		t.Fatalf("mid-chain should expand: visit=%v expand=%v", visit, expand)
	}
}

func TestBuildVerdictNarrative(t *testing.T) {
	r := scanner.Result{
		Host: "storage.googleapis.com",
		Findings: []scanner.Finding{
			{Severity: "high", Category: "phish", Message: "HTML hosted on cloud object storage (storage.googleapis.com)"},
			{Severity: "high", Category: "phish", Message: "Cloudflare Turnstile widget on non-Cloudflare host — likely fake browser check"},
			{Severity: "high", Category: "phish", Message: "JS/meta redirect to external host: http://pociv.site/ (cleartext HTTP)"},
			{Severity: "high", Category: "phish", Message: "brand impersonation: Cloudflare interstitial/turnstile clone"},
			{Severity: "high", Category: "phish", Message: "brand impersonation: Cloudflare logo asset on foreign host"},
		},
		Graph: &scanner.AttackGraph{
			Nodes: []scanner.GraphNode{
				{Host: "storage.googleapis.com", Role: scanner.RoleCloaker, Depth: 0, Title: "Just a moment..."},
				{Host: "pociv.site", Role: scanner.RoleLander, Depth: 1, Title: "DeskFlow", URL: "http://pociv.site/"},
			},
		},
		Hops: []scanner.HopDetail{
			{Host: "pociv.site", URL: "http://pociv.site/", Role: scanner.RoleLander},
		},
	}
	v := scanner.BuildVerdict(r)
	if v.Score < 70 {
		t.Fatalf("expected malicious-range score for classic lure, got %d (%s)", v.Score, v.Label)
	}
	if v.Label == "clean" {
		t.Fatalf("expected non-clean label, got %s", v.Label)
	}
	if v.Narrative == "" {
		t.Fatal("expected narrative")
	}
}

func TestBuildVerdictESPOnlyCapped(t *testing.T) {
	r := scanner.Result{
		Host: "u1.ct.sendgrid.net",
		Findings: []scanner.Finding{
			{Severity: "medium", Category: "url", Message: "SendGrid click-tracking URL — common email campaign / phishing delivery path"},
			{Severity: "medium", Category: "url", Message: "cross-domain redirect(s): 2 hop(s) change hostname"},
			{Severity: "medium", Category: "phish", Message: "branch deepview / deferred deep-link page"},
		},
		Graph: &scanner.AttackGraph{
			Nodes: []scanner.GraphNode{
				{Host: "u1.ct.sendgrid.net", Role: scanner.RoleTracker, Depth: 0},
				{Host: "kx2t.app.link", Role: scanner.RoleDeepview, Depth: 2},
				{Host: "albert.com", Role: scanner.RoleUnknown, Depth: 3},
			},
		},
	}
	v := scanner.BuildVerdict(r)
	if v.Score > 35 {
		t.Fatalf("ESP→deepview without cloaker should be capped, got %d", v.Score)
	}
	if v.Label == "malicious" {
		t.Fatalf("should not be malicious: %s", v.Label)
	}
}

func TestExtractIOCs(t *testing.T) {
	r := scanner.Result{
		Host:      "example.com",
		InputURL:  "https://example.com/a",
		FinalHost: "evil.test",
		DNS:       &scanner.DNSResult{A: []string{"1.2.3.4"}},
		Enrich: &scanner.Enrichment{
			ASN: []scanner.ASNInfo{{IP: "1.2.3.4", ASN: "15169", ASName: "GOOGLE"}},
		},
		Graph: &scanner.AttackGraph{
			Nodes: []scanner.GraphNode{
				{Host: "evil.test", URL: "http://evil.test/", Role: scanner.RoleLander},
			},
		},
	}
	set := scanner.ExtractIOCs(r)
	if len(set.Domains) < 2 {
		t.Fatalf("domains: %#v", set.Domains)
	}
	if len(set.IPs) < 1 || len(set.ASNs) < 1 || len(set.URLs) < 1 {
		t.Fatalf("incomplete IOCs: %#v", set)
	}
}

func TestSaveEvidenceHTML(t *testing.T) {
	dir := t.TempDir()
	ev, err := scanner.SaveEvidenceHTML(dir, scanner.RoleCloaker, "https://storage.googleapis.com/x", "storage.googleapis.com", "Just a moment...", "text/html", []byte("<html>hi</html>"))
	if err != nil {
		t.Fatal(err)
	}
	if ev == nil || ev.Path == "" {
		t.Fatal("expected evidence path")
	}
	if _, err := os.Stat(ev.Path); err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(ev.Path) != dir {
		t.Fatalf("path %s not in %s", ev.Path, dir)
	}
	// Non-snapshot roles skip.
	ev2, err := scanner.SaveEvidenceHTML(dir, scanner.RoleTracker, "https://x", "x", "", "", []byte("x"))
	if err != nil || ev2 != nil {
		t.Fatalf("tracker should not snapshot: %#v %v", ev2, err)
	}
}

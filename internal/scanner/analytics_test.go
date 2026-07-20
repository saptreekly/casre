package scanner

import (
	"strings"
	"testing"
)

func TestBuildInvestigationTimelineAndTechniques(t *testing.T) {
	r := Result{
		Host:      "storage.googleapis.com",
		FinalHost: "evil.lander",
		Page: &PageAnalysis{
			CloudStorageHost:   true,
			BrandImpersonation: []string{"Cloudflare interstitial/turnstile clone"},
			Kits:               []string{"HREFB-style IP-var redirect cloaker"},
			JSRedirects:        []string{"http://evil.lander/"},
			MetaRefresh:        []string{"http://evil.lander/alt"},
			Bytes:              1200,
		},
		Graph: &AttackGraph{
			Nodes: []GraphNode{
				{ID: "n0", Host: "u1.ct.sendgrid.net", Role: RoleTracker, Depth: 0, URL: "https://u1.ct.sendgrid.net/x"},
				{ID: "n1", Host: "storage.googleapis.com", Role: RoleCloaker, Depth: 1, URL: "https://storage.googleapis.com/x", Title: "Just a moment..."},
				{ID: "n2", Host: "evil.lander", Role: RoleLander, Depth: 2, URL: "http://evil.lander/"},
			},
			Edges: []GraphEdge{
				{From: "n0", To: "n1", Via: "http"},
				{From: "n1", To: "n2", Via: "js"},
			},
		},
		Findings: []Finding{
			{Severity: "high", Category: "phish", Message: "password input field present on page"},
			{Severity: "high", Category: "phish", Message: "JS/meta redirect to external host: http://evil.lander/"},
		},
		DNS:    &DNSResult{A: []string{"1.2.3.4"}},
		Enrich: &Enrichment{ASN: []ASNInfo{{IP: "1.2.3.4", ASN: "123", ASName: "TEST-AS"}}, CDN: []string{"gcp"}},
		Verdict: &Verdict{Score: 80, Label: "malicious", Narrative: "tracker → cloaker → lander"},
	}
	inv := BuildInvestigation(r)
	if inv == nil {
		t.Fatal("nil investigation")
	}
	if !strings.Contains(inv.KillChain, "Delivery") || !strings.Contains(inv.KillChain, "Cloaker") {
		t.Fatalf("kill chain=%q", inv.KillChain)
	}
	phases := map[string]bool{}
	for _, p := range inv.Timeline {
		phases[p.Phase] = true
	}
	if !phases["delivery"] || !phases["cloaker"] || !phases["lander"] || !phases["harvest"] {
		t.Fatalf("timeline phases=%v", phases)
	}
	if inv.Techniques.HTTP < 1 || inv.Techniques.JS < 1 || inv.Techniques.Kit < 1 {
		t.Fatalf("techniques=%+v", inv.Techniques)
	}
	if len(inv.BlastRadius.Hosts) < 2 || len(inv.BlastRadius.IPs) < 1 {
		t.Fatalf("blast=%+v", inv.BlastRadius)
	}
	if len(inv.Attributions) < 2 {
		t.Fatalf("attributions=%+v", inv.Attributions)
	}
	if inv.Confidence.Level == "" || inv.Confidence.Score <= 0 {
		t.Fatalf("confidence=%+v", inv.Confidence)
	}
}

func TestBuildCoverageGapsFlagsExternalScripts(t *testing.T) {
	r := Result{
		Host: "evil.test",
		Page: &PageAnalysis{
			Bytes:           100,
			ExternalScripts: []string{"https://cdn.example/a.js", "https://cdn.example/b.js"},
		},
		Graph: &AttackGraph{Nodes: []GraphNode{
			{Host: "evil.test", Role: RoleCloaker},
		}},
	}
	gaps := buildCoverageGaps(r)
	foundScript := false
	foundFuzz := false
	for _, g := range gaps {
		if strings.Contains(g.Gap, "external script") {
			foundScript = true
		}
		if strings.Contains(g.Gap, "Path fuzzing not run") {
			foundFuzz = true
		}
	}
	if !foundScript || !foundFuzz {
		t.Fatalf("gaps=%+v", gaps)
	}
}

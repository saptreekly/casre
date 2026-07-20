package scanner

import (
	"testing"
)

func TestFuzzFindingSensitivePaths(t *testing.T) {
	h := fuzzHost{scheme: "https", host: "evil.test", role: RoleLander}

	hit := fuzzFinding(h, "/.env", HTTPResult{StatusCode: 200})
	if hit == nil || hit.Severity != "high" || hit.Category != "fuzz" {
		t.Fatalf("env hit: %+v", hit)
	}

	login := fuzzFinding(h, "/admin/login", HTTPResult{StatusCode: 200})
	if login == nil || login.Severity != "high" {
		t.Fatalf("admin login: %+v", login)
	}

	miss := fuzzFinding(h, "/nope", HTTPResult{StatusCode: 404})
	if miss != nil {
		t.Fatalf("404 should be ignored: %+v", miss)
	}

	redir := fuzzFinding(h, "/admin", HTTPResult{
		StatusCode: 302,
		FinalURL:   "https://evil.test/admin/login",
	})
	if redir == nil || redir.Severity != "medium" {
		t.Fatalf("redirect hit: %+v", redir)
	}

	auth := fuzzFinding(h, "/panel", HTTPResult{StatusCode: 401})
	if auth == nil || auth.Severity != "medium" {
		t.Fatalf("401 hit: %+v", auth)
	}
}

func TestCollectFuzzHostsSkipsDecoysAndCloudStorage(t *testing.T) {
	res := Result{
		Graph: &AttackGraph{
			Nodes: []GraphNode{
				{Host: "storage.googleapis.com", Role: RoleCloaker, URL: "https://storage.googleapis.com/x"},
				{Host: "www.youtube.com", Role: RoleDecoy, URL: "https://www.youtube.com/"},
				{Host: "phish-lander.evil", Role: RoleLander, URL: "http://phish-lander.evil/"},
				{Host: "185.1.2.3", Role: RoleCloaker, URL: "http://185.1.2.3/gate"},
			},
		},
	}
	hosts := collectFuzzHosts(res)
	seen := map[string]bool{}
	for _, h := range hosts {
		seen[h.host] = true
	}
	if !seen["phish-lander.evil"] || !seen["185.1.2.3"] {
		t.Fatalf("expected lander+IP, got %+v", hosts)
	}
	if seen["www.youtube.com"] {
		t.Fatal("decoy should be skipped")
	}
	if seen["storage.googleapis.com"] {
		t.Fatal("cloud storage should be skipped (no kit admin paths)")
	}
}

func TestLooksLikeSoft404(t *testing.T) {
	base := soft404Baseline{status: 200, size: 1200}
	if !looksLikeSoft404(base, HTTPResult{StatusCode: 200, Body: make([]byte, 1180)}) {
		t.Fatal("similar 200 body should be soft-404")
	}
	if looksLikeSoft404(base, HTTPResult{StatusCode: 200, Body: make([]byte, 40)}) {
		t.Fatal("very different size should not be soft-404")
	}
	if !looksLikeSoft404(base, HTTPResult{StatusCode: 404}) {
		t.Fatal("hard 404")
	}
}

func TestPathKeyNormalizes(t *testing.T) {
	a := pathKey("Evil.TEST", "/Admin/")
	b := pathKey("evil.test", "/admin")
	if a != b {
		t.Fatalf("%q vs %q", a, b)
	}
}

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

func TestCollectFuzzHostsSkipsDecoys(t *testing.T) {
	res := Result{
		Graph: &AttackGraph{
			Nodes: []GraphNode{
				{Host: "storage.googleapis.com", Role: RoleCloaker, URL: "https://storage.googleapis.com/x"},
				{Host: "www.youtube.com", Role: RoleDecoy, URL: "https://www.youtube.com/"},
				{Host: "phish-lander.evil", Role: RoleLander, URL: "http://phish-lander.evil/"},
			},
		},
	}
	hosts := collectFuzzHosts(res)
	seen := map[string]bool{}
	for _, h := range hosts {
		seen[h.host] = true
	}
	if !seen["storage.googleapis.com"] || !seen["phish-lander.evil"] {
		t.Fatalf("expected cloaker+lander, got %+v", hosts)
	}
	if seen["www.youtube.com"] {
		t.Fatal("decoy should be skipped")
	}
}

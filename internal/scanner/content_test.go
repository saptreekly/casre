package scanner_test

import (
	"strings"
	"testing"

	"github.com/saptreekly/casre/internal/scanner"
)

const spoofHTML = `<!DOCTYPE html>
<html><head><title>Just a moment...</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
</head><body>
<img src="https://1000logos.net/wp-content/uploads/2020/09/Cloudflare-logo.png">
<h1>Checking your browser...</h1>
<div class="cf-turnstile" data-sitekey="x"></div>
<script>
function executeRedirect(token) {
  const currentHash = window.location.hash;
  window.location.href = "http://pociv.site/" + currentHash;
}
</script>
</body></html>`

func TestAnalyzePageCloudflareSpoof(t *testing.T) {
	page := scanner.AnalyzePage([]byte(spoofHTML), "text/html", "https://storage.googleapis.com/devilex/devilex1.html")
	if page == nil {
		t.Fatal("nil page")
	}
	if page.Title != "Just a moment..." {
		t.Fatalf("title=%q", page.Title)
	}
	if !page.HasTurnstile {
		t.Fatal("expected turnstile")
	}
	if !page.CloudStorageHost {
		t.Fatal("expected cloud storage host")
	}
	found := false
	for _, d := range page.Destinations {
		if strings.Contains(d, "pociv.site") {
			found = true
		}
	}
	if !found {
		t.Fatalf("destinations=%v", page.Destinations)
	}
	findings := scanner.PageFindings("https://storage.googleapis.com/devilex/devilex1.html", page)
	if len(findings) < 3 {
		t.Fatalf("expected multiple phish findings, got %d: %+v", len(findings), findings)
	}
}

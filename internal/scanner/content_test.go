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

const hrefbHTML = `<script>
var tarcking_param = window.location.href.split('#')[1];
var srv_ip = "49.13.68.203";
if(!tarcking_param){
alert("please set tracking params!");
}else{
document.location.href = 'http://'+srv_ip+'/?'+tarcking_param;
}
</script>`

func TestAnalyzePageCloudflareSpoof(t *testing.T) {
	page := scanner.AnalyzePage([]byte(spoofHTML), "text/html", "https://storage.googleapis.com/devilex/devilex1.html", "")
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

func TestAnalyzePageHREFBIPVarRedirect(t *testing.T) {
	frag := "?Z289MSZzMT0yMzEzNTA2JnMyPTgxMDU0NjE5NiZzMz1HTEI="
	page := scanner.AnalyzePage(
		[]byte(hrefbHTML),
		"text/html",
		"https://storage.googleapis.com/264you/HREFB.html",
		frag,
	)
	if page == nil {
		t.Fatal("nil page")
	}
	wantHost := "49.13.68.203"
	found := false
	for _, j := range page.JSRedirects {
		if strings.Contains(j, "http://") && !strings.Contains(j, wantHost) {
			t.Fatalf("incomplete/non-reconstructed js redirect: %q", j)
		}
		if strings.Contains(j, wantHost) {
			found = true
			if !strings.Contains(j, "Z289MSZzMT0yMzEzNTA2JnMyPTgxMDU0NjE5NiZzMz1HTEI=") {
				t.Fatalf("expected tracking fragment in redirect, got %q", j)
			}
			if strings.HasPrefix(j, "http://") && (j == "http://" || j == "http:") {
				t.Fatalf("bare protocol redirect: %q", j)
			}
		}
	}
	if !found {
		t.Fatalf("expected JS redirect to %s, got %v", wantHost, page.JSRedirects)
	}
	destOK := false
	for _, d := range page.Destinations {
		if strings.Contains(d, wantHost) {
			destOK = true
		}
	}
	if !destOK {
		t.Fatalf("expected destination %s, got %v", wantHost, page.Destinations)
	}
}

func TestAnalyzePageHREFBWithoutFragmentStillResolvesHost(t *testing.T) {
	page := scanner.AnalyzePage(
		[]byte(hrefbHTML),
		"text/html",
		"https://storage.googleapis.com/264you/HREFB.html",
		"",
	)
	if page == nil {
		t.Fatal("nil page")
	}
	found := false
	for _, j := range page.JSRedirects {
		if j == "http://" || j == "http:" || j == "https://" {
			t.Fatalf("incomplete redirect leaked: %q", j)
		}
		if strings.Contains(j, "49.13.68.203") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected host reconstruction without fragment, got %v", page.JSRedirects)
	}
}

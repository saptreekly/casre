package scanner_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/saptreekly/casre/internal/scanner"
)

func TestAnalyzePageMetaRefreshAndAssign(t *testing.T) {
	html := `<html><head>
<meta http-equiv="refresh" content="0;url=https://evil.example/lander">
</head><body><script>
location.assign("https://evil.example/from-assign");
</script></body></html>`
	page := scanner.AnalyzePage([]byte(html), "text/html", "https://storage.googleapis.com/x/y.html", "")
	if page == nil {
		t.Fatal("nil page")
	}
	if len(page.MetaRefresh) == 0 || !strings.Contains(page.MetaRefresh[0], "evil.example/lander") {
		t.Fatalf("meta refresh=%v", page.MetaRefresh)
	}
	found := false
	for _, j := range page.JSRedirects {
		if strings.Contains(j, "from-assign") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected location.assign redirect, got %v", page.JSRedirects)
	}
}

func TestAnalyzePageObfuscatedConcat(t *testing.T) {
	html := `<script>
document.location.href = 'ht'+'tp://'+'49.13.68.203'+'/phish';
</script>`
	page := scanner.AnalyzePage([]byte(html), "text/html", "https://cdn.example/cloak.html", "")
	if page == nil {
		t.Fatal("nil page")
	}
	found := false
	for _, j := range page.JSRedirects {
		if strings.Contains(j, "49.13.68.203") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected deobfuscated redirect, got %v", page.JSRedirects)
	}
}

func TestAnalyzePageAtobRedirect(t *testing.T) {
	target := "https://phish.example/login"
	b64 := base64.StdEncoding.EncodeToString([]byte(target))
	html := `<script>window.location.href = atob("` + b64 + `");</script>`
	page := scanner.AnalyzePage([]byte(html), "text/html", "https://bucket.example/a.html", "")
	if page == nil {
		t.Fatal("nil page")
	}
	found := false
	for _, j := range page.JSRedirects {
		if j == target {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected atob redirect to %s, got %v", target, page.JSRedirects)
	}
	kit := false
	for _, k := range page.Kits {
		if strings.Contains(k, "atob") {
			kit = true
		}
	}
	if !kit {
		t.Fatalf("expected atob kit fingerprint, got %v", page.Kits)
	}
}

func TestAnalyzePageDocuSignAndShippingLures(t *testing.T) {
	html := `<html><title>Please review and sign</title><body>
Please review and sign this DocuSign envelope.
<img src="https://cdn.evil/docusign-logo.png">
</body></html>`
	page := scanner.AnalyzePage([]byte(html), "text/html", "https://not-docusign.evil/doc.html", "")
	if page == nil {
		t.Fatal("nil")
	}
	found := false
	for _, b := range page.BrandImpersonation {
		if strings.Contains(b, "DocuSign") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected DocuSign lure, got %v", page.BrandImpersonation)
	}

	ship := `<html><body>Failed delivery notice — track your package via FedEx customs fee portal</body></html>`
	page2 := scanner.AnalyzePage([]byte(ship), "text/html", "https://parcel-notice.evil/", "")
	foundShip := false
	for _, b := range page2.BrandImpersonation {
		if strings.Contains(b, "Shipping") {
			foundShip = true
		}
	}
	if !foundShip {
		t.Fatalf("expected shipping lure, got %v", page2.BrandImpersonation)
	}
}

func TestHREFBKitFingerprint(t *testing.T) {
	page := scanner.AnalyzePage([]byte(hrefbHTML), "text/html", "https://storage.googleapis.com/x/HREFB.html", "?x=1")
	if page == nil {
		t.Fatal("nil")
	}
	found := false
	for _, k := range page.Kits {
		if strings.Contains(k, "HREFB") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HREFB kit, got %v", page.Kits)
	}
}

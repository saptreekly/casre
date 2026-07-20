package scanner

import (
	"regexp"
	"strings"
)

var (
	reFormBlock       = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	reHiddenInput     = regexp.MustCompile(`(?is)<input\b[^>]*\btype\s*=\s*["']hidden["']`)
	rePasswordInput   = regexp.MustCompile(`(?is)<input\b[^>]*\btype\s*=\s*["']password["']`)
	reAutocompleteOff = regexp.MustCompile(`(?i)autocomplete\s*=\s*["']off["']`)
	reEmailInput      = regexp.MustCompile(`(?is)<input\b[^>]*(?:\btype\s*=\s*["'](?:email|text)["'][^>]*\bname\s*=\s*["'][^"']*(?:user|email|login|account)|\bname\s*=\s*["'][^"']*(?:user|email|login|account)[^"']*["'][^>]*\btype\s*=\s*["'](?:email|text)["'])`)

	reFromCharCode = regexp.MustCompile(`(?i)String\.fromCharCode\s*\(`)
	reEvalCall     = regexp.MustCompile(`(?i)\beval\s*\(`)
	reFunctionCtor = regexp.MustCompile(`(?i)\bFunction\s*\(`)
	reHexEscape    = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	reUnicodeEsc   = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	rePackedLoader = regexp.MustCompile(`(?i)eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)|` +
		`function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)`)
	reAtobCall      = regexp.MustCompile(`(?i)\batob\s*\(`)
	reDocumentWrite = regexp.MustCompile(`(?i)document\.write\s*\(`)

	reHiddenPassBlock = regexp.MustCompile(`(?is)<(?:div|form|section|span)[^>]*(?:style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^"']*["']|hidden\s*=\s*["']?true)[^>]*>[^<]*(?:<[^>]+>)*[^<]*<input[^>]+type\s*=\s*["']password["']`)
	reTurnstileHidden = regexp.MustCompile(`(?is)(?:display\s*:\s*none|visibility\s*:\s*hidden)[^<]{0,200}cf-turnstile|cf-turnstile[^>]*(?:style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)|hidden)`)
	reFullPageIFrame  = regexp.MustCompile(`(?is)<iframe\b[^>]*(?:` +
		`style\s*=\s*["'][^"']*(?:position\s*:\s*(?:fixed|absolute)[^"']*(?:inset\s*:\s*0|top\s*:\s*0[^"']*left\s*:\s*0)|width\s*:\s*100(?:%|vw)|height\s*:\s*100(?:%|vh))[^"']*["']|` +
		`(?:width\s*=\s*["']?(?:100%|100vw)["']?[^>]*height\s*=\s*["']?(?:100%|100vh)|height\s*=\s*["']?(?:100%|100vh)["']?[^>]*width\s*=\s*["']?(?:100%|100vw))` +
		`)`)
	reInvisibleCaptcha = regexp.MustCompile(`(?is)g-recaptcha|hcaptcha|cf-turnstile`)
)

// applyHTMLSignals fills forms, obfuscation, and hidden-UI fields on an analyzed page.
func applyHTMLSignals(p *PageAnalysis, text, pageURL string) {
	if p == nil {
		return
	}
	baseHost := HostFromURL(pageURL)
	p.Forms = parseForms(text, pageURL, baseHost)
	for _, f := range p.Forms {
		if f.HasPassword {
			p.HasPasswordField = true
			break
		}
	}
	if !p.HasPasswordField {
		p.HasPasswordField = rePassword.MatchString(text)
	}
	p.Obfuscation = detectObfuscation(text)
	p.HiddenUI = detectHiddenUI(text, p)
}

// parseForms extracts forms with exfil-oriented detail (cross-origin action, hidden fields, autofill).
func parseForms(text, pageURL, baseHost string) []PageForm {
	var out []PageForm
	blocks := reFormBlock.FindAllStringSubmatch(text, 10)
	if len(blocks) == 0 {
		// Fallback: opening tags only (unclosed / truncated bodies).
		for _, m := range reForm.FindAllStringSubmatch(text, 10) {
			attrs := ""
			if len(m) > 1 {
				attrs = m[1]
			}
			out = append(out, formFromAttrs(attrs, "", pageURL, baseHost))
		}
		return out
	}
	for _, m := range blocks {
		attrs, body := "", ""
		if len(m) > 1 {
			attrs = m[1]
		}
		if len(m) > 2 {
			body = m[2]
		}
		out = append(out, formFromAttrs(attrs, body, pageURL, baseHost))
	}
	return out
}

func formFromAttrs(attrs, body, pageURL, baseHost string) PageForm {
	f := PageForm{Method: "get"}
	if am := reAction.FindStringSubmatch(attrs); len(am) > 1 {
		f.Action = absolutize(pageURL, am[1])
	}
	if mm := reMethod.FindStringSubmatch(attrs); len(mm) > 1 {
		f.Method = strings.ToLower(mm[1])
	}
	f.ActionHost = HostFromURL(f.Action)
	if f.ActionHost != "" && baseHost != "" && !HostEqual(f.ActionHost, baseHost) {
		f.CrossOrigin = true
	}
	scope := attrs + " " + body
	f.HiddenFields = len(reHiddenInput.FindAllStringIndex(scope, -1))
	f.HasPassword = rePasswordInput.MatchString(scope)
	f.AutofillOff = reAutocompleteOff.MatchString(scope)
	return f
}

// detectObfuscation returns cheap regex signals — for confidence/alerts, not hop discovery.
func detectObfuscation(text string) []string {
	if text == "" {
		return nil
	}
	var out []string
	add := func(s string) {
		out = appendUnique(out, s)
	}

	fromChar := len(reFromCharCode.FindAllStringIndex(text, 20))
	evalN := len(reEvalCall.FindAllStringIndex(text, 20))
	fnN := len(reFunctionCtor.FindAllStringIndex(text, 20))
	hexN := len(reHexEscape.FindAllStringIndex(text, 80))
	uniN := len(reUnicodeEsc.FindAllStringIndex(text, 80))
	atobN := len(reAtobCall.FindAllStringIndex(text, 20))

	if rePackedLoader.MatchString(text) {
		add("packed/eval packer loader")
	}
	if fromChar >= 2 || (fromChar >= 1 && (hexN >= 8 || evalN >= 1)) {
		add("String.fromCharCode obfuscation")
	}
	if evalN >= 1 && (fnN >= 1 || fromChar >= 1 || hexN >= 10) {
		add("eval() with encoded payload")
	} else if evalN >= 2 {
		add("multiple eval() calls")
	}
	if fnN >= 2 {
		add("Function() constructor obfuscation")
	}
	if hexN >= 24 || (hexN >= 12 && uniN >= 8) {
		add("high hex/unicode escape density")
	}
	if atobN >= 2 || (atobN >= 1 && (hexN >= 8 || fromChar >= 1)) {
		add("atob() decoding chain")
	}
	if reDocumentWrite.MatchString(text) && (evalN+fromChar+atobN) >= 1 {
		add("document.write of decoded script")
	}
	return out
}

// detectHiddenUI finds invisible overlays, captchas, and login forms.
func detectHiddenUI(text string, p *PageAnalysis) []string {
	if text == "" {
		return nil
	}
	var out []string
	add := func(s string) {
		out = appendUnique(out, s)
	}

	if reFullPageIFrame.MatchString(text) {
		add("full-page iframe overlay")
	}
	if reTurnstileHidden.MatchString(text) {
		add("hidden Turnstile/captcha container")
	}
	if reHiddenPassBlock.MatchString(text) {
		add("hidden password field")
	}
	// Invisible captcha widgets near harvest UI.
	if reInvisibleCaptcha.MatchString(text) && (rePassword.MatchString(text) || reEmailInput.MatchString(text)) {
		lower := strings.ToLower(text)
		if strings.Contains(lower, "display:none") || strings.Contains(lower, "visibility:hidden") ||
			strings.Contains(lower, "opacity:0") {
			add("captcha alongside hidden harvest UI")
		}
	}
	if p != nil && p.HasPasswordField {
		lower := strings.ToLower(text)
		hiddenStyle := strings.Contains(lower, "visibility:hidden") || strings.Contains(lower, "opacity:0") ||
			strings.Contains(lower, "display:none")
		hasPassAttr := strings.Contains(lower, `type="password"`) || strings.Contains(lower, `type='password'`)
		if hiddenStyle && hasPassAttr && !containsStr(out, "hidden password field") {
			add("visibility-hidden login UI")
		}
	}
	return out
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

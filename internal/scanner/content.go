package scanner

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// PageForm is a HTML form found in a response body.
type PageForm struct {
	Action       string `json:"action,omitempty"`
	Method       string `json:"method,omitempty"`
	ActionHost   string `json:"action_host,omitempty"`
	CrossOrigin  bool   `json:"cross_origin,omitempty"` // action host ≠ page host
	HiddenFields int    `json:"hidden_fields,omitempty"`
	HasPassword  bool   `json:"has_password,omitempty"`
	AutofillOff  bool   `json:"autofill_off,omitempty"` // autocomplete=off (anti-autofill / harvest)
}

// PageAnalysis holds phishing-oriented extraction from an HTML body.
type PageAnalysis struct {
	Title              string     `json:"title,omitempty"`
	OGTitle            string     `json:"og_title,omitempty"`
	ContentType        string     `json:"content_type,omitempty"`
	Bytes              int        `json:"bytes,omitempty"`
	MetaRefresh        []string   `json:"meta_refresh,omitempty"`
	JSRedirects        []string   `json:"js_redirects,omitempty"`
	EmbeddedURLs       []string   `json:"embedded_urls,omitempty"`
	AnchorLinks        []string   `json:"anchor_links,omitempty"`
	ExternalScripts    []string   `json:"external_scripts,omitempty"`
	ExternalImages     []string   `json:"external_images,omitempty"`
	IFrames            []string   `json:"iframes,omitempty"`
	Downloads          []string   `json:"downloads,omitempty"`
	AppLinks           []string   `json:"app_links,omitempty"` // intent://, market://, custom schemes
	Forms              []PageForm `json:"forms,omitempty"`
	HasPasswordField   bool       `json:"has_password_field,omitempty"`
	HasTurnstile       bool       `json:"has_turnstile,omitempty"`
	CloudStorageHost   bool       `json:"cloud_storage_host,omitempty"`
	Deepview           string     `json:"deepview,omitempty"` // branch, appsflyer, etc.
	BrandImpersonation []string   `json:"brand_impersonation,omitempty"`
	Kits               []string   `json:"kits,omitempty"`         // named cloaker / phishing-kit fingerprints
	Destinations       []string   `json:"destinations,omitempty"` // resolved external next-hops
	Obfuscation        []string   `json:"obfuscation,omitempty"`  // JS obfuscation signals (confidence, not hops)
	HiddenUI           []string   `json:"hidden_ui,omitempty"`    // invisible overlays / captcha / login
	ScriptsSkimmed     []string   `json:"scripts_skimmed,omitempty"`
	ScriptsSkipped     int        `json:"scripts_skipped,omitempty"` // external scripts not fetched
}

var (
	reTitle          = regexp.MustCompile(`(?is)<title[^>]*>\s*([^<]*?)\s*</title>`)
	reOGTitle        = regexp.MustCompile(`(?is)<meta[^>]+property\s*=\s*["']og:title["'][^>]+content\s*=\s*["']([^"']+)["']`)
	reOGTitle2       = regexp.MustCompile(`(?is)<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]+property\s*=\s*["']og:title["']`)
	reMetaRefresh    = regexp.MustCompile(`(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']([^"']+)["']`)
	reMetaRefreshURL = regexp.MustCompile(`(?i)url\s*=\s*([^\s;]+)`)
	reScriptSrc      = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	reImgSrc         = regexp.MustCompile(`(?is)<img[^>]+src\s*=\s*["']([^"']+)["']`)
	reIFrameSrc      = regexp.MustCompile(`(?is)<iframe[^>]+src\s*=\s*["']([^"']+)["']`)
	reAnchorHref     = regexp.MustCompile(`(?is)<a\b[^>]+href\s*=\s*["']([^"']+)["']`)
	reForm           = regexp.MustCompile(`(?is)<form\b([^>]*)>`)
	reAction         = regexp.MustCompile(`(?i)\baction\s*=\s*["']([^"']*)["']`)
	reMethod         = regexp.MustCompile(`(?i)\bmethod\s*=\s*["']([^"']*)["']`)
	rePassword       = regexp.MustCompile(`(?is)<input[^>]+type\s*=\s*["']password["']`)
	reTurnstile      = regexp.MustCompile(`(?is)cf-turnstile|challenges\.cloudflare\.com/turnstile`)
	reJSLoc          = regexp.MustCompile(`(?is)(?:window\.)?(?:document\.)?(?:top\.)?(?:self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']`)
	reJSReplace      = regexp.MustCompile(`(?is)(?:window\.)?(?:document\.)?(?:top\.)?(?:self\.)?location\.replace\(\s*["']([^"']+)["']`)
	reJSAssignHref   = regexp.MustCompile(`(?is)(?:window\.)?(?:document\.)?(?:top\.)?(?:self\.)?location\.href\s*=\s*["'](https?://[^"']+)["']\s*\+`)
	reAbsURLInJS     = regexp.MustCompile(`(?is)["'](https?://[^"'\s]+)["']\s*\+\s*(?:window\.)?location\.hash`)
	reValidateProto  = regexp.MustCompile(`(?is)validateProtocol\(\s*["']([^"']+)["']\s*\)`)
	reQuotedHTTP     = regexp.MustCompile(`(?is)["'](https?://[^"'\s]+)["']`)
	// 'http://'+srv_ip+'/?'+tracking_param  (and similar protocol+hostVar[+pathLit[+trackVar]])
	reJSProtoHostVar  = regexp.MustCompile(`(?is)(?:window\.)?(?:document\.)?(?:top\.)?(?:self\.)?location(?:\.href)?\s*=\s*["'](https?://)["']\s*\+\s*([A-Za-z_$][\w$]*)\s*(?:\+\s*["']([^"']*)["'])?(?:\+\s*([A-Za-z_$][\w$]*))?`)
	reJSStringAssign  = regexp.MustCompile(`(?is)(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=\s*["']([^"']+)["']`)
	reJSHashSplit     = regexp.MustCompile(`(?is)(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:window\.)?location\.href\.split\(\s*['"]#['"]\s*\)\s*\[\s*1\s*]`)
	reJSHashDirect    = regexp.MustCompile(`(?is)(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:window\.)?location\.hash`)
	reCheckingBrowser = regexp.MustCompile(`(?i)checking your browser|just a moment|review your connection security|verification complete|ddos protection by`)
	reDownloadExt     = regexp.MustCompile(`(?i)\.(?:apk|ipa|exe|dmg|pkg|msi|zip|rar|7z|vbs|scr|pdf)(?:\?|#|$)`)
)

// AnalyzePage extracts phishing-relevant signals from an HTML (or HTML-ish) body.
// fragment is the client-only #... part of the page URL (used to reconstruct tracking redirects).
func AnalyzePage(body []byte, contentType, pageURL, fragment string) *PageAnalysis {
	if len(body) == 0 {
		return nil
	}
	ct := strings.ToLower(contentType)
	text := string(body)
	looksHTML := strings.Contains(ct, "html") ||
		strings.Contains(strings.ToLower(text[:min(200, len(text))]), "<html") ||
		strings.Contains(strings.ToLower(text[:min(200, len(text))]), "<!doctype")
	if !looksHTML && !strings.Contains(ct, "text/") {
		return &PageAnalysis{ContentType: contentType, Bytes: len(body)}
	}

	baseHost := HostFromURL(pageURL)
	p := &PageAnalysis{
		ContentType:      contentType,
		Bytes:            len(body),
		CloudStorageHost: isCloudStorageHost(baseHost),
	}

	if m := reTitle.FindStringSubmatch(text); len(m) > 1 {
		p.Title = collapseWS(m[1])
	}
	if m := reOGTitle.FindStringSubmatch(text); len(m) > 1 {
		p.OGTitle = collapseWS(m[1])
	} else if m := reOGTitle2.FindStringSubmatch(text); len(m) > 1 {
		p.OGTitle = collapseWS(m[1])
	}
	p.Deepview = detectDeepview(pageURL, text)

	for _, m := range reMetaRefresh.FindAllStringSubmatch(text, -1) {
		if len(m) < 2 {
			continue
		}
		target := m[1]
		if um := reMetaRefreshURL.FindStringSubmatch(m[1]); len(um) > 1 {
			target = strings.Trim(um[1], `"'`)
		}
		if abs := absolutize(pageURL, target); abs != "" {
			p.MetaRefresh = appendUnique(p.MetaRefresh, abs)
		}
	}

	for _, u := range reconstructJSVarRedirects(text, fragment) {
		if isNavigableHTTPURL(u) {
			p.JSRedirects = appendUnique(p.JSRedirects, u)
		}
	}

	collapsed := collapseJSStringConcats(text)
	for _, src := range []string{text, collapsed} {
		for _, re := range []*regexp.Regexp{reJSLoc, reJSReplace, reJSAssignHref, reAbsURLInJS, reValidateProto} {
			for _, m := range re.FindAllStringSubmatch(src, -1) {
				if len(m) < 2 {
					continue
				}
				if abs := absolutize(pageURL, m[1]); abs != "" && isNavigableHTTPURL(abs) {
					p.JSRedirects = appendUnique(p.JSRedirects, abs)
				}
			}
		}
	}
	for _, u := range extractAssignRedirects(text, pageURL) {
		p.JSRedirects = appendUnique(p.JSRedirects, u)
	}
	for _, u := range extractAtobRedirects(text, pageURL) {
		p.JSRedirects = appendUnique(p.JSRedirects, u)
	}
	// Only keep collapsed-literal URLs that look like redirect targets (not every CDN asset).
	if collapsed != text {
		for _, u := range extractCollapsedLiteralRedirects(collapsed, pageURL) {
			if isLikelyDestination(u, baseHost) || IsIPHost(HostFromURL(u)) {
				p.JSRedirects = appendUnique(p.JSRedirects, u)
			}
		}
		// Also re-run IP-var reconstruction on collapsed text.
		for _, u := range reconstructJSVarRedirects(collapsed, fragment) {
			if isNavigableHTTPURL(u) {
				p.JSRedirects = appendUnique(p.JSRedirects, u)
			}
		}
	}

	// Branch/deepview pages often embed destination URLs as string literals.
	for _, m := range reQuotedHTTP.FindAllStringSubmatch(text, 50) {
		if len(m) < 2 {
			continue
		}
		abs := absolutize(pageURL, m[1])
		if abs == "" || !isLikelyDestination(abs, baseHost) {
			continue
		}
		already := false
		for _, j := range p.JSRedirects {
			if sameWire(j, abs) {
				already = true
				break
			}
		}
		if !already {
			p.EmbeddedURLs = appendUnique(p.EmbeddedURLs, abs)
		}
	}

	for _, m := range reScriptSrc.FindAllStringSubmatch(text, 20) {
		if abs := absolutize(pageURL, m[1]); abs != "" {
			h := HostFromURL(abs)
			if h != "" && !HostEqual(h, baseHost) {
				p.ExternalScripts = appendUnique(p.ExternalScripts, abs)
			}
		}
	}
	for _, m := range reImgSrc.FindAllStringSubmatch(text, 20) {
		if abs := absolutize(pageURL, m[1]); abs != "" {
			h := HostFromURL(abs)
			if h != "" && !HostEqual(h, baseHost) {
				p.ExternalImages = appendUnique(p.ExternalImages, abs)
			}
		}
	}
	for _, m := range reIFrameSrc.FindAllStringSubmatch(text, 10) {
		if abs := absolutize(pageURL, m[1]); abs != "" {
			p.IFrames = appendUnique(p.IFrames, abs)
		}
	}

	for _, m := range reAnchorHref.FindAllStringSubmatch(text, 50) {
		if len(m) < 2 {
			continue
		}
		raw := strings.TrimSpace(m[1])
		lower := strings.ToLower(raw)
		switch {
		case strings.HasPrefix(lower, "intent:") || strings.HasPrefix(lower, "market:") ||
			strings.HasPrefix(lower, "itms-apps:") || strings.HasPrefix(lower, "itms-appss:") ||
			(strings.Contains(raw, "://") && !strings.HasPrefix(lower, "http") &&
				!strings.HasPrefix(lower, "javascript:") && !strings.HasPrefix(lower, "data:") &&
				!strings.HasPrefix(lower, "mailto:") && !strings.HasPrefix(lower, "tel:")):
			p.AppLinks = appendUnique(p.AppLinks, raw)
		case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(raw, "/"):
			abs := absolutize(pageURL, raw)
			if abs == "" {
				continue
			}
			p.AnchorLinks = appendUnique(p.AnchorLinks, abs)
			if reDownloadExt.MatchString(abs) {
				p.Downloads = appendUnique(p.Downloads, abs)
			}
		}
	}

	p.HasTurnstile = reTurnstile.MatchString(text)
	applyHTMLSignals(p, text, pageURL)

	p.BrandImpersonation = detectBrandImpersonation(text, baseHost, p)
	p.Kits = detectKits(text, p)

	// Destinations = navigable external next hops (explicit redirects + deepview embeds).
	cands := append([]string{}, p.MetaRefresh...)
	cands = append(cands, p.JSRedirects...)
	if p.Deepview != "" {
		cands = append(cands, p.EmbeddedURLs...)
	}
	cands = append(cands, p.Downloads...)
	for _, d := range cands {
		h := HostFromURL(d)
		if h != "" && !HostEqual(h, baseHost) && isHTTPURL(d) && !isNoiseDestination(d) {
			p.Destinations = appendUnique(p.Destinations, d)
		}
	}
	sort.Strings(p.Destinations)
	return p
}

func detectDeepview(pageURL, text string) string {
	h := strings.ToLower(HostFromURL(pageURL))
	// Host-based only — do not treat marketing sites that merely include Branch
	// query params / pixels as deepview wrappers (that causes crawl explosion).
	switch {
	case strings.Contains(h, "app.link") || strings.Contains(h, "bnc.lt") ||
		strings.HasSuffix(h, ".app.link"):
		return "branch"
	case strings.Contains(h, "onelink.me") || strings.Contains(h, "appsflyer.com"):
		return "appsflyer"
	case strings.Contains(h, "adjust.com") || strings.Contains(h, "adj.st"):
		return "adjust"
	case strings.Contains(h, "page.link"):
		return "firebase"
	default:
		return ""
	}
}

// isLikelyDestination filters noisy CDN/asset URLs when mining JS string literals.
func isLikelyDestination(abs, baseHost string) bool {
	h := HostFromURL(abs)
	if h == "" || HostEqual(h, baseHost) || isNoiseDestination(abs) {
		return false
	}
	path := ""
	if u, err := url.Parse(abs); err == nil {
		path = strings.ToLower(u.Path)
	}
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".map"} {
		if strings.HasSuffix(path, ext) || strings.Contains(path, ext+"?") {
			return false
		}
	}
	return true
}

func isNoiseDestination(abs string) bool {
	h := strings.ToLower(HostFromURL(abs))
	path := ""
	if u, err := url.Parse(abs); err == nil {
		path = strings.ToLower(u.Path)
		// Sentry DSNs and similar userinfo URLs are telemetry, not nav targets.
		if u.User != nil {
			return true
		}
	}
	// XML/SVG/RDF namespace URIs are not navigable phishing hops.
	if strings.Contains(path, "/2000/svg") || strings.Contains(path, "/1999/xhtml") ||
		strings.Contains(path, "/1999/xlink") || strings.HasPrefix(path, "/ns/") {
		return true
	}
	if strings.Contains(abs, `%5C`) || strings.Contains(abs, `\`) {
		return true
	}
	noiseHosts := []string{
		"w3.org", "schema.org", "googleapis.com", "gstatic.com", "cloudflare.com",
		"jquery.com", "bootstrapcdn.com", "jsdelivr.net", "unpkg.com",
		"cdnjs.cloudflare.com", "googletagmanager.com", "google-analytics.com",
		"doubleclick.net", "facebook.net", "fbcdn.net", "branch.io",
		"example.com", "localhost", "1000logos.net", "sentry.io",
		"facebook.com", "instagram.com", "twitter.com", "x.com", "youtube.com",
		"linkedin.com", "tiktok.com",
	}
	for _, n := range noiseHosts {
		if h == n || strings.HasSuffix(h, "."+n) {
			return true
		}
	}
	return false
}

func isHTTPURL(u string) bool {
	l := strings.ToLower(u)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// isNavigableHTTPURL rejects incomplete captures like "http://" or "http:".
func isNavigableHTTPURL(u string) bool {
	if !isHTTPURL(u) {
		return false
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" {
		return false
	}
	return true
}

// reconstructJSVarRedirects resolves 'http://'+srv_ip+'/?'+tracking patterns.
func reconstructJSVarRedirects(text, fragment string) []string {
	vars := extractJSStringVars(text)
	hashVars := extractJSHashDerivedVars(text)
	var out []string
	for _, m := range reJSProtoHostVar.FindAllStringSubmatch(text, -1) {
		if len(m) < 3 {
			continue
		}
		proto, hostVar := m[1], m[2]
		pathLit, trackVar := "", ""
		if len(m) > 3 {
			pathLit = m[3]
		}
		if len(m) > 4 {
			trackVar = m[4]
		}
		hostVal := strings.TrimSpace(vars[hostVar])
		if hostVal == "" || !looksLikeHostOrIP(hostVal) {
			continue
		}
		dest := proto + hostVal
		if pathLit != "" {
			dest += pathLit
		} else {
			dest += "/"
		}
		if trackVar != "" && fragment != "" && (hashVars[trackVar] || looksLikeTrackingVar(trackVar)) {
			dest = appendTrackingQuery(dest, fragment)
		} else {
			dest = strings.TrimSuffix(dest, "?")
		}
		if isNavigableHTTPURL(dest) {
			out = appendUnique(out, dest)
		}
	}
	return out
}

func extractJSStringVars(text string) map[string]string {
	out := make(map[string]string)
	for _, m := range reJSStringAssign.FindAllStringSubmatch(text, -1) {
		if len(m) < 3 {
			continue
		}
		name, val := m[1], strings.TrimSpace(m[2])
		if name == "" || val == "" {
			continue
		}
		// Prefer host/IP literals; keep first assignment.
		if _, ok := out[name]; ok {
			continue
		}
		out[name] = val
	}
	return out
}

func extractJSHashDerivedVars(text string) map[string]bool {
	out := make(map[string]bool)
	for _, re := range []*regexp.Regexp{reJSHashSplit, reJSHashDirect} {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			if len(m) > 1 && m[1] != "" {
				out[m[1]] = true
			}
		}
	}
	return out
}

func looksLikeHostOrIP(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "/?# ") {
		return false
	}
	if IsIPHost(s) {
		return true
	}
	// Basic hostname: has a dot, no scheme.
	if strings.Contains(s, "://") {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func looksLikeTrackingVar(name string) bool {
	l := strings.ToLower(name)
	return strings.Contains(l, "track") || strings.Contains(l, "hash") ||
		strings.Contains(l, "param") || strings.Contains(l, "frag") ||
		strings.Contains(l, "query") || strings.Contains(l, "campaign")
}

// appendTrackingQuery joins a base ending in /? or / with a fragment payload as a query string.
func appendTrackingQuery(base, frag string) string {
	frag = strings.TrimSpace(frag)
	if frag == "" {
		return strings.TrimSuffix(base, "?")
	}
	base = strings.TrimSuffix(base, "?")
	payload := strings.TrimPrefix(frag, "?")
	if !strings.HasSuffix(base, "/") && !strings.Contains(strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://"), "/") {
		base += "/"
	}
	return base + "?" + payload
}

// PageFindings converts page analysis into actionable phishing findings.
func PageFindings(pageURL string, page *PageAnalysis) []Finding {
	if page == nil {
		return nil
	}
	var findings []Finding
	host := HostFromURL(pageURL)

	if page.CloudStorageHost && strings.Contains(strings.ToLower(page.ContentType), "html") {
		findings = append(findings, Finding{
			Severity: "high",
			Category: "phish",
			Message:  "HTML hosted on cloud object storage (" + host + ") — common phishing lure pattern",
		})
	}

	for _, brand := range page.BrandImpersonation {
		findings = append(findings, Finding{
			Severity: "high",
			Category: "phish",
			Message:  "brand impersonation: " + brand,
		})
	}

	for _, kit := range page.Kits {
		findings = append(findings, Finding{
			Severity: "high",
			Category: "phish",
			Message:  "phishing kit fingerprint: " + kit,
		})
	}

	if page.HasTurnstile && !isCloudflareHost(host) {
		findings = append(findings, Finding{
			Severity: "high",
			Category: "phish",
			Message:  "Cloudflare Turnstile widget on non-Cloudflare host — likely fake browser check",
		})
	}

	if reCheckingBrowser.MatchString(page.Title) || reCheckingBrowser.MatchString(strings.Join(page.BrandImpersonation, " ")) {
		findings = append(findings, Finding{
			Severity: "medium",
			Category: "phish",
			Message:  "page mimics interstitial/browser-check language (" + page.Title + ")",
		})
	}

	if page.Deepview != "" {
		findings = append(findings, Finding{
			Severity: "medium",
			Category: "phish",
			Message:  fmt.Sprintf("%s deepview / deferred deep-link page — often used to wrap campaign destinations", page.Deepview),
		})
		for i, u := range page.EmbeddedURLs {
			if i >= 6 {
				break
			}
			if isNoiseDestination(u) {
				continue
			}
			findings = append(findings, Finding{
				Severity: "medium",
				Category: "phish",
				Message:  "embedded campaign destination: " + u,
			})
		}
	}

	destShown := 0
	for _, dest := range page.Destinations {
		if destShown >= 8 {
			findings = append(findings, Finding{
				Severity: "info",
				Category: "phish",
				Message:  fmt.Sprintf("+%d more external destination(s)", len(page.Destinations)-destShown),
			})
			break
		}
		sev := "medium"
		via := "external destination"
		for _, j := range page.JSRedirects {
			if sameWire(j, dest) {
				via = "JS/meta redirect to external host"
				sev = "high"
				break
			}
		}
		for _, m := range page.MetaRefresh {
			if sameWire(m, dest) {
				via = "meta refresh to external host"
				sev = "high"
				break
			}
		}
		msg := via + ": " + dest
		if strings.HasPrefix(strings.ToLower(dest), "http://") {
			msg += " (cleartext HTTP)"
			sev = "high"
		}
		if IsIPHost(HostFromURL(dest)) {
			sev = "high"
			msg += " (raw IP)"
		}
		findings = append(findings, Finding{Severity: sev, Category: "phish", Message: msg})
		destShown++
	}

	for _, d := range page.Downloads {
		findings = append(findings, Finding{
			Severity: "high",
			Category: "phish",
			Message:  "download / payload link: " + d,
		})
	}

	for _, a := range page.AppLinks {
		findings = append(findings, Finding{
			Severity: "medium",
			Category: "phish",
			Message:  "app / deep-link scheme: " + truncateMid(a, 120),
		})
	}

	if page.HasPasswordField {
		findings = append(findings, Finding{
			Severity: "high",
			Category: "phish",
			Message:  "password input field present on page",
		})
	}
	for _, f := range page.Forms {
		if f.CrossOrigin || (f.ActionHost != "" && !HostEqual(f.ActionHost, host)) {
			msg := fmt.Sprintf("form posts off-site (%s → %s)", f.Method, f.Action)
			if f.HasPassword {
				msg += " · password field"
			}
			if f.HiddenFields > 0 {
				msg += fmt.Sprintf(" · %d hidden field(s)", f.HiddenFields)
			}
			if f.AutofillOff {
				msg += " · autocomplete=off"
			}
			findings = append(findings, Finding{
				Severity: "high",
				Category: "phish",
				Message:  msg,
			})
			continue
		}
		if f.HasPassword && f.HiddenFields >= 2 {
			findings = append(findings, Finding{
				Severity: "medium",
				Category: "phish",
				Message:  fmt.Sprintf("credential form with %d hidden field(s) (possible tracking/exfil tokens)", f.HiddenFields),
			})
		}
		if f.HasPassword && f.AutofillOff {
			findings = append(findings, Finding{
				Severity: "medium",
				Category: "phish",
				Message:  "password form disables autocomplete (common on credential harvesters)",
			})
		}
	}

	for _, sig := range page.Obfuscation {
		findings = append(findings, Finding{
			Severity: "medium",
			Category: "phish",
			Message:  "JS obfuscation: " + sig,
		})
	}
	for _, sig := range page.HiddenUI {
		sev := "medium"
		if strings.Contains(sig, "password") || strings.Contains(sig, "full-page") {
			sev = "high"
		}
		findings = append(findings, Finding{
			Severity: sev,
			Category: "phish",
			Message:  "hidden UI: " + sig,
		})
	}
	if len(page.ScriptsSkimmed) > 0 {
		findings = append(findings, Finding{
			Severity: "info",
			Category: "phish",
			Message:  fmt.Sprintf("skimmed %d external script(s) for redirects/obfuscation", len(page.ScriptsSkimmed)),
		})
	}

	for _, img := range page.ExternalImages {
		ih := HostFromURL(img)
		if ih != "" && !HostEqual(ih, host) && looksLikeBrandAsset(img) {
			findings = append(findings, Finding{
				Severity: "medium",
				Category: "phish",
				Message:  "external brand/logo asset: " + img,
			})
		}
	}

	return findings
}

func isCloudStorageHost(host string) bool {
	h := strings.ToLower(host)
	switch {
	case h == "storage.googleapis.com", strings.HasSuffix(h, ".storage.googleapis.com"):
		return true
	case strings.Contains(h, "s3.amazonaws.com"), strings.Contains(h, ".s3."),
		strings.HasSuffix(h, ".amazonaws.com") && strings.Contains(h, "s3"):
		return true
	case strings.Contains(h, "blob.core.windows.net"):
		return true
	case strings.Contains(h, "digitaloceanspaces.com"):
		return true
	case strings.Contains(h, "r2.dev"), strings.Contains(h, "r2.cloudflarestorage.com"):
		return true
	default:
		return false
	}
}

func isCloudflareHost(host string) bool {
	h := strings.ToLower(host)
	return strings.Contains(h, "cloudflare.com") || strings.Contains(h, "cloudflareinsights.com")
}

func looksLikeBrandAsset(u string) bool {
	l := strings.ToLower(u)
	keys := []string{
		"logo", "cloudflare", "microsoft", "apple", "paypal", "1000logos",
		"docusign", "fedex", "ups", "usps", "dhl", "okta", "adobe", "acrobat",
		"linkedin", "chase", "wellsfargo", "bankofamerica",
	}
	for _, k := range keys {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

func absolutize(base, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "data:") || strings.HasPrefix(ref, "javascript:") {
		return ""
	}
	bu, err := url.Parse(base)
	if err != nil {
		return ref
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return bu.ResolveReference(ru).String()
}

func appendUnique(slice []string, v string) []string {
	for _, s := range slice {
		if s == v {
			return slice
		}
	}
	return append(slice, v)
}

func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

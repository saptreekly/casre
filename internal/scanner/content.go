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
	Action string `json:"action,omitempty"`
	Method string `json:"method,omitempty"`
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
	Destinations       []string   `json:"destinations,omitempty"` // resolved external next-hops
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
	reJSLoc          = regexp.MustCompile(`(?is)(?:window\.)?(?:top\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']`)
	reJSReplace      = regexp.MustCompile(`(?is)(?:window\.)?(?:top\.)?location\.replace\(\s*["']([^"']+)["']`)
	reJSAssignHref   = regexp.MustCompile(`(?is)(?:window\.)?location\.href\s*=\s*["'](https?://[^"']+)["']\s*\+`)
	reAbsURLInJS     = regexp.MustCompile(`(?is)["'](https?://[^"'\s]+)["']\s*\+\s*(?:window\.)?location\.hash`)
	reValidateProto  = regexp.MustCompile(`(?is)validateProtocol\(\s*["']([^"']+)["']\s*\)`)
	reQuotedHTTP     = regexp.MustCompile(`(?is)["'](https?://[^"'\s]+)["']`)
	reCheckingBrowser = regexp.MustCompile(`(?i)checking your browser|just a moment|review your connection security|verification complete|ddos protection by`)
	reDownloadExt    = regexp.MustCompile(`(?i)\.(?:apk|ipa|exe|dmg|pkg|msi|zip|rar|7z|vbs|scr|pdf)(?:\?|#|$)`)
)

// AnalyzePage extracts phishing-relevant signals from an HTML (or HTML-ish) body.
func AnalyzePage(body []byte, contentType, pageURL string) *PageAnalysis {
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

	for _, re := range []*regexp.Regexp{reJSLoc, reJSReplace, reJSAssignHref, reAbsURLInJS, reValidateProto} {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			if len(m) < 2 {
				continue
			}
			if abs := absolutize(pageURL, m[1]); abs != "" {
				p.JSRedirects = appendUnique(p.JSRedirects, abs)
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

	for _, m := range reForm.FindAllStringSubmatch(text, 10) {
		attrs := ""
		if len(m) > 1 {
			attrs = m[1]
		}
		f := PageForm{Method: "get"}
		if am := reAction.FindStringSubmatch(attrs); len(am) > 1 {
			f.Action = absolutize(pageURL, am[1])
		}
		if mm := reMethod.FindStringSubmatch(attrs); len(mm) > 1 {
			f.Method = strings.ToLower(mm[1])
		}
		p.Forms = append(p.Forms, f)
	}

	p.HasPasswordField = rePassword.MatchString(text)
	p.HasTurnstile = reTurnstile.MatchString(text)

	p.BrandImpersonation = detectBrandImpersonation(text, baseHost, p)

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
		actionHost := HostFromURL(f.Action)
		if actionHost != "" && !HostEqual(actionHost, host) {
			findings = append(findings, Finding{
				Severity: "high",
				Category: "phish",
				Message:  fmt.Sprintf("form posts off-site (%s → %s)", f.Method, f.Action),
			})
		}
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

func detectBrandImpersonation(text, host string, p *PageAnalysis) []string {
	var out []string
	lower := strings.ToLower(text)
	if !isCloudflareHost(host) {
		if strings.Contains(lower, "cloudflare") || p.HasTurnstile ||
			strings.Contains(lower, "checking your browser") ||
			strings.Contains(lower, "just a moment") {
			out = appendUnique(out, "Cloudflare interstitial/turnstile clone")
		}
		for _, img := range p.ExternalImages {
			if strings.Contains(strings.ToLower(img), "cloudflare") {
				out = appendUnique(out, "Cloudflare logo asset on foreign host")
			}
		}
	}
	if !strings.Contains(strings.ToLower(host), "microsoft") &&
		(strings.Contains(lower, "microsoft 365") || strings.Contains(lower, "office 365") ||
			strings.Contains(lower, "outlook web")) {
		out = appendUnique(out, "Microsoft 365 / Outlook language")
	}
	if !strings.Contains(strings.ToLower(host), "apple") &&
		(strings.Contains(lower, "apple id") || strings.Contains(lower, "icloud")) {
		out = appendUnique(out, "Apple ID / iCloud language")
	}
	if !strings.Contains(strings.ToLower(host), "google") && !isCloudStorageHost(host) &&
		(strings.Contains(lower, "google account") || strings.Contains(lower, "sign in with google")) {
		out = appendUnique(out, "Google account language")
	}
	return out
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
	return strings.Contains(l, "logo") || strings.Contains(l, "cloudflare") ||
		strings.Contains(l, "microsoft") || strings.Contains(l, "apple") ||
		strings.Contains(l, "paypal") || strings.Contains(l, "1000logos")
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

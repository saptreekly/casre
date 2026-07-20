package scanner

import (
	"net"
	"net/url"
	"strings"
)

// Node roles for phishing campaign graphs.
const (
	RoleTracker  = "tracker"  // ESP / shortener / click tracker
	RoleCloaker  = "cloaker"  // interstitial / fake browser check / bucket lure
	RoleDeepview = "deepview" // Branch / AppsFlyer deferred deep-link wrap
	RoleLander   = "lander"   // credential / payload / suspicious campaign destination
	RoleDecoy    = "decoy"    // brand / CDN / social — stop expanding in campaign mode
	RoleUnknown  = "unknown"
)

// RoleContext carries parent-edge info so landers aren't over-labeled.
type RoleContext struct {
	ParentRole string
	Via        string // seed, http, js, meta, form, link
}

// ClassifyNodeRole assigns a campaign role from host + page signals.
func ClassifyNodeRole(host, rawURL string, page *PageAnalysis, probe *HTTPResult) string {
	return ClassifyNodeRoleCtx(host, rawURL, page, probe, RoleContext{})
}

// ClassifyNodeRoleCtx is the context-aware classifier used during crawls.
func ClassifyNodeRoleCtx(host, rawURL string, page *PageAnalysis, probe *HTTPResult, rc RoleContext) string {
	h := strings.ToLower(host)
	pathStr := pathOf(rawURL)
	cleartext := strings.HasPrefix(strings.ToLower(rawURL), "http://")

	if isDecoyHost(h) {
		return RoleDecoy
	}
	if isTrackerHost(h, pathStr) {
		return RoleTracker
	}
	if page != nil && page.Deepview != "" {
		return RoleDeepview
	}
	if strings.Contains(h, "app.link") || strings.Contains(h, "bnc.lt") ||
		strings.Contains(h, "onelink.me") || strings.HasSuffix(h, ".page.link") {
		return RoleDeepview
	}

	if page != nil {
		if isCloakerPage(page) {
			return RoleCloaker
		}
		if isStrongLander(page, h, pathStr) {
			return RoleLander
		}
	}

	// Redirect-only hop.
	if probe != nil && probe.StatusCode >= 300 && probe.StatusCode < 400 && (page == nil || page.Bytes == 0) {
		return RoleUnknown
	}

	// Weak lander: only when reached from a delivery hop with phishy traits.
	if looksLikeWeakLander(h, rawURL, cleartext, page, rc) {
		return RoleLander
	}

	return RoleUnknown
}

func isCloakerPage(page *PageAnalysis) bool {
	if page.HasTurnstile || len(page.BrandImpersonation) > 0 || len(page.Kits) > 0 {
		return true
	}
	if page.CloudStorageHost && strings.Contains(strings.ToLower(page.ContentType), "html") {
		return true
	}
	if reCheckingBrowser.MatchString(page.Title) {
		return true
	}
	if len(page.JSRedirects) > 0 && (page.CloudStorageHost || len(page.MetaRefresh) > 0) {
		return true
	}
	for _, h := range page.HiddenUI {
		if strings.Contains(h, "iframe") || strings.Contains(h, "captcha") || strings.Contains(h, "Turnstile") {
			return true
		}
	}
	if len(page.Obfuscation) >= 2 && len(page.JSRedirects) > 0 {
		return true
	}
	return false
}

func isStrongLander(page *PageAnalysis, pageHost, pathStr string) bool {
	if page.HasPasswordField {
		return true
	}
	if len(page.Downloads) > 0 {
		return true
	}
	for _, f := range page.Forms {
		if f.CrossOrigin {
			return true
		}
		if f.Action == "" {
			continue
		}
		ah := HostFromURL(f.Action)
		if ah != "" && !HostEqual(ah, pageHost) {
			return true
		}
	}
	for _, h := range page.HiddenUI {
		if strings.Contains(h, "password") || strings.Contains(h, "login") || strings.Contains(h, "harvest") {
			return true
		}
	}
	lowerPath := strings.ToLower(pathStr)
	for _, needle := range []string{"/login", "/signin", "/account", "/verify", "/password", "/wallet", "/webmail", "/owa"} {
		if strings.Contains(lowerPath, needle) {
			return true
		}
	}
	return false
}

func looksLikeWeakLander(host, rawURL string, cleartext bool, page *PageAnalysis, rc RoleContext) bool {
	if page == nil || page.Title == "" {
		return false
	}
	if isLikelyBenignBrand(host) {
		return false
	}

	fromDelivery := rc.ParentRole == RoleCloaker || rc.ParentRole == RoleDeepview ||
		rc.ParentRole == RoleTracker || rc.Via == "js" || rc.Via == "meta"
	if !fromDelivery && rc.ParentRole == "" && rc.Via != "seed" {
		// No context (single probe): only cleartext + non-brand with title after interstitial signals.
		return false
	}

	// Classic phish: cloaker JS → cleartext lander on odd host.
	if cleartext && (rc.ParentRole == RoleCloaker || rc.Via == "js" || rc.Via == "meta") {
		return true
	}
	if isSuspiciousHost(host) && fromDelivery {
		return true
	}
	// Seed page itself that isn't cloaker/tracker but has phishy title on suspicious host.
	if rc.Via == "seed" && isSuspiciousHost(host) && reCheckingBrowser.MatchString(page.Title) {
		return false // cloaker path should have caught this
	}
	return false
}

func isSuspiciousHost(host string) bool {
	h := strings.ToLower(host)
	if net.ParseIP(h) != nil || (strings.HasPrefix(h, "[") && net.ParseIP(strings.Trim(h, "[]")) != nil) {
		return true
	}
	suspiciousTLD := []string{
		".xyz", ".top", ".icu", ".click", ".loan", ".gq", ".ml", ".cf", ".tk",
		".pw", ".cc", ".buzz", ".work", ".rest", ".country", ".kim", ".mom",
		".site", ".online", ".shop", ".sbs", ".cfd", ".bond",
	}
	for _, t := range suspiciousTLD {
		if strings.HasSuffix(h, t) {
			return true
		}
	}
	// Short random-looking labels (e.g. pociv.site already caught by .site).
	labels := strings.Split(h, ".")
	if len(labels) >= 2 {
		sld := labels[len(labels)-2]
		if len(sld) <= 5 && !isCommonSLD(sld) {
			// Very short SLD on cheap TLD already handled; keep mild signal for .com only if digits-heavy.
			digits := 0
			for _, r := range sld {
				if r >= '0' && r <= '9' {
					digits++
				}
			}
			if digits >= 2 {
				return true
			}
		}
	}
	return false
}

func isCommonSLD(s string) bool {
	switch s {
	case "google", "apple", "amazon", "microsoft", "facebook", "instagram", "twitter",
		"youtube", "github", "cloudflare", "outlook", "office", "linkedin", "netflix",
		"paypal", "adobe", "dropbox", "spotify", "albert":
		return true
	default:
		return false
	}
}

func isLikelyBenignBrand(host string) bool {
	h := strings.ToLower(host)
	if isDecoyHost(h) {
		return true
	}
	// Well-known consumer brands that Branch/ESP campaigns often land on legitimately.
	brands := []string{
		"albert.com", "meetalbert.com",
		"paypal.com", "venmo.com", "stripe.com",
		"amazon.com", "apple.com", "microsoft.com", "office.com",
		"google.com", "youtube.com", "facebook.com", "instagram.com",
		"netflix.com", "spotify.com", "adobe.com", "dropbox.com",
		"github.com", "gitlab.com", "atlassian.com", "slack.com",
		"salesforce.com", "shopify.com", "zendesk.com",
	}
	for _, b := range brands {
		if h == b || strings.HasSuffix(h, "."+b) {
			return true
		}
	}
	return false
}

// CampaignShouldExpand reports whether page/JS children should be crawled.
// HTTP redirects are handled separately so unknown mid-chain 3xx still advances.
func CampaignShouldExpand(role string) bool {
	switch role {
	case RoleTracker, RoleCloaker, RoleDeepview, RoleLander:
		return true
	default:
		return false
	}
}

// CampaignShouldEnqueueChild decides whether to visit a child host and whether
// that child may expand further (campaign mode stops at decoys).
func CampaignShouldEnqueueChild(parentRole, childHost string, fullCrawl bool) (visit bool, expandLater bool) {
	if fullCrawl {
		return true, true
	}
	if isDecoyHost(childHost) || isLikelyBenignBrand(childHost) {
		return true, false
	}
	return true, true
}

func isTrackerHost(host, pathStr string) bool {
	h := strings.ToLower(host)
	switch {
	case strings.Contains(h, "sendgrid.net"), strings.Contains(h, "sendgrid.com"),
		strings.Contains(h, "mailchimp.com"), strings.Contains(h, "list-manage.com"),
		strings.Contains(h, "constantcontact.com"), strings.Contains(h, "mandrillapp.com"),
		strings.Contains(h, "sparkpostmail.com"), strings.Contains(h, "spgo.io"),
		strings.Contains(h, "mailgun.org"), strings.Contains(h, "amazonses.com"),
		strings.Contains(h, "awstrack.me"):
		return true
	case h == "bit.ly", strings.HasSuffix(h, ".bit.ly"), h == "t.co", h == "tinyurl.com",
		strings.Contains(h, "rebrand.ly"), strings.Contains(h, "linktr.ee"),
		strings.Contains(h, "ow.ly"), strings.Contains(h, "cutt.ly"):
		return true
	case strings.Contains(pathStr, "/ls/click"), strings.Contains(pathStr, "/wf/click"):
		return true
	}
	return false
}

func isDecoyHost(host string) bool {
	h := strings.ToLower(host)
	if h == "" {
		return false
	}
	if isCloudStorageHost(h) {
		return false
	}
	exact := map[string]struct{}{
		"facebook.com": {}, "www.facebook.com": {}, "m.facebook.com": {},
		"instagram.com": {}, "www.instagram.com": {},
		"twitter.com": {}, "www.twitter.com": {}, "x.com": {}, "www.x.com": {},
		"youtube.com": {}, "www.youtube.com": {}, "m.youtube.com": {},
		"linkedin.com": {}, "www.linkedin.com": {},
		"tiktok.com": {}, "www.tiktok.com": {},
		"apple.com": {}, "www.apple.com": {}, "apps.apple.com": {}, "itunes.apple.com": {},
		"play.google.com": {}, "accounts.google.com": {},
		"microsoft.com": {}, "www.microsoft.com": {}, "login.microsoftonline.com": {},
		"github.com": {}, "www.github.com": {},
		"w3.org": {}, "www.w3.org": {}, "schema.org": {},
		"cloudflare.com": {}, "www.cloudflare.com": {},
		"google.com": {}, "www.google.com": {},
		"bing.com": {}, "www.bing.com": {},
		"finra.org": {}, "www.finra.org": {},
		"sipc.org": {}, "www.sipc.org": {},
	}
	if _, ok := exact[h]; ok {
		return true
	}
	suffixes := []string{
		".facebook.com", ".fbcdn.net", ".instagram.com", ".twitter.com", ".x.com",
		".youtube.com", ".ytimg.com", ".linkedin.com", ".tiktok.com",
		".apple.com", ".cdn-apple.com",
		".google.com", ".gstatic.com", ".googleapis.com", ".googleusercontent.com",
		".microsoft.com", ".office.com", ".live.com",
		".cloudflare.com", ".cloudflareinsights.com",
		".akamaihd.net", ".akamaized.net", ".fastly.net",
		".sentry.io", ".zendesk.com",
		".doubleclick.net", ".googlesyndication.com",
	}
	for _, s := range suffixes {
		if strings.HasSuffix(h, s) {
			return true
		}
	}
	return false
}

func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Path)
}

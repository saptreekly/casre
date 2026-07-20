package scanner

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

// brandSig is a lure/impersonation fingerprint.
// Matching any Needle (or all RequireAll) on a non-excluded host triggers BrandImpersonation.
type brandSig struct {
	Name             string
	HostExclude      []string // skip if host contains any of these
	SkipCloudStorage bool     // skip on GCS/S3/etc (avoids Google false positives)
	Needles          []string // case-insensitive; any match
	RequireAll       []string // if set, all must appear (in addition to any Needles if both set — Needles OR RequireAll logic: if RequireAll nonempty, use RequireAll only)
	AssetNeedles     []string // match against external image URLs
}

var brandSignatures = []brandSig{
	{
		Name:        "Cloudflare interstitial/turnstile clone",
		HostExclude: []string{"cloudflare.com", "cloudflareinsights.com"},
		Needles: []string{
			"checking your browser", "just a moment", "review your connection security",
			"ddos protection by", "cf-turnstile", "challenges.cloudflare.com/turnstile",
		},
		AssetNeedles: []string{"cloudflare"},
	},
	{
		Name:        "Microsoft 365 / Outlook lure",
		HostExclude: []string{"microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com", "office365.com"},
		Needles: []string{
			"microsoft 365", "office 365", "outlook web", "microsoftonline",
			"exchange online", "protect.outlook", "sign in to microsoft",
			"microsoft account", "office.com/login",
		},
		AssetNeedles: []string{"microsoft", "office365", "outlook"},
	},
	{
		Name:        "Apple ID / iCloud lure",
		HostExclude: []string{"apple.com", "icloud.com", "appleid.apple.com"},
		Needles: []string{
			"apple id", "appleid", "icloud", "find my iphone", "sign in with apple",
		},
		AssetNeedles: []string{"apple", "icloud"},
	},
	{
		Name:             "Google account lure",
		HostExclude:      []string{"google.com", "googleapis.com", "gstatic.com", "youtube.com"},
		SkipCloudStorage: true,
		Needles: []string{
			"google account", "sign in with google", "accounts.google", "myaccount.google",
		},
		AssetNeedles: []string{"google", "gstatic"},
	},
	{
		Name:        "DocuSign / e-signature lure",
		HostExclude: []string{"docusign.com", "docusign.net"},
		Needles: []string{
			"docusign", "docusign envelope", "please review and sign",
			"electronic signature", "sign document",
		},
		AssetNeedles: []string{"docusign"},
	},
	{
		Name:        "PayPal account lure",
		HostExclude: []string{"paypal.com", "paypal.me", "paypalobjects.com"},
		Needles: []string{
			"paypal", "resolve an issue with your paypal", "paypal account limited",
			"confirm your paypal",
		},
		AssetNeedles: []string{"paypal"},
	},
	{
		Name:        "Okta / SSO lure",
		HostExclude: []string{"okta.com", "oktacdn.com"},
		Needles: []string{
			"okta", "sign in to continue to", "single sign-on", "sso login",
		},
		AssetNeedles: []string{"okta"},
	},
	{
		Name:        "Shipping / parcel lure",
		HostExclude: []string{"fedex.com", "ups.com", "usps.com", "dhl.com", "royalmail.com"},
		Needles: []string{
			"fedex", "ups tracking", "usps", "dhl express", "package delivery",
			"failed delivery", "redelivery notice", "track your package", "customs fee",
			"shipping notification", "parcel pending",
		},
		AssetNeedles: []string{"fedex", "ups", "usps", "dhl"},
	},
	{
		Name: "Bank / financial lure",
		HostExclude: []string{
			"chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
			"capitalone.com", "americanexpress.com", "amex.com",
		},
		Needles: []string{
			"unusual activity on your account", "verify your banking", "online banking login",
			"account has been locked", "confirm your debit", "wire transfer pending",
			"chase bank", "bank of america", "wells fargo", "capital one",
		},
		AssetNeedles: []string{"chase", "bankofamerica", "wellsfargo", "amex"},
	},
	{
		Name:        "Adobe / document lure",
		HostExclude: []string{"adobe.com", "acrobat.com", "adobelogin.com"},
		Needles: []string{
			"adobe sign", "shared a file with you", "view document", "acrobat reader",
			"encrypted document",
		},
		AssetNeedles: []string{"adobe", "acrobat"},
	},
	{
		Name:        "LinkedIn / HR lure",
		HostExclude: []string{"linkedin.com", "licdn.com"},
		Needles: []string{
			"linkedin", "you have 1 new message", "connection request", "job opportunity waiting",
		},
		AssetNeedles: []string{"linkedin", "licdn"},
	},
}

var (
	reKitHREFB    = regexp.MustCompile(`(?is)srv_ip|tarcking_param|tracking_param`)
	reKitAtob     = regexp.MustCompile(`(?is)(?:location(?:\.href)?|location\.(?:replace|assign))\s*(?:=\s*|\()\s*atob\s*\(`)
	reKitFromChar = regexp.MustCompile(`(?is)String\.fromCharCode\s*\(\s*\d`)
	reAtobLiteral = regexp.MustCompile(`(?is)(?:window\.)?(?:document\.)?(?:top\.)?(?:self\.)?location(?:\.href)?\s*=\s*atob\(\s*["']([A-Za-z0-9+/=]+)["']\s*\)|` +
		`(?:window\.)?(?:document\.)?(?:top\.)?(?:self\.)?location\.(?:replace|assign)\(\s*atob\(\s*["']([A-Za-z0-9+/=]+)["']\s*\)`)
	reJSAssignFn   = regexp.MustCompile(`(?is)(?:window\.)?(?:document\.)?(?:top\.)?(?:self\.)?location\.assign\(\s*["']([^"']+)["']`)
	reJSConcatPair = regexp.MustCompile(`(?is)["']([^"']*)["']\s*\+\s*["']([^"']*)["']`)
)

func detectBrandImpersonation(text, host string, p *PageAnalysis) []string {
	var out []string
	lower := strings.ToLower(text)
	hostLower := strings.ToLower(host)

	for _, sig := range brandSignatures {
		if hostExcluded(hostLower, sig.HostExclude) {
			continue
		}
		if sig.SkipCloudStorage && isCloudStorageHost(host) {
			continue
		}
		matched := false
		if len(sig.RequireAll) > 0 {
			matched = true
			for _, n := range sig.RequireAll {
				if !strings.Contains(lower, strings.ToLower(n)) {
					matched = false
					break
				}
			}
		} else {
			for _, n := range sig.Needles {
				if strings.Contains(lower, strings.ToLower(n)) {
					matched = true
					break
				}
			}
		}
		if !matched {
			for _, img := range p.ExternalImages {
				il := strings.ToLower(img)
				for _, a := range sig.AssetNeedles {
					if strings.Contains(il, a) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
		}
		// Cloudflare: also treat HasTurnstile as a needle.
		if !matched && strings.HasPrefix(sig.Name, "Cloudflare") && p.HasTurnstile {
			matched = true
		}
		if matched {
			out = appendUnique(out, sig.Name)
		}
	}

	// Extra Cloudflare logo-on-foreign-host signal (kept distinct).
	if !isCloudflareHost(host) {
		for _, img := range p.ExternalImages {
			if strings.Contains(strings.ToLower(img), "cloudflare") {
				out = appendUnique(out, "Cloudflare logo asset on foreign host")
			}
		}
	}
	return out
}

func hostExcluded(host string, excludes []string) bool {
	for _, e := range excludes {
		if e != "" && strings.Contains(host, strings.ToLower(e)) {
			return true
		}
	}
	return false
}

// detectKits returns named phishing-kit / cloaker fingerprints.
func detectKits(text string, p *PageAnalysis) []string {
	var out []string
	lower := strings.ToLower(text)

	if reKitHREFB.MatchString(text) && (strings.Contains(lower, "document.location") ||
		strings.Contains(lower, "location.href") || strings.Contains(lower, "location.replace")) {
		out = appendUnique(out, "HREFB-style IP-var redirect cloaker")
	}
	if reKitAtob.MatchString(text) {
		out = appendUnique(out, "atob() redirect cloaker")
	}
	if reKitFromChar.MatchString(text) && (strings.Contains(lower, "location") || strings.Contains(lower, "http")) {
		out = appendUnique(out, "fromCharCode obfuscated redirect")
	}
	if p.CloudStorageHost && p.HasTurnstile {
		out = appendUnique(out, "Turnstile-on-cloud-storage cloaker")
	}
	if len(p.MetaRefresh) > 0 && (p.HasPasswordField || len(p.BrandImpersonation) > 0) {
		out = appendUnique(out, "meta-refresh credential lure")
	}
	if strings.Contains(lower, "executeRedirect") && p.HasTurnstile {
		out = appendUnique(out, "Turnstile executeRedirect kit")
	}
	return out
}

// collapseJSStringConcats repeatedly joins adjacent string-literal concatenations
// so obfuscated 'ht'+'tp://'+'evil.com' patterns become readable for redirect extractors.
func collapseJSStringConcats(text string) string {
	prev := ""
	cur := text
	for i := 0; i < 32 && cur != prev; i++ {
		prev = cur
		cur = reJSConcatPair.ReplaceAllString(cur, `'$1$2'`)
	}
	return cur
}

// extractAtobRedirects decodes atob('…') location assignments into navigable URLs.
func extractAtobRedirects(text, pageURL string) []string {
	var out []string
	for _, m := range reAtobLiteral.FindAllStringSubmatch(text, -1) {
		b64 := ""
		if len(m) > 1 && m[1] != "" {
			b64 = m[1]
		} else if len(m) > 2 && m[2] != "" {
			b64 = m[2]
		}
		if b64 == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(b64)
		}
		if err != nil {
			continue
		}
		cand := strings.TrimSpace(string(raw))
		if abs := absolutize(pageURL, cand); abs != "" && isNavigableHTTPURL(abs) {
			out = appendUnique(out, abs)
		} else if isNavigableHTTPURL(cand) {
			out = appendUnique(out, cand)
		}
	}
	return out
}

// extractAssignRedirects picks up location.assign('…') targets.
func extractAssignRedirects(text, pageURL string) []string {
	var out []string
	for _, m := range reJSAssignFn.FindAllStringSubmatch(text, -1) {
		if len(m) < 2 {
			continue
		}
		if abs := absolutize(pageURL, m[1]); abs != "" && isNavigableHTTPURL(abs) {
			out = appendUnique(out, abs)
		}
	}
	return out
}

// looksLikeURLAfterCollapse finds http(s) URLs that only appear after concat collapse.
func extractCollapsedLiteralRedirects(collapsed, pageURL string) []string {
	var out []string
	for _, m := range reQuotedHTTP.FindAllStringSubmatch(collapsed, 40) {
		if len(m) < 2 {
			continue
		}
		abs := absolutize(pageURL, m[1])
		if abs == "" || !isNavigableHTTPURL(abs) {
			continue
		}
		// Prefer absolute navigable destinations (including same-host — crawl filters later).
		if u, err := url.Parse(abs); err == nil && u.Host != "" {
			out = appendUnique(out, abs)
		}
	}
	return out
}

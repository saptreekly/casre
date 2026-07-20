package scanner

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// EnrichPageFromScripts fetches up to maxScripts external scripts referenced by page,
// skims them for redirects/obfuscation/kits, and merges results into page.
// Script URLs themselves are not crawl nodes — only discovered redirects become hops.
func EnrichPageFromScripts(
	ctx context.Context,
	page *PageAnalysis,
	pageURL, fragment string,
	timeout time.Duration,
	insecure bool,
	maxScripts int,
	wait func() error,
) {
	if page == nil || maxScripts <= 0 || len(page.ExternalScripts) == 0 {
		if page != nil && len(page.ExternalScripts) > 0 {
			page.ScriptsSkipped = len(page.ExternalScripts)
		}
		return
	}
	cands := prioritizeExternalScripts(page.ExternalScripts)
	for _, u := range cands {
		if len(page.ScriptsSkimmed) >= maxScripts {
			break
		}
		if err := ctx.Err(); err != nil {
			break
		}
		if wait != nil {
			if err := wait(); err != nil {
				break
			}
		}
		body, ok := fetchScriptBody(ctx, u, timeout, insecure)
		if !ok || len(body) == 0 {
			continue
		}
		page.ScriptsSkimmed = appendUnique(page.ScriptsSkimmed, u)
		mergeScriptSkim(page, skimJavaScript(body, u, pageURL, fragment))
	}
	skipped := len(page.ExternalScripts) - len(page.ScriptsSkimmed)
	if skipped < 0 {
		skipped = 0
	}
	page.ScriptsSkipped = skipped
	// Rebuild destinations after new redirects.
	rebuildDestinations(page, HostFromURL(pageURL))
}

func prioritizeExternalScripts(urls []string) []string {
	var hi, mid, lo []string
	for _, u := range urls {
		l := strings.ToLower(u)
		h := strings.ToLower(HostFromURL(u))
		switch {
		case strings.Contains(h, "challenges.cloudflare.com"),
			strings.Contains(h, "google.com/recaptcha"),
			strings.Contains(h, "gstatic.com"),
			strings.Contains(h, "hcaptcha.com"),
			strings.Contains(l, "jquery"),
			strings.Contains(l, "bootstrap"),
			strings.Contains(l, "analytics"),
			strings.Contains(l, "gtag"),
			strings.Contains(l, "googletagmanager"):
			lo = append(lo, u)
		case strings.Contains(l, "redirect"),
			strings.Contains(l, "cloak"),
			strings.Contains(l, "gate"),
			strings.Contains(l, "challenge"),
			strings.Contains(l, "verify"),
			strings.Contains(l, "loader"),
			strings.Contains(l, "pack"),
			strings.HasSuffix(strings.Split(l, "?")[0], ".js"):
			hi = append(hi, u)
		default:
			mid = append(mid, u)
		}
	}
	out := append(append(hi, mid...), lo...)
	return out
}

func fetchScriptBody(ctx context.Context, rawURL string, timeout time.Duration, insecure bool) ([]byte, bool) {
	host := HostFromURL(rawURL)
	if host == "" {
		return nil, false
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: timeout,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure, //nolint:gosec
			MinVersion:         tls.VersionTLS10,
		},
		ForceAttemptHTTP2: true,
		MaxIdleConns:      4,
		IdleConnTimeout:   timeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", "CASRE/1.0 (+recon; script-skim)")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		_, _ = io.CopyN(io.Discard, resp.Body, 2048)
		return nil, false
	}
	const maxBody = 256 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil && len(body) == 0 {
		return nil, false
	}
	return body, true
}

type scriptSkim struct {
	redirects   []string
	obfuscation []string
	kits        []string
}

func skimJavaScript(body []byte, scriptURL, pageURL, fragment string) scriptSkim {
	text := string(body)
	base := scriptURL
	if base == "" {
		base = pageURL
	}
	var s scriptSkim
	s.redirects = collectJSRedirects(text, base, fragment)
	// Also resolve relative to the HTML page when script uses page-relative paths.
	if pageURL != "" && pageURL != base {
		for _, u := range collectJSRedirects(text, pageURL, fragment) {
			s.redirects = appendUnique(s.redirects, u)
		}
	}
	s.obfuscation = detectObfuscation(text)
	tmp := &PageAnalysis{}
	s.kits = detectKits(text, tmp)
	return s
}

func mergeScriptSkim(page *PageAnalysis, s scriptSkim) {
	for _, u := range s.redirects {
		if isNavigableHTTPURL(u) {
			page.JSRedirects = appendUnique(page.JSRedirects, u)
		}
	}
	for _, o := range s.obfuscation {
		page.Obfuscation = appendUnique(page.Obfuscation, o)
	}
	for _, k := range s.kits {
		page.Kits = appendUnique(page.Kits, k)
	}
}

func rebuildDestinations(p *PageAnalysis, baseHost string) {
	if p == nil {
		return
	}
	p.Destinations = nil
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
}

// collectJSRedirects runs the same redirect extractors AnalyzePage uses on a JS body.
func collectJSRedirects(text, baseURL, fragment string) []string {
	var out []string
	add := func(u string) {
		if isNavigableHTTPURL(u) {
			out = appendUnique(out, u)
		}
	}
	for _, u := range reconstructJSVarRedirects(text, fragment) {
		add(u)
	}
	collapsed := collapseJSStringConcats(text)
	baseHost := HostFromURL(baseURL)
	for _, src := range []string{text, collapsed} {
		for _, re := range []*regexp.Regexp{reJSLoc, reJSReplace, reJSAssignHref, reAbsURLInJS, reValidateProto} {
			for _, m := range re.FindAllStringSubmatch(src, -1) {
				if len(m) < 2 {
					continue
				}
				if abs := absolutize(baseURL, m[1]); abs != "" {
					add(abs)
				}
			}
		}
	}
	for _, u := range extractAssignRedirects(text, baseURL) {
		add(u)
	}
	for _, u := range extractAtobRedirects(text, baseURL) {
		add(u)
	}
	if collapsed != text {
		for _, u := range extractCollapsedLiteralRedirects(collapsed, baseURL) {
			if isLikelyDestination(u, baseHost) || IsIPHost(HostFromURL(u)) {
				add(u)
			}
		}
		for _, u := range reconstructJSVarRedirects(collapsed, fragment) {
			add(u)
		}
	}
	return out
}

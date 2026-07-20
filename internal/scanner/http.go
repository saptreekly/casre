package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

// AuditHTTP fetches HTTP and HTTPS endpoints and audits response headers.
func AuditHTTP(ctx context.Context, host string, timeout time.Duration, insecure bool) []HTTPResult {
	schemes := []string{"http", "https"}
	results := make([]HTTPResult, 0, len(schemes))

	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s/", scheme, host)
		results = append(results, fetchHTTP(ctx, url, host, timeout, insecure, false, true))
	}
	return results
}

// ProbeURL fetches a URL, follows redirects, and captures a body sample.
func ProbeURL(ctx context.Context, rawURL string, timeout time.Duration, insecure bool) HTTPResult {
	host := HostFromURL(rawURL)
	if host == "" {
		return HTTPResult{URL: rawURL, Error: "could not parse host from url"}
	}
	return fetchHTTP(ctx, rawURL, host, timeout, insecure, true, true)
}

// ProbeURLHop fetches a single hop without following redirects (for graph mapping).
func ProbeURLHop(ctx context.Context, rawURL string, timeout time.Duration, insecure bool) HTTPResult {
	host := HostFromURL(rawURL)
	if host == "" {
		return HTTPResult{URL: rawURL, Error: "could not parse host from url"}
	}
	return fetchHTTP(ctx, rawURL, host, timeout, insecure, true, false)
}

func fetchHTTP(ctx context.Context, rawURL, host string, timeout time.Duration, insecure bool, captureBody, followRedirects bool) HTTPResult {
	result := HTTPResult{
		URL:     rawURL,
		Headers: make(map[string]string),
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
		MaxIdleConns:      10,
		IdleConnTimeout:   timeout,
	}

	startHost := host
	var chain []RedirectHop
	chain = append(chain, RedirectHop{URL: rawURL, Host: startHost})

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout * 3,
	}
	if followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 15 {
				return fmt.Errorf("stopped after 15 redirects")
			}
			prev := via[len(via)-1]
			status := 0
			if prev.Response != nil {
				status = prev.Response.StatusCode
			}
			if len(chain) > 0 {
				chain[len(chain)-1].StatusCode = status
			}
			nextHost := req.URL.Hostname()
			prevHost := ""
			if len(chain) > 0 {
				prevHost = chain[len(chain)-1].Host
			}
			chain = append(chain, RedirectHop{
				URL:         req.URL.String(),
				Host:        nextHost,
				CrossDomain: prevHost != "" && !HostEqual(prevHost, nextHost),
			})
			return nil
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; CASRE/1.0; +recon; authorized-use-only)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		if len(chain) > 1 {
			result.Redirects = chain
			result.RedirectCount = len(chain) - 1
		}
		return result
	}
	defer resp.Body.Close()

	const maxBody = 256 * 1024
	var body []byte
	if captureBody {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	} else {
		_, _ = io.CopyN(io.Discard, resp.Body, 8192)
	}

	result.StatusCode = resp.StatusCode
	result.FinalURL = resp.Request.URL.String()
	result.FinalHost = resp.Request.URL.Hostname()
	result.Server = resp.Header.Get("Server")
	result.ContentLength = resp.ContentLength
	if result.ContentLength < 0 && len(body) > 0 {
		result.ContentLength = int64(len(body))
	}

	for k, vals := range resp.Header {
		result.Headers[k] = strings.Join(vals, ", ")
	}

	if !followRedirects && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			abs := loc
			if u, err := resp.Request.URL.Parse(loc); err == nil {
				abs = u.String()
			}
			nextHost := HostFromURL(abs)
			result.FinalURL = abs
			result.FinalHost = nextHost
			result.RedirectCount = 1
			result.Redirects = []RedirectHop{
				{URL: rawURL, Host: startHost, StatusCode: resp.StatusCode},
				{URL: abs, Host: nextHost, CrossDomain: !HostEqual(startHost, nextHost)},
			}
		}
	} else if followRedirects {
		if len(chain) > 0 {
			chain[len(chain)-1].StatusCode = resp.StatusCode
			if chain[len(chain)-1].Host == "" {
				chain[len(chain)-1].Host = result.FinalHost
			}
		}
		if len(chain) > 1 {
			result.Redirects = chain
			result.RedirectCount = len(chain) - 1
		}
	}

	isHTTPS := strings.HasPrefix(result.FinalURL, "https") || strings.HasPrefix(rawURL, "https")
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		result.SecurityGaps = missingSecurityHeaders(resp.Header, isHTTPS)
	}
	result.Technologies = detectTech(resp.Header)

	if captureBody && len(body) > 0 {
		result.Body = body
	}
	if captureBody && len(body) > 0 && resp.StatusCode < 300 {
		ct := resp.Header.Get("Content-Type")
		result.Page = AnalyzePage(body, ct, firstNonEmpty(result.FinalURL, rawURL))
	}

	return result
}

func missingSecurityHeaders(h http.Header, isHTTPS bool) []string {
	var missing []string
	for _, name := range securityHeaders {
		if name == "Strict-Transport-Security" && !isHTTPS {
			continue
		}
		if name == "Content-Security-Policy" {
			if h.Get(name) != "" || h.Get("Content-Security-Policy-Report-Only") != "" {
				continue
			}
		}
		if h.Get(name) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

func detectTech(h http.Header) []string {
	seen := map[string]struct{}{}
	add := func(t string) {
		if t == "" {
			return
		}
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
	}

	if s := h.Get("Server"); s != "" {
		add("server:" + s)
	}
	if p := h.Get("X-Powered-By"); p != "" {
		add("powered-by:" + p)
	}
	if h.Get("X-AspNet-Version") != "" || h.Get("X-AspNetMvc-Version") != "" {
		add("aspnet")
	}
	if strings.Contains(strings.ToLower(h.Get("Set-Cookie")), "wordpress") ||
		h.Get("X-Redirect-By") == "WordPress" {
		add("wordpress")
	}
	if h.Get("CF-Ray") != "" || h.Get("CF-Cache-Status") != "" {
		add("cloudflare")
	}
	if h.Get("X-GitHub-Request-Id") != "" {
		add("github-pages")
	}
	if h.Get("X-Vercel-Id") != "" || h.Get("X-Vercel-Cache") != "" {
		add("vercel")
	}
	if h.Get("X-Amz-Cf-Id") != "" {
		add("cloudfront")
	}
	if h.Get("X-Amz-Request-Id") != "" {
		add("aws")
	}
	if h.Get("X-Served-By") != "" && strings.Contains(strings.ToLower(h.Get("X-Served-By")), "cache-") {
		add("fastly")
	}
	if h.Get("X-Akamai-Transformed") != "" {
		add("akamai")
	}
	if h.Get("X-Generator") != "" {
		add("generator:" + h.Get("X-Generator"))
	}
	if strings.Contains(strings.ToLower(h.Get("Set-Cookie")), "_ga") {
		add("google-analytics-cookie")
	}

	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	return out
}

func gapSeverity(gaps []string) string {
	for _, g := range gaps {
		if g == "Strict-Transport-Security" || g == "Content-Security-Policy" {
			return "medium"
		}
	}
	return "low"
}

// HTTPFindings converts header audit results into findings.
func HTTPFindings(results []HTTPResult) []Finding {
	var findings []Finding
	for _, r := range results {
		if r.Error != "" {
			continue
		}
		scheme := "http"
		if strings.HasPrefix(r.URL, "https") {
			scheme = "https"
		}

		if r.RedirectCount > 0 {
			findings = append(findings, Finding{
				Severity: "info",
				Category: "http",
				Message:  fmt.Sprintf("%s redirect chain: %d hop(s) → %s", scheme, r.RedirectCount, r.FinalURL),
			})
		}

		if cspRO := r.Headers["Content-Security-Policy-Report-Only"]; cspRO != "" &&
			r.Headers["Content-Security-Policy"] == "" {
			findings = append(findings, Finding{
				Severity: "low",
				Category: "http",
				Message:  fmt.Sprintf("%s has CSP-Report-Only but no enforced Content-Security-Policy", scheme),
			})
		}

		if len(r.SecurityGaps) > 0 {
			findings = append(findings, Finding{
				Severity: gapSeverity(r.SecurityGaps),
				Category: "http",
				Message:  fmt.Sprintf("%s missing headers: %s", scheme, strings.Join(r.SecurityGaps, ", ")),
			})
		}

		if scheme == "http" && r.StatusCode > 0 &&
			!strings.HasPrefix(r.FinalURL, "https") {
			findings = append(findings, Finding{
				Severity: "medium",
				Category: "http",
				Message:  "HTTP endpoint does not land on HTTPS after redirects",
			})
		}
	}
	return findings
}

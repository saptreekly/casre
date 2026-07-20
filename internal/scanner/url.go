package scanner

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// URLFindings emits phishing / spam-oriented signals for a probed URL.
func URLFindings(t Target, probe *HTTPResult) []Finding {
	if probe == nil && t.URL == "" {
		return nil
	}
	var findings []Finding
	inputURL := t.URL
	if inputURL == "" {
		inputURL = t.RawInput
	}

	if t.Fragment != "" {
		findings = append(findings, Finding{
			Severity: "info",
			Category: "url",
			Message:  "URL fragment present (not sent to server): #" + truncateMid(t.Fragment, 80),
		})
		if FragmentLooksLikeQuery(t.Fragment) {
			findings = append(findings, Finding{
				Severity: "medium",
				Category: "url",
				Message:  "fragment looks like a hidden query string — common tracking/campaign pattern",
			})
			q := parseFragmentQuery(t.Fragment)
			if len(q) > 0 {
				keys := make([]string, 0, len(q))
				for k := range q {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				findings = append(findings, Finding{
					Severity: "info",
					Category: "url",
					Message:  fmt.Sprintf("fragment params: %s", strings.Join(keys, ", ")),
				})
			}
		}
	}

	if u, err := url.Parse(inputURL); err == nil {
		if u.User != nil {
			findings = append(findings, Finding{
				Severity: "high",
				Category: "url",
				Message:  "URL contains userinfo (@) — common phishing obfuscation",
			})
		}
		if strings.Contains(u.Hostname(), "xn--") {
			findings = append(findings, Finding{
				Severity: "medium",
				Category: "url",
				Message:  "punycode/IDN hostname present — verify lookalike domains",
			})
		}
		if q := u.Query(); len(q) > 0 {
			findings = append(findings, Finding{
				Severity: "info",
				Category: "url",
				Message:  fmt.Sprintf("query string has %d parameter(s)", len(q)),
			})
		}
		path := strings.ToLower(u.Path)
		if strings.Contains(path, "login") || strings.Contains(path, "signin") ||
			strings.Contains(path, "account") || strings.Contains(path, "verify") ||
			strings.Contains(path, "password") || strings.Contains(path, "wallet") {
			findings = append(findings, Finding{
				Severity: "medium",
				Category: "url",
				Message:  "path looks credential/account related: " + u.Path,
			})
		}
		if esp := detectESP(u.Hostname(), path); esp != "" {
			findings = append(findings, Finding{
				Severity: "medium",
				Category: "url",
				Message:  esp,
			})
		}
	}

	if probe == nil {
		return findings
	}

	if probe.Error != "" {
		findings = append(findings, Finding{
			Severity: "medium",
			Category: "url",
			Message:  "URL probe failed: " + probe.Error,
		})
		return findings
	}

	startHost := HostFromURL(inputURL)
	finalHost := probe.FinalHost
	if finalHost == "" {
		finalHost = HostFromURL(probe.FinalURL)
	}

	if probe.RedirectCount > 0 {
		findings = append(findings, Finding{
			Severity: "info",
			Category: "url",
			Message:  fmt.Sprintf("redirect chain: %d hop(s)", probe.RedirectCount),
		})
	}
	if probe.RedirectCount >= 4 {
		findings = append(findings, Finding{
			Severity: "medium",
			Category: "url",
			Message:  "long redirect chain (≥4 hops) — common in tracking/malware lures",
		})
	}

	cross := 0
	for _, hop := range probe.Redirects {
		if hop.CrossDomain {
			cross++
		}
	}
	if cross > 0 {
		findings = append(findings, Finding{
			Severity: "medium",
			Category: "url",
			Message:  fmt.Sprintf("cross-domain redirect(s): %d hop(s) change hostname", cross),
		})
	}

	if startHost != "" && finalHost != "" && !HostEqual(startHost, finalHost) {
		sev := "medium"
		if IsIPHost(finalHost) {
			sev = "high"
		}
		label := "final host differs"
		if probe.StatusCode >= 300 && probe.StatusCode < 400 {
			label = "redirect Location host"
		}
		findings = append(findings, Finding{
			Severity: sev,
			Category: "url",
			Message:  fmt.Sprintf("%s: %s → %s", label, startHost, finalHost),
		})
	}

	if IsIPHost(finalHost) {
		findings = append(findings, Finding{
			Severity: "high",
			Category: "url",
			Message:  "redirect lands on a raw IP address",
		})
	}

	if strings.HasPrefix(strings.ToLower(inputURL), "https://") &&
		strings.HasPrefix(strings.ToLower(probe.FinalURL), "http://") {
		findings = append(findings, Finding{
			Severity: "high",
			Category: "url",
			Message:  "HTTPS URL redirects to cleartext HTTP",
		})
	}

	return findings
}

func detectESP(host, path string) string {
	h := strings.ToLower(host)
	switch {
	case strings.Contains(h, "sendgrid.net") || strings.Contains(h, "sendgrid.com"):
		return "SendGrid click-tracking URL — common email campaign / phishing delivery path"
	case strings.Contains(h, "mailchimp.com") || strings.Contains(h, "list-manage.com"):
		return "Mailchimp tracking URL"
	case strings.Contains(h, "constantcontact.com"):
		return "Constant Contact tracking URL"
	case strings.Contains(h, "mandrillapp.com"):
		return "Mandrill (Mailchimp) tracking URL"
	case strings.Contains(h, "sparkpostmail.com") || strings.Contains(h, "spgo.io"):
		return "SparkPost tracking URL"
	case strings.Contains(h, "mailgun.org") || strings.HasSuffix(h, ".mailgun.org"):
		return "Mailgun tracking URL"
	case strings.Contains(h, "amazonses.com") || strings.Contains(h, "awstrack.me"):
		return "Amazon SES / AWS click-tracking URL"
	case strings.Contains(h, "linktr.ee") || h == "bit.ly" || strings.HasSuffix(h, ".bit.ly") ||
		h == "t.co" || h == "tinyurl.com" || strings.Contains(h, "rebrand.ly"):
		return "URL shortener / link hub — destination may be opaque until followed"
	case strings.Contains(h, "app.link") || strings.Contains(h, "bnc.lt"):
		return "Branch app.link deep-link host"
	case strings.Contains(path, "/ls/click") || strings.Contains(path, "/wf/click"):
		return "email click-tracking path pattern"
	default:
		return ""
	}
}

func parseFragmentQuery(frag string) url.Values {
	frag = strings.TrimSpace(frag)
	frag = strings.TrimPrefix(frag, "?")
	if i := strings.IndexByte(frag, '?'); i >= 0 {
		frag = frag[i+1:]
	}
	v, err := url.ParseQuery(frag)
	if err != nil {
		return nil
	}
	return v
}

func truncateMid(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

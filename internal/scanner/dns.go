package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

// ResolveDNS performs concurrent lookups for common record types.
func ResolveDNS(ctx context.Context, host string, resolver *net.Resolver) *DNSResult {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	result := &DNSResult{}

	var mu sync.Mutex
	var wg sync.WaitGroup

	lookups := []struct {
		name string
		fn   func()
	}{
		{"a", func() {
			addrs, err := resolver.LookupIP(ctx, "ip4", host)
			if err != nil {
				return
			}
			mu.Lock()
			for _, a := range addrs {
				result.A = append(result.A, a.String())
			}
			mu.Unlock()
		}},
		{"aaaa", func() {
			addrs, err := resolver.LookupIP(ctx, "ip6", host)
			if err != nil {
				return
			}
			mu.Lock()
			for _, a := range addrs {
				result.AAAA = append(result.AAAA, a.String())
			}
			mu.Unlock()
		}},
		{"cname", func() {
			cname, err := resolver.LookupCNAME(ctx, host)
			if err != nil || cname == "" || strings.EqualFold(strings.TrimSuffix(cname, "."), host) {
				return
			}
			mu.Lock()
			result.CNAME = []string{strings.TrimSuffix(cname, ".")}
			mu.Unlock()
		}},
		{"mx", func() {
			mxs, err := resolver.LookupMX(ctx, host)
			if err != nil {
				return
			}
			mu.Lock()
			for _, mx := range mxs {
				h := strings.TrimSuffix(strings.TrimSpace(mx.Host), ".")
				if h == "" || h == "." {
					continue
				}
				result.MX = append(result.MX, h)
			}
			mu.Unlock()
		}},
		{"ns", func() {
			nss, err := resolver.LookupNS(ctx, host)
			if err != nil {
				return
			}
			mu.Lock()
			for _, ns := range nss {
				h := strings.TrimSuffix(strings.TrimSpace(ns.Host), ".")
				if h == "" {
					continue
				}
				result.NS = append(result.NS, h)
			}
			mu.Unlock()
		}},
		{"txt", func() {
			txts, err := resolver.LookupTXT(ctx, host)
			if err != nil {
				return
			}
			mu.Lock()
			for _, t := range txts {
				t = strings.TrimSpace(t)
				if t != "" {
					result.TXT = append(result.TXT, t)
				}
			}
			mu.Unlock()
		}},
	}

	wg.Add(len(lookups))
	for _, l := range lookups {
		go func(fn func()) {
			defer wg.Done()
			fn()
		}(l.fn)
	}
	wg.Wait()

	sort.Strings(result.A)
	sort.Strings(result.AAAA)
	sort.Strings(result.MX)
	sort.Strings(result.NS)
	return result
}

// DNSFindings extracts actionable signals from DNS records.
func DNSFindings(host string, dns *DNSResult) []Finding {
	if dns == nil {
		return nil
	}
	var findings []Finding

	if len(dns.A) == 0 && len(dns.AAAA) == 0 && len(dns.CNAME) == 0 {
		findings = append(findings, Finding{
			Severity: "info",
			Category: "dns",
			Message:  "no A/AAAA/CNAME records resolved",
		})
	}

	var (
		hasSPF        bool
		hasDMARC      bool
		verifyCount   int
		verifyVendors []string
	)
	seenVendor := map[string]struct{}{}

	for _, txt := range dns.TXT {
		lower := strings.ToLower(txt)
		switch {
		case strings.Contains(lower, "v=spf1"):
			hasSPF = true
			if strings.Contains(lower, "+all") {
				findings = append(findings, Finding{
					Severity: "high",
					Category: "dns",
					Message:  "SPF uses +all (permits any sender)",
				})
			}
		case strings.HasPrefix(lower, "v=dmarc1"):
			hasDMARC = true
		}

		vendor := verificationVendor(lower)
		if vendor != "" {
			verifyCount++
			if _, ok := seenVendor[vendor]; !ok {
				seenVendor[vendor] = struct{}{}
				verifyVendors = append(verifyVendors, vendor)
			}
		}
	}

	if hasSPF {
		findings = append(findings, Finding{
			Severity: "info",
			Category: "dns",
			Message:  "SPF record present",
		})
	}
	if hasDMARC {
		findings = append(findings, Finding{
			Severity: "info",
			Category: "dns",
			Message:  "DMARC policy advertised in TXT",
		})
	}
	if verifyCount > 0 {
		msg := fmt.Sprintf("%d domain verification token(s) in TXT", verifyCount)
		if len(verifyVendors) > 0 {
			msg += " (" + strings.Join(verifyVendors, ", ") + ")"
		}
		findings = append(findings, Finding{
			Severity: "info",
			Category: "dns",
			Message:  msg,
		})
	}

	if len(dns.MX) > 0 {
		findings = append(findings, Finding{
			Severity: "info",
			Category: "dns",
			Message:  fmt.Sprintf("mail infrastructure in scope (%d MX)", len(dns.MX)),
		})
	}

	_ = host
	return findings
}

func verificationVendor(lowerTXT string) string {
	switch {
	case strings.Contains(lowerTXT, "google-site-verification"):
		return "google"
	case strings.HasPrefix(lowerTXT, "ms=") || strings.Contains(lowerTXT, "ms="):
		// Avoid matching arbitrary "ms=" substrings in other TXT blobs.
		if strings.HasPrefix(lowerTXT, "ms=") {
			return "microsoft"
		}
		return ""
	case strings.Contains(lowerTXT, "facebook-domain-verification"):
		return "facebook"
	case strings.Contains(lowerTXT, "apple-domain-verification"):
		return "apple"
	case strings.Contains(lowerTXT, "docusign="):
		return "docusign"
	case strings.Contains(lowerTXT, "onetrust-domain-verification"):
		return "onetrust"
	case strings.Contains(lowerTXT, "cisco-ci-domain-verification"):
		return "cisco"
	case strings.Contains(lowerTXT, "atlassian-domain-verification"):
		return "atlassian"
	default:
		return ""
	}
}

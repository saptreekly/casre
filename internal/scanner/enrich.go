package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

// Enrich builds CDN / ASN / infrastructure hints from prior module results.
func Enrich(ctx context.Context, host string, dns *DNSResult, httpResults []HTTPResult, resolver *net.Resolver) *Enrichment {
	e := &Enrichment{}

	cdnSet := map[string]struct{}{}
	hintSet := map[string]struct{}{}

	addCDN := func(name string) {
		if name == "" {
			return
		}
		cdnSet[name] = struct{}{}
	}
	addHint := func(h string) {
		if h == "" {
			return
		}
		hintSet[h] = struct{}{}
	}

	if dns != nil {
		for _, ns := range dns.NS {
			if name := cdnFromName(ns); name != "" {
				addCDN(name)
			}
		}
		for _, cname := range dns.CNAME {
			if name := cdnFromName(cname); name != "" {
				addCDN(name)
			}
			if strings.Contains(strings.ToLower(cname), "amazonses") {
				addHint("email infra: Amazon SES")
			}
		}
		for _, mx := range dns.MX {
			lower := strings.ToLower(mx)
			switch {
			case strings.Contains(lower, "google.com"), strings.Contains(lower, "googlemail.com"):
				addHint("mail: Google Workspace")
			case strings.Contains(lower, "outlook.com"), strings.Contains(lower, "protection.outlook.com"):
				addHint("mail: Microsoft 365")
			case strings.Contains(lower, "pphosted.com"), strings.Contains(lower, "proofpoint"):
				addHint("mail: Proofpoint")
			case strings.Contains(lower, "mimecast"):
				addHint("mail: Mimecast")
			}
		}
	}

	for _, h := range httpResults {
		for _, t := range h.Technologies {
			if name := cdnFromTech(t); name != "" {
				addCDN(name)
			}
		}
		if s := strings.ToLower(h.Server); s != "" {
			if name := cdnFromName(s); name != "" {
				addCDN(name)
			}
		}
		for k, v := range h.Headers {
			lk := strings.ToLower(k)
			lv := strings.ToLower(v)
			switch {
			case lk == "cf-ray" || lk == "cf-cache-status":
				addCDN("cloudflare")
			case lk == "x-amz-cf-id" || strings.Contains(lv, "cloudfront"):
				addCDN("cloudfront")
			case lk == "x-served-by" && strings.Contains(lv, "cache-"):
				addCDN("fastly")
			case lk == "x-akamai-transformed" || strings.Contains(lk, "akamai"):
				addCDN("akamai")
			case lk == "x-vercel-id" || lk == "x-vercel-cache":
				addCDN("vercel")
			case lk == "x-github-request-id":
				addHint("hosting: GitHub Pages")
			case lk == "x-shopify-stage" || strings.Contains(lv, "shopify"):
				addHint("ecommerce: Shopify")
			}
		}
	}

	if dns != nil && len(dns.A) > 0 {
		e.ASN = lookupASNs(ctx, dns.A, resolver)
		for _, a := range e.ASN {
			if name := cdnFromName(a.ASName); name != "" {
				addCDN(name)
			}
		}
	}

	for name := range cdnSet {
		e.CDN = append(e.CDN, name)
	}
	sort.Strings(e.CDN)
	for h := range hintSet {
		e.Hints = append(e.Hints, h)
	}
	sort.Strings(e.Hints)

	_ = host
	if len(e.CDN) == 0 && len(e.ASN) == 0 && len(e.Hints) == 0 {
		return nil
	}
	return e
}

func cdnFromName(s string) string {
	lower := strings.ToLower(s)
	switch {
	case strings.Contains(lower, "cloudflare"):
		return "cloudflare"
	case strings.Contains(lower, "cloudfront"):
		return "cloudfront"
	case strings.Contains(lower, "fastly"):
		return "fastly"
	case strings.Contains(lower, "akamai"), strings.Contains(lower, "edgekey"), strings.Contains(lower, "edgesuite"):
		return "akamai"
	case strings.Contains(lower, "incapsula"), strings.Contains(lower, "imperva"):
		return "imperva"
	case strings.Contains(lower, "sucuri"):
		return "sucuri"
	case strings.Contains(lower, "stackpath"), strings.Contains(lower, "highwinds"):
		return "stackpath"
	case strings.Contains(lower, "azureedge"):
		return "azure"
	case strings.Contains(lower, "1e100.net"), strings.Contains(lower, "googleusercontent"):
		return "google"
	case strings.Contains(lower, "vercel"):
		return "vercel"
	case strings.Contains(lower, "netlify"):
		return "netlify"
	default:
		return ""
	}
}

func cdnFromTech(t string) string {
	lower := strings.ToLower(t)
	switch {
	case strings.Contains(lower, "cloudflare"):
		return "cloudflare"
	case strings.Contains(lower, "cloudfront"), strings.Contains(lower, "aws"):
		if strings.Contains(lower, "cloudfront") {
			return "cloudfront"
		}
	case strings.Contains(lower, "fastly"):
		return "fastly"
	case strings.Contains(lower, "vercel"):
		return "vercel"
	case strings.Contains(lower, "akamai"):
		return "akamai"
	}
	return ""
}

func lookupASNs(ctx context.Context, ips []string, resolver *net.Resolver) []ASNInfo {
	// Cap lookups for noisy multi-IP hosts.
	limit := len(ips)
	if limit > 3 {
		limit = 3
	}

	out := make([]ASNInfo, limit)
	var wg sync.WaitGroup
	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			out[idx] = lookupASN(ctx, ips[idx], resolver)
		}(i)
	}
	wg.Wait()

	var filtered []ASNInfo
	for _, a := range out {
		if a.ASN != "" || a.ASName != "" {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

// lookupASN uses Team Cymru's DNS interface (no API key).
// Query: reversed-ip.origin.asn.cymru.com TXT → "ASN | prefix | CC | registry | allocated"
// Then AS-name via AS{n}.asn.cymru.com TXT.
func lookupASN(ctx context.Context, ip string, resolver *net.Resolver) ASNInfo {
	info := ASNInfo{IP: ip}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return info
	}

	rev := reverseIPv4(ip)
	if rev == "" {
		return info
	}
	q := rev + ".origin.asn.cymru.com"
	txts, err := resolver.LookupTXT(ctx, q)
	if err != nil || len(txts) == 0 {
		return info
	}
	parts := splitCymru(txts[0])
	if len(parts) >= 1 {
		info.ASN = strings.TrimSpace(parts[0])
	}
	if len(parts) >= 2 {
		info.Prefix = strings.TrimSpace(parts[1])
	}
	if len(parts) >= 3 {
		info.CC = strings.TrimSpace(parts[2])
	}
	if len(parts) >= 4 {
		info.Registry = strings.TrimSpace(parts[3])
	}
	if len(parts) >= 5 {
		info.Allocated = strings.TrimSpace(parts[4])
	}

	if info.ASN != "" {
		asq := "AS" + info.ASN + ".asn.cymru.com"
		if names, err := resolver.LookupTXT(ctx, asq); err == nil && len(names) > 0 {
			np := splitCymru(names[0])
			if len(np) >= 1 {
				// Format: ASN | CC | registry | allocated | AS Name
				info.ASName = strings.TrimSpace(np[len(np)-1])
			}
		}
	}
	return info
}

func reverseIPv4(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
}

func splitCymru(s string) []string {
	raw := strings.Split(s, "|")
	out := make([]string, len(raw))
	for i, p := range raw {
		out[i] = strings.TrimSpace(p)
	}
	return out
}

// EnrichFindings converts enrichment into findings.
func EnrichFindings(e *Enrichment) []Finding {
	if e == nil {
		return nil
	}
	var findings []Finding
	if len(e.CDN) > 0 {
		findings = append(findings, Finding{
			Severity: "info",
			Category: "enrich",
			Message:  "CDN/edge: " + strings.Join(e.CDN, ", "),
		})
	}
	for _, a := range e.ASN {
		msg := fmt.Sprintf("%s → AS%s", a.IP, a.ASN)
		if a.ASName != "" {
			msg += " " + a.ASName
		}
		if a.CC != "" {
			msg += " (" + a.CC + ")"
		}
		findings = append(findings, Finding{
			Severity: "info",
			Category: "enrich",
			Message:  msg,
		})
	}
	for _, h := range e.Hints {
		findings = append(findings, Finding{
			Severity: "info",
			Category: "enrich",
			Message:  h,
		})
	}
	return findings
}

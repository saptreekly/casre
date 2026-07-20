package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/jackweekly/casre/internal/scanner"
)

// Writer formats scan results.
type Writer interface {
	Write(r scanner.Result) error
	Flush() error
}

// JSONWriter emits one JSON object per result (NDJSON).
type JSONWriter struct {
	w   io.Writer
	enc *json.Encoder
}

// NewJSONWriter creates an NDJSON writer.
func NewJSONWriter(w io.Writer) *JSONWriter {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONWriter{w: w, enc: enc}
}

func (j *JSONWriter) Write(r scanner.Result) error {
	return j.enc.Encode(r)
}

func (j *JSONWriter) Flush() error { return nil }

// TextOptions controls human-readable formatting.
type TextOptions struct {
	Color   bool
	Verbose bool // full SAN lists and redirect hops
}

// TextWriter emits a colorized tree report per host.
type TextWriter struct {
	w   io.Writer
	c   palette
	opt TextOptions
}

// NewTextWriter creates a tree text writer.
func NewTextWriter(w io.Writer, opt TextOptions) *TextWriter {
	return &TextWriter{w: w, c: newPalette(opt.Color), opt: opt}
}

func (t *TextWriter) Write(r scanner.Result) error {
	var b strings.Builder
	c := t.c

	fmt.Fprintf(&b, "\n%s%s%s  %s%s%s\n",
		c.bold, r.Host, c.reset,
		c.dim, r.Duration, c.reset,
	)
	if r.RawInput != "" {
		fmt.Fprintf(&b, "%s%s%s\n", c.dim, truncateMiddle(r.RawInput, 88), c.reset)
	} else if r.InputURL != "" {
		fmt.Fprintf(&b, "%s%s%s\n", c.dim, truncateMiddle(r.InputURL, 88), c.reset)
	}

	sections := collectSections(r, t.opt.Verbose)
	for si, sec := range sections {
		lastSec := si == len(sections)-1
		fmt.Fprintf(&b, "%s%s%s\n", c.section, sec.title, c.reset)

		// Precompute which top-level rows are last among top-level siblings.
		topLast := map[int]bool{}
		var topIdx []int
		for i, line := range sec.lines {
			if !line.child {
				topIdx = append(topIdx, i)
			}
		}
		for ti, idx := range topIdx {
			topLast[idx] = ti == len(topIdx)-1
		}

		parentIsLast := false
		for i, line := range sec.lines {
			if !line.child {
				parentIsLast = topLast[i]
			}
			var last bool
			if line.child {
				last = i == len(sec.lines)-1 || !sec.lines[i+1].child
			} else {
				last = topLast[i]
			}
			prefix, _ := treePrefix(last)
			guide := "│  "
			if line.child && parentIsLast {
				guide = "   "
			}
			renderTreeLine(&b, c, prefix, guide, line)
		}
		if !lastSec {
			b.WriteByte('\n')
		}
	}

	_, err := io.WriteString(t.w, b.String())
	return err
}

func (t *TextWriter) Flush() error { return nil }

type section struct {
	title string
	lines []treeLine
}

type treeLine struct {
	key     string
	value   string
	cont    []string // continuation lines under value
	sev     string   // optional severity tint for value
	child   bool     // indent as nested under previous visual group
}

func collectSections(r scanner.Result, verbose bool) []section {
	var out []section

	if r.InputURL != "" || r.URLProbe != nil || r.RawInput != "" {
		var lines []treeLine
		display := r.RawInput
		if display == "" {
			display = r.InputURL
		}
		if display != "" {
			lines = append(lines, treeLine{key: "input", value: display, sev: "info"})
		}
		if r.Fragment != "" {
			sev := "info"
			if scanner.FragmentLooksLikeQuery(r.Fragment) {
				sev = "medium"
			}
			lines = append(lines, treeLine{
				key:   "fragment",
				value: "#" + r.Fragment,
				sev:   sev,
			})
			if scanner.FragmentLooksLikeQuery(r.Fragment) {
				lines = append(lines, treeLine{
					key:   "note",
					value: "fragment params are client-only — never sent to the server",
					sev:   "medium",
					child: true,
				})
			}
		}
		if r.InputURL != "" && r.RawInput != "" && r.InputURL != r.RawInput {
			lines = append(lines, treeLine{key: "wire", value: r.InputURL, sev: "info"})
		}
		if r.URLProbe != nil {
			p := r.URLProbe
			if p.Error != "" {
				lines = append(lines, treeLine{key: "error", value: p.Error, sev: "high"})
			} else {
				lines = append(lines, treeLine{
					key:   "status",
					value: fmt.Sprintf("%d", p.StatusCode),
					sev:   statusSeverity(p.StatusCode),
				})
				if p.FinalURL != "" && p.FinalURL != p.URL {
					lines = append(lines, treeLine{key: "final", value: p.FinalURL})
				}
				if r.FinalHost != "" {
					lines = append(lines, treeLine{
						key:   "finalhost",
						value: r.FinalHost,
						sev:   "medium",
					})
				}
				if p.Server != "" {
					lines = append(lines, treeLine{key: "server", value: p.Server})
				}
				if len(p.Redirects) > 1 {
					var hops []string
					for i, hop := range p.Redirects {
						mark := ""
						if hop.CrossDomain {
							mark = " ⚠ cross-domain"
						}
						status := ""
						if hop.StatusCode > 0 {
							status = fmt.Sprintf("[%d] ", hop.StatusCode)
						}
						hops = append(hops, fmt.Sprintf("%d. %s%s%s", i+1, status, hop.URL, mark))
					}
					lines = append(lines, treeLine{
						key:   "chain",
						value: fmt.Sprintf("%d hop(s)", p.RedirectCount),
						cont:  hops,
						sev:   "info",
					})
				} else {
					lines = append(lines, treeLine{key: "chain", value: "no redirects", sev: "ok"})
				}
			}
		}
		out = append(out, section{title: "URL", lines: lines})
	}

	if r.Page != nil {
		p := r.Page
		var lines []treeLine
		if p.Title != "" {
			lines = append(lines, treeLine{key: "title", value: p.Title, sev: "info"})
		}
		if p.OGTitle != "" && p.OGTitle != p.Title {
			lines = append(lines, treeLine{key: "og:title", value: p.OGTitle})
		}
		if p.ContentType != "" {
			lines = append(lines, treeLine{key: "type", value: fmt.Sprintf("%s · %d bytes", p.ContentType, p.Bytes)})
		}
		if p.CloudStorageHost {
			lines = append(lines, treeLine{key: "hosting", value: "cloud object storage", sev: "high"})
		}
		if p.Deepview != "" {
			lines = append(lines, treeLine{key: "deepview", value: p.Deepview, sev: "medium"})
		}
		if p.HasTurnstile {
			lines = append(lines, treeLine{key: "widget", value: "Cloudflare Turnstile", sev: "high"})
		}
		for _, b := range p.BrandImpersonation {
			lines = append(lines, treeLine{key: "brand", value: b, sev: "high"})
		}
		if len(p.JSRedirects) > 0 {
			lines = append(lines, treeLine{
				key:   "js-redir",
				value: p.JSRedirects[0],
				cont:  p.JSRedirects[1:],
				sev:   "high",
			})
		}
		if len(p.MetaRefresh) > 0 {
			lines = append(lines, treeLine{
				key:   "meta-ref",
				value: p.MetaRefresh[0],
				cont:  p.MetaRefresh[1:],
				sev:   "high",
			})
		}
		if len(p.Destinations) > 0 {
			show := p.Destinations
			if len(show) > 8 {
				show = show[:8]
			}
			lines = append(lines, treeLine{
				key:   "next-hop",
				value: show[0],
				cont:  show[1:],
				sev:   "high",
			})
		}
		if len(p.Downloads) > 0 {
			lines = append(lines, treeLine{
				key:   "download",
				value: p.Downloads[0],
				cont:  p.Downloads[1:],
				sev:   "high",
			})
		}
		if len(p.AppLinks) > 0 {
			cont := make([]string, 0, len(p.AppLinks)-1)
			for _, a := range p.AppLinks[1:] {
				cont = append(cont, truncateMiddle(a, 100))
			}
			lines = append(lines, treeLine{
				key:   "app-link",
				value: truncateMiddle(p.AppLinks[0], 100),
				cont:  cont,
				sev:   "medium",
			})
		}
		for _, s := range p.ExternalScripts {
			if strings.Contains(strings.ToLower(s), "turnstile") || strings.Contains(strings.ToLower(s), "cloudflare") {
				lines = append(lines, treeLine{key: "script", value: s, sev: "medium"})
			}
		}
		for _, img := range p.ExternalImages {
			if looksBrandish(img) {
				lines = append(lines, treeLine{key: "image", value: img, sev: "medium"})
			}
		}
		if p.HasPasswordField {
			lines = append(lines, treeLine{key: "password", value: "input field present", sev: "high"})
		}
		for _, f := range p.Forms {
			val := f.Method
			if f.Action != "" {
				val += " → " + f.Action
			}
			lines = append(lines, treeLine{key: "form", value: val, sev: "medium"})
		}
		if len(lines) > 0 {
			out = append(out, section{title: "PAGE", lines: lines})
		}
	}

	if r.Graph != nil && len(r.Graph.Nodes) > 0 {
		out = append(out, graphSection(r.Graph))
	}

	// Extra hops beyond the seed (seed is already shown in URL/PAGE).
	if len(r.Hops) > 1 {
		for i, hop := range r.Hops[1:] {
			var lines []treeLine
			lines = append(lines, treeLine{key: "url", value: hop.URL, sev: "info"})
			lines = append(lines, treeLine{key: "host", value: hop.Host})
			if hop.Probe != nil {
				if hop.Probe.Error != "" {
					lines = append(lines, treeLine{key: "error", value: hop.Probe.Error, sev: "high"})
				} else {
					lines = append(lines, treeLine{
						key:   "status",
						value: fmt.Sprintf("%d", hop.Probe.StatusCode),
						sev:   statusSeverity(hop.Probe.StatusCode),
					})
					if hop.Probe.FinalURL != "" && hop.Probe.FinalURL != hop.Probe.URL {
						lines = append(lines, treeLine{key: "final", value: hop.Probe.FinalURL})
					}
					if hop.Probe.Server != "" {
						lines = append(lines, treeLine{key: "server", value: hop.Probe.Server})
					}
				}
			}
			if hop.Page != nil {
				if hop.Page.Title != "" {
					lines = append(lines, treeLine{key: "title", value: hop.Page.Title})
				}
				if hop.Page.OGTitle != "" && hop.Page.OGTitle != hop.Page.Title {
					lines = append(lines, treeLine{key: "og:title", value: hop.Page.OGTitle})
				}
				if hop.Page.Deepview != "" {
					lines = append(lines, treeLine{key: "deepview", value: hop.Page.Deepview, sev: "medium"})
				}
				show := hop.Page.Destinations
				if len(show) > 6 {
					show = show[:6]
				}
				for _, d := range show {
					lines = append(lines, treeLine{key: "next-hop", value: d, sev: "high"})
				}
				for _, d := range hop.Page.Downloads {
					lines = append(lines, treeLine{key: "download", value: d, sev: "high"})
				}
				for _, a := range hop.Page.AppLinks {
					lines = append(lines, treeLine{key: "app-link", value: truncateMiddle(a, 100), sev: "medium"})
				}
				for _, b := range hop.Page.BrandImpersonation {
					lines = append(lines, treeLine{key: "brand", value: b, sev: "high"})
				}
			}
			title := fmt.Sprintf("HOP %d", i+1)
			out = append(out, section{title: title, lines: lines})
		}
	}

	if r.DNS != nil {
		var lines []treeLine
		lines = appendKV(lines, "A", r.DNS.A)
		lines = appendKV(lines, "AAAA", r.DNS.AAAA)
		lines = appendKV(lines, "CNAME", r.DNS.CNAME)
		lines = appendKV(lines, "MX", r.DNS.MX)
		lines = appendKV(lines, "NS", r.DNS.NS)
		lines = append(lines, txtLines(r.DNS.TXT, verbose)...)
		if len(lines) > 0 {
			out = append(out, section{title: "DNS", lines: lines})
		}
	}

	if r.TLS != nil {
		var lines []treeLine
		lines = append(lines, treeLine{key: "proto", value: r.TLS.Version})
		lines = append(lines, treeLine{key: "cipher", value: r.TLS.CipherSuite})
		if len(r.TLS.ALPN) > 0 {
			lines = append(lines, treeLine{key: "alpn", value: strings.Join(r.TLS.ALPN, ", ")})
		}
		if len(r.TLS.Chain) > 0 {
			leaf := r.TLS.Chain[0]
			lines = append(lines, treeLine{key: "leaf", value: shortDN(leaf.Subject)})
			lines = append(lines, treeLine{key: "issuer", value: shortDN(leaf.Issuer), child: true})
			lines = append(lines, treeLine{
				key:   "expires",
				value: expiryLabel(leaf.DaysUntilExp),
				sev:   expirySeverity(leaf.DaysUntilExp),
				child: true,
			})
			if len(leaf.DNSNames) > 0 {
				sanLine := treeLine{
					key:   "SANs",
					value: fmt.Sprintf("%d names", len(leaf.DNSNames)),
					child: true,
				}
				if verbose {
					sanLine.cont = wrapCSV(leaf.DNSNames, 70)
				} else if len(leaf.DNSNames) <= 6 {
					sanLine.cont = wrapCSV(leaf.DNSNames, 70)
				} else {
					preview := append([]string{}, leaf.DNSNames[:5]...)
					sanLine.cont = append(wrapCSV(preview, 70),
						fmt.Sprintf("… +%d more (use -v)", len(leaf.DNSNames)-5))
				}
				lines = append(lines, sanLine)
			}
			if len(r.TLS.Chain) > 1 {
				var chain []string
				for i := 1; i < len(r.TLS.Chain); i++ {
					c := r.TLS.Chain[i]
					chain = append(chain, fmt.Sprintf("%s → %s (%s)",
						shortDN(c.Subject), shortDN(c.Issuer), expiryLabel(c.DaysUntilExp)))
				}
				lines = append(lines, treeLine{key: "chain", value: chain[0], cont: chain[1:]})
			}
		}
		out = append(out, section{title: "TLS", lines: lines})
	}

	if len(r.Banners) > 0 {
		var lines []treeLine
		for _, banner := range r.Banners {
			svc := orDefault(banner.Service, "unknown")
			lines = append(lines, treeLine{
				key:   fmt.Sprintf("%d/%s", banner.Port, svc),
				value: cleanBanner(banner.Banner),
				sev:   "ok",
			})
		}
		out = append(out, section{title: "PORTS", lines: lines})
	}

	if len(r.HTTP) > 0 {
		var lines []treeLine
		for _, h := range r.HTTP {
			if h.Error != "" {
				lines = append(lines, treeLine{key: h.URL, value: h.Error, sev: "high"})
				continue
			}
			lines = append(lines, treeLine{
				key:   h.URL,
				value: fmt.Sprintf("%d", h.StatusCode),
				sev:   statusSeverity(h.StatusCode),
			})
			if h.FinalURL != "" && h.FinalURL != h.URL {
				lines = append(lines, treeLine{key: "final", value: h.FinalURL, child: true})
			}
			if len(h.Redirects) > 1 && verbose {
				var hops []string
				for i, hop := range h.Redirects {
					if hop.StatusCode > 0 {
						hops = append(hops, fmt.Sprintf("%d. [%d] %s", i+1, hop.StatusCode, hop.URL))
					} else {
						hops = append(hops, fmt.Sprintf("%d. %s", i+1, hop.URL))
					}
				}
				lines = append(lines, treeLine{
					key:   "chain",
					value: hops[0],
					cont:  hops[1:],
					child: true,
				})
			} else if h.RedirectCount > 0 {
				lines = append(lines, treeLine{
					key:   "redirects",
					value: fmt.Sprintf("%d hop(s)", h.RedirectCount),
					child: true,
				})
			}
			if h.Server != "" {
				lines = append(lines, treeLine{key: "server", value: h.Server, child: true})
			}
			if len(h.Technologies) > 0 {
				lines = append(lines, treeLine{key: "tech", value: strings.Join(h.Technologies, ", "), child: true})
			}
			if len(h.SecurityGaps) > 0 {
				lines = append(lines, treeLine{
					key:   "gaps",
					value: strings.Join(h.SecurityGaps, ", "),
					sev:   "medium",
					child: true,
				})
			} else {
				lines = append(lines, treeLine{key: "gaps", value: "none", sev: "ok", child: true})
			}
		}
		out = append(out, section{title: "HTTP", lines: lines})
	}

	if r.Enrich != nil {
		var lines []treeLine
		if len(r.Enrich.CDN) > 0 {
			lines = append(lines, treeLine{key: "CDN", value: strings.Join(r.Enrich.CDN, ", "), sev: "info"})
		}
		for i, a := range r.Enrich.ASN {
			label := "ASN"
			if i > 0 {
				label = "ASN"
			}
			val := fmt.Sprintf("AS%s %s", a.ASN, a.ASName)
			if a.CC != "" {
				val += " · " + a.CC
			}
			line := treeLine{key: label, value: strings.TrimSpace(val), sev: "info"}
			if verbose {
				line.cont = []string{fmt.Sprintf("%s  %s", a.IP, a.Prefix)}
			} else {
				line.value = fmt.Sprintf("%s · %s", a.IP, strings.TrimSpace(val))
			}
			lines = append(lines, line)
		}
		for _, h := range r.Enrich.Hints {
			lines = append(lines, treeLine{key: "hint", value: h, sev: "info"})
		}
		if len(lines) > 0 {
			out = append(out, section{title: "ENRICH", lines: lines})
		}
	}

	if len(r.Findings) > 0 {
		bySev := groupFindings(r.Findings)
		var lines []treeLine
		for _, sev := range []string{"high", "medium", "low", "info"} {
			items := bySev[sev]
			if len(items) == 0 {
				continue
			}
			// Default: collapse INFO findings unless verbose.
			if sev == "info" && !verbose {
				lines = append(lines, treeLine{
					key:   "INFO",
					value: fmt.Sprintf("%d (use -v to expand)", len(items)),
					sev:   sev,
				})
				continue
			}
			lines = append(lines, treeLine{
				key:   strings.ToUpper(sev),
				value: fmt.Sprintf("%d", len(items)),
				sev:   sev,
			})
			for _, f := range items {
				lines = append(lines, treeLine{
					key:   f.Category,
					value: f.Message,
					sev:   sev,
					child: true,
				})
			}
		}
		out = append(out, section{title: "FINDINGS", lines: lines})
	}

	if len(r.Errors) > 0 {
		var lines []treeLine
		for _, e := range r.Errors {
			lines = append(lines, treeLine{key: "error", value: e, sev: "high"})
		}
		out = append(out, section{title: "ERRORS", lines: lines})
	}

	return out
}

func appendKV(lines []treeLine, key string, vals []string) []treeLine {
	if len(vals) == 0 {
		return lines
	}
	return append(lines, treeLine{key: key, value: vals[0], cont: vals[1:]})
}

func txtLines(txts []string, verbose bool) []treeLine {
	if len(txts) == 0 {
		return nil
	}
	var spf, dmarc, other []string
	vendors := map[string]int{}
	for _, raw := range txts {
		lower := strings.ToLower(raw)
		switch {
		case strings.Contains(lower, "v=spf1"):
			spf = append(spf, raw)
		case strings.HasPrefix(lower, "v=dmarc1"):
			dmarc = append(dmarc, raw)
		default:
			if v := txtVendor(lower); v != "" {
				vendors[v]++
				continue
			}
			other = append(other, truncateMiddle(raw, 78))
		}
	}

	lines := []treeLine{{key: "TXT", value: fmt.Sprintf("%d records", len(txts))}}
	for _, s := range spf {
		lines = append(lines, treeLine{key: "SPF", value: s, child: true})
	}
	for _, s := range dmarc {
		lines = append(lines, treeLine{key: "DMARC", value: s, child: true})
	}
	if len(vendors) > 0 {
		names := make([]string, 0, len(vendors))
		total := 0
		for v := range vendors {
			names = append(names, v)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, v := range names {
			n := vendors[v]
			total += n
			if n > 1 {
				parts = append(parts, fmt.Sprintf("%s×%d", v, n))
			} else {
				parts = append(parts, v)
			}
		}
		lines = append(lines, treeLine{
			key:   "verify",
			value: fmt.Sprintf("%d tokens (%s)", total, strings.Join(parts, ", ")),
			child: true,
		})
	}
	if len(other) > 0 {
		if !verbose && len(other) > 3 {
			shown := other[:3]
			lines = append(lines, treeLine{
				key:   "other",
				value: shown[0],
				cont:  append(shown[1:], fmt.Sprintf("… +%d more (use -v)", len(other)-3)),
				child: true,
			})
		} else {
			lines = append(lines, treeLine{key: "other", value: other[0], cont: other[1:], child: true})
		}
	}
	return lines
}

func treePrefix(last bool) (branch, pad string) {
	if last {
		return "└─ ", "   "
	}
	return "├─ ", "│  "
}

func renderTreeLine(b *strings.Builder, c palette, branch, guide string, line treeLine) {
	indent := ""
	keyWidth := 8
	if line.child {
		indent = guide
	} else if len(line.key) > keyWidth {
		keyWidth = len(line.key)
		if keyWidth > 40 {
			keyWidth = 40
		}
	}

	key := line.key
	if len(key) > 40 {
		key = truncateMiddle(key, 40)
	}

	valColor := c.value
	switch line.sev {
	case "high":
		valColor = c.high
	case "medium":
		valColor = c.medium
	case "low":
		valColor = c.low
	case "info":
		valColor = c.info
	case "ok":
		valColor = c.ok
	}

	fmt.Fprintf(b, "%s%s%s%s%s%-*s%s %s%s%s\n",
		c.dim, indent, branch, c.reset,
		c.dim, keyWidth, key, c.reset,
		valColor, line.value, c.reset,
	)

	contGuide := indent
	if !line.child {
		if branch == "└─ " {
			contGuide = "   "
		} else {
			contGuide = "│  "
		}
	}
	// Align wrapped values under the first value column.
	contPad := contGuide + strings.Repeat(" ", len([]rune(branch))+keyWidth+1)
	for _, extra := range line.cont {
		fmt.Fprintf(b, "%s%s%s%s\n", c.dim, contPad, c.reset, extra)
	}
}

type palette struct {
	bold, dim, section, value, reset string
	high, medium, low, info, ok      string
}

func newPalette(color bool) palette {
	if !color {
		return palette{}
	}
	return palette{
		bold:    "\033[1m",
		dim:     "\033[2m",
		section: "\033[1;36m", // bold cyan
		value:   "\033[0m",
		reset:   "\033[0m",
		high:    "\033[1;31m", // bold red
		medium:  "\033[1;33m", // bold yellow
		low:     "\033[33m",   // yellow
		info:    "\033[36m",   // cyan
		ok:      "\033[32m",   // green
	}
}

// EnableColor returns whether stdout should use color.
func EnableColor(forceOff, forceOn bool) bool {
	if forceOff || os.Getenv("NO_COLOR") != "" {
		return false
	}
	if forceOn {
		return true
	}
	if os.Getenv("CLICOLOR_FORCE") == "1" || os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	stat, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func txtVendor(lower string) string {
	switch {
	case strings.Contains(lower, "google-site-verification"):
		return "google"
	case strings.HasPrefix(lower, "ms="):
		return "microsoft"
	case strings.Contains(lower, "facebook-domain-verification"):
		return "facebook"
	case strings.Contains(lower, "apple-domain-verification"):
		return "apple"
	case strings.Contains(lower, "docusign="):
		return "docusign"
	case strings.Contains(lower, "onetrust-domain-verification"):
		return "onetrust"
	case strings.Contains(lower, "cisco-ci-domain-verification"):
		return "cisco"
	case strings.Contains(lower, "atlassian-domain-verification"):
		return "atlassian"
	case strings.Contains(lower, "work-accounts-domain-verification"):
		return "google-work"
	default:
		return ""
	}
}

func wrapCSV(items []string, width int) []string {
	if len(items) == 0 {
		return nil
	}
	var lines []string
	line := ""
	for i, item := range items {
		chunk := item
		if i < len(items)-1 {
			chunk += ", "
		}
		if len(line)+len(chunk) > width && line != "" {
			lines = append(lines, strings.TrimRight(line, " "))
			line = ""
		}
		line += chunk
	}
	if strings.TrimSpace(line) != "" {
		lines = append(lines, strings.TrimRight(line, " "))
	}
	return lines
}

func groupFindings(findings []scanner.Finding) map[string][]scanner.Finding {
	out := map[string][]scanner.Finding{}
	for _, f := range findings {
		sev := strings.ToLower(f.Severity)
		out[sev] = append(out[sev], f)
	}
	for sev := range out {
		sort.SliceStable(out[sev], func(i, j int) bool {
			if out[sev][i].Category != out[sev][j].Category {
				return out[sev][i].Category < out[sev][j].Category
			}
			return out[sev][i].Message < out[sev][j].Message
		})
	}
	return out
}

func shortDN(dn string) string {
	parts := strings.Split(dn, ",")
	var cn, org string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		upper := strings.ToUpper(p)
		switch {
		case strings.HasPrefix(upper, "CN="):
			cn = p[3:]
		case strings.HasPrefix(upper, "O="):
			org = p[2:]
		}
	}
	switch {
	case cn != "" && org != "":
		return cn + " (" + org + ")"
	case cn != "":
		return cn
	default:
		return truncateMiddle(dn, 72)
	}
}

func expiryLabel(days int) string {
	switch {
	case days < 0:
		return fmt.Sprintf("EXPIRED (%d days ago)", -days)
	case days == 0:
		return "today"
	case days == 1:
		return "in 1 day"
	default:
		return fmt.Sprintf("in %d days", days)
	}
}

func expirySeverity(days int) string {
	switch {
	case days < 0:
		return "high"
	case days <= 14:
		return "medium"
	case days <= 30:
		return "low"
	default:
		return "ok"
	}
}

func statusSeverity(code int) string {
	switch {
	case code >= 500:
		return "high"
	case code >= 400:
		return "medium"
	case code >= 300:
		return "info"
	default:
		return "ok"
	}
}

func cleanBanner(s string) string {
	if s == "" {
		return "open, no banner"
	}
	if s == "[tls-wrapped]" {
		return "tls"
	}
	s = strings.ReplaceAll(s, "\\r\\n", " | ")
	s = strings.ReplaceAll(s, "\\n", " | ")
	s = strings.ReplaceAll(s, "\\r", "")
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.Index(s, " | "); i > 0 {
		first := s[:i]
		upper := strings.ToUpper(first)
		if strings.Contains(upper, "HTTP/") ||
			strings.HasPrefix(first, "SSH-") ||
			strings.HasPrefix(first, "220") ||
			strings.HasPrefix(first, "221") {
			rest := s[i+3:]
			if loc := extractLocation(rest); loc != "" {
				return first + " → " + loc
			}
			return truncateMiddle(first, 72)
		}
	}
	return truncateMiddle(s, 72)
}

func extractLocation(s string) string {
	lower := strings.ToLower(s)
	idx := strings.Index(lower, "location:")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(s[idx+len("location:"):])
	if i := strings.Index(rest, " | "); i >= 0 {
		rest = rest[:i]
	}
	return strings.TrimSpace(rest)
}

func truncateMiddle(s string, max int) string {
	if max < 8 || len(s) <= max {
		return s
	}
	keep := max - 1
	left := keep / 2
	right := keep - left
	return s[:left] + "…" + s[len(s)-right:]
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func looksBrandish(u string) bool {
	l := strings.ToLower(u)
	return strings.Contains(l, "logo") || strings.Contains(l, "cloudflare") ||
		strings.Contains(l, "microsoft") || strings.Contains(l, "apple") ||
		strings.Contains(l, "paypal") || strings.Contains(l, "1000logos")
}

func graphSection(g *scanner.AttackGraph) section {
	var lines []treeLine
	lines = append(lines, treeLine{
		key:   "size",
		value: fmt.Sprintf("%d nodes · %d edges", len(g.Nodes), len(g.Edges)),
		sev:   "info",
	})

	outEdges := map[string][]scanner.GraphEdge{}
	for _, e := range g.Edges {
		outEdges[e.From] = append(outEdges[e.From], e)
	}

	// Short labels for display.
	label := map[string]string{}
	for i, n := range g.Nodes {
		label[n.ID] = fmt.Sprintf("n%d", i+1)
	}

	for i, n := range g.Nodes {
		tag := ""
		if n.Seed {
			tag = "seed"
		} else if n.Terminal {
			tag = "terminal"
		}
		head := truncateMiddle(n.URL, 72)
		if n.Title != "" {
			head = fmt.Sprintf("%s · %q", head, truncateMiddle(n.Title, 32))
		}
		if n.StatusCode > 0 {
			head = fmt.Sprintf("[%d] %s", n.StatusCode, head)
		}
		if tag != "" {
			head = fmt.Sprintf("(%s) %s", tag, head)
		}
		sev := ""
		if n.Terminal && !n.Seed {
			sev = "high"
		}
		key := fmt.Sprintf("n%d", i+1)
		line := treeLine{key: key, value: head, sev: sev}

		var cont []string
		for _, e := range outEdges[n.ID] {
			to := e.To
			if lb, ok := label[e.To]; ok {
				to = lb + " " + truncateMiddle(e.To, 56)
			}
			cont = append(cont, fmt.Sprintf("─[%s]→ %s", e.Via, to))
		}
		line.cont = cont
		lines = append(lines, line)
	}

	return section{title: "GRAPH", lines: lines}
}

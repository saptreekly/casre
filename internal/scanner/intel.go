package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// IntelReport holds keyless external intelligence for a target host.
type IntelReport struct {
	Host          string        `json:"host"`
	RegDomain     string        `json:"reg_domain,omitempty"`
	Domain        *DomainIntel  `json:"domain,omitempty"`
	CTSiblings    []string      `json:"ct_siblings,omitempty"` // sibling hostnames from CT logs
	CTTotal       int           `json:"ct_total,omitempty"`    // total sibling names before truncation
	Favicon       *FaviconIntel `json:"favicon,omitempty"`
	CampaignPeers []string      `json:"campaign_peers,omitempty"` // other scanned hosts in same cluster
	Reputation    []string      `json:"reputation,omitempty"`     // opt-in VT/urlscan/Shodan notes
}

// DomainIntel is registration metadata from RDAP.
type DomainIntel struct {
	Registrar   string    `json:"registrar,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	AgeDays     int       `json:"age_days,omitempty"`
	Nameservers []string  `json:"nameservers,omitempty"`
	Statuses    []string  `json:"statuses,omitempty"`
}

// FaviconIntel is a Shodan-style favicon fingerprint for pivoting.
type FaviconIntel struct {
	MMH3   int32  `json:"mmh3"`
	Sha256 string `json:"sha256,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
	URL    string `json:"url,omitempty"`
}

// RegistrableDomain returns the eTLD+1 for a host (e.g. login.evil.co.uk → evil.co.uk).
func RegistrableDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// GatherIntel runs keyless external intel for a host: RDAP domain age, CT siblings,
// and (if faviconBody is supplied) a favicon fingerprint. Bounded by ctx + rate limiter.
func GatherIntel(ctx context.Context, host string, timeout time.Duration, wait func() error, favicon *FaviconIntel) *IntelReport {
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}
	reg := RegistrableDomain(host)
	if reg == "" {
		return nil
	}
	rep := &IntelReport{Host: host, RegDomain: reg, Favicon: favicon}

	if wait != nil {
		_ = wait()
	}
	if d := fetchRDAP(ctx, reg, timeout); d != nil {
		rep.Domain = d
	}

	if wait != nil {
		_ = wait()
	}
	if sibs, total := fetchCTSiblings(ctx, reg, timeout); len(sibs) > 0 {
		rep.CTSiblings = sibs
		rep.CTTotal = total
	}

	if rep.Domain == nil && len(rep.CTSiblings) == 0 && rep.Favicon == nil {
		return nil
	}
	return rep
}

func intelHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 6 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// --- RDAP (keyless, standardized JSON) ---

type rdapResponse struct {
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities    []rdapEntity `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	Status []string `json:"status"`
}

type rdapEntity struct {
	Roles      []string        `json:"roles"`
	VCardArray json.RawMessage `json:"vcardArray"`
}

func fetchRDAP(ctx context.Context, regDomain string, timeout time.Duration) *DomainIntel {
	url := "https://rdap.org/domain/" + regDomain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "CASRE/1.0 (+recon; authorized-use-only)")
	resp, err := intelHTTPClient(timeout).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}
	return parseRDAP(body)
}

func parseRDAP(body []byte) *DomainIntel {
	var r rdapResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil
	}
	d := &DomainIntel{}
	for _, e := range r.Events {
		t := parseRDAPTime(e.Date)
		if t.IsZero() {
			continue
		}
		switch strings.ToLower(e.Action) {
		case "registration":
			d.CreatedAt = t
		case "last changed", "last update of rdap database":
			if e.Date != "" && strings.EqualFold(e.Action, "last changed") {
				d.UpdatedAt = t
			}
		case "expiration":
			d.ExpiresAt = t
		}
	}
	if !d.CreatedAt.IsZero() {
		d.AgeDays = int(time.Since(d.CreatedAt).Hours() / 24)
	}
	for _, ns := range r.Nameservers {
		if ns.LDHName != "" {
			d.Nameservers = appendUnique(d.Nameservers, strings.ToLower(ns.LDHName))
		}
	}
	for _, s := range r.Status {
		d.Statuses = appendUnique(d.Statuses, s)
	}
	d.Registrar = rdapRegistrar(r.Entities)

	if d.CreatedAt.IsZero() && d.Registrar == "" && len(d.Nameservers) == 0 {
		return nil
	}
	return d
}

func rdapRegistrar(entities []rdapEntity) string {
	for _, e := range entities {
		isRegistrar := false
		for _, role := range e.Roles {
			if strings.EqualFold(role, "registrar") {
				isRegistrar = true
				break
			}
		}
		if !isRegistrar {
			continue
		}
		if name := vcardFullName(e.VCardArray); name != "" {
			return name
		}
	}
	return ""
}

// vcardFullName pulls the "fn" value out of a jCard array: ["vcard", [ [ "fn", {}, "text", "Name" ], ... ] ]
func vcardFullName(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if err := json.Unmarshal(arr[1], &props); err != nil {
		return ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var key string
		if err := json.Unmarshal(p[0], &key); err != nil || !strings.EqualFold(key, "fn") {
			continue
		}
		var val string
		if err := json.Unmarshal(p[3], &val); err == nil && val != "" {
			return val
		}
	}
	return ""
}

func parseRDAPTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02T15:04:05.000Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// --- Certificate Transparency siblings (crt.sh JSON, keyless) ---

type crtEntry struct {
	NameValue string `json:"name_value"`
}

func fetchCTSiblings(ctx context.Context, regDomain string, timeout time.Duration) ([]string, int) {
	url := "https://crt.sh/?q=%25." + regDomain + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CASRE/1.0 (+recon; authorized-use-only)")
	// crt.sh can be slow; give it a little more room but stay bounded.
	ctSh := intelHTTPClient(timeout * 3)
	resp, err := ctSh.Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return nil, 0
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, 0
	}
	return parseCTSiblings(body, regDomain)
}

func parseCTSiblings(body []byte, regDomain string) ([]string, int) {
	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, 0
	}
	set := map[string]struct{}{}
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || strings.ContainsAny(name, " @") {
				continue
			}
			if net.ParseIP(name) != nil {
				continue
			}
			if !strings.HasSuffix(name, regDomain) {
				continue
			}
			if name == regDomain {
				continue
			}
			set[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	total := len(out)
	const cap = 25
	if len(out) > cap {
		out = out[:cap]
	}
	return out, total
}

// --- Favicon fingerprint (Shodan-style mmh3 of base64) ---

// FetchFavicon downloads a favicon and returns its fingerprint.
func FetchFavicon(ctx context.Context, faviconURL string, timeout time.Duration, insecure bool) *FaviconIntel {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, faviconURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; CASRE/1.0; +recon)")
	req.Header.Set("Accept", "image/x-icon,image/*,*/*;q=0.8")
	resp, err := intelHTTPClient(timeout).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil || len(body) == 0 {
		return nil
	}
	fi := FaviconHash(body)
	fi.URL = faviconURL
	return fi
}

// faviconURLFor builds the best-guess favicon URL for a result, preferring the
// scheme of an observed final/probe URL and falling back to https.
func faviconURLFor(r Result, host string) string {
	if host == "" {
		return ""
	}
	scheme := "https"
	for _, u := range []string{r.FinalHost, r.InputURL} {
		if strings.HasPrefix(strings.ToLower(u), "http://") {
			scheme = "http"
			break
		}
	}
	if r.URLProbe != nil && strings.HasPrefix(strings.ToLower(r.URLProbe.FinalURL), "http://") {
		scheme = "http"
	}
	return scheme + "://" + host + "/favicon.ico"
}

// FaviconHash computes the Shodan favicon hash: mmh3 of the standard-base64
// (line-wrapped every 76 chars, trailing newline) of the raw bytes.
func FaviconHash(body []byte) *FaviconIntel {
	if len(body) == 0 {
		return nil
	}
	b64 := base64WithNewlines(body)
	h := murmur3Hash32([]byte(b64))
	return &FaviconIntel{
		MMH3:   int32(h),
		Sha256: sha256Hex(body),
		Bytes:  len(body),
	}
}

func base64WithNewlines(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	return b.String()
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:])
}

// IntelFindings converts intel into analyst findings.
func IntelFindings(rep *IntelReport) []Finding {
	if rep == nil {
		return nil
	}
	var out []Finding
	if d := rep.Domain; d != nil {
		if !d.CreatedAt.IsZero() {
			sev := "info"
			switch {
			case d.AgeDays <= 7:
				sev = "high"
			case d.AgeDays <= 30:
				sev = "medium"
			case d.AgeDays <= 90:
				sev = "low"
			}
			msg := fmt.Sprintf("domain age: %d day(s), registered %s", d.AgeDays, d.CreatedAt.Format("2006-01-02"))
			if d.Registrar != "" {
				msg += " via " + d.Registrar
			}
			out = append(out, Finding{Severity: sev, Category: "intel", Message: msg})
		} else if d.Registrar != "" {
			out = append(out, Finding{Severity: "info", Category: "intel", Message: "registrar: " + d.Registrar})
		}
	}
	if len(rep.CTSiblings) > 0 {
		shown := rep.CTSiblings
		if len(shown) > 8 {
			shown = shown[:8]
		}
		msg := fmt.Sprintf("%d CT sibling host(s): %s", rep.CTTotal, strings.Join(shown, ", "))
		if rep.CTTotal > len(shown) {
			msg += fmt.Sprintf(" (+%d more)", rep.CTTotal-len(shown))
		}
		sev := "info"
		if rep.CTTotal >= 10 {
			sev = "low"
		}
		out = append(out, Finding{Severity: sev, Category: "intel", Message: msg})
	}
	if rep.Favicon != nil {
		out = append(out, Finding{
			Severity: "info",
			Category: "intel",
			Message:  fmt.Sprintf("favicon mmh3=%d (pivot: Shodan http.favicon.hash:%d)", rep.Favicon.MMH3, rep.Favicon.MMH3),
		})
	}
	for _, note := range rep.Reputation {
		out = append(out, Finding{Severity: "medium", Category: "intel", Message: note})
	}
	return out
}

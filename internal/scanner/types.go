package scanner

import (
	"time"
)

// Result aggregates all findings for one target.
type Result struct {
	Host      string       `json:"host"`
	InputURL  string       `json:"input_url,omitempty"`  // wire URL probed
	RawInput  string       `json:"raw_input,omitempty"`  // original analyst paste
	Fragment  string       `json:"fragment,omitempty"`   // #... client-only part
	ScannedAt time.Time    `json:"scanned_at"`
	URLProbe  *HTTPResult   `json:"url_probe,omitempty"`
	Page      *PageAnalysis `json:"page,omitempty"`
	Graph     *AttackGraph  `json:"graph,omitempty"`
	Hops      []HopDetail   `json:"hops,omitempty"`
	FinalHost string        `json:"final_host,omitempty"` // redirects / JS destinations leave InputURL host
	DNS       *DNSResult   `json:"dns,omitempty"`
	TLS       *TLSResult   `json:"tls,omitempty"`
	Banners   []Banner     `json:"banners,omitempty"`
	HTTP      []HTTPResult `json:"http,omitempty"`
	Enrich    *Enrichment  `json:"enrichment,omitempty"`
	Findings  []Finding    `json:"findings,omitempty"`
	Errors    []string     `json:"errors,omitempty"`
	Duration  string       `json:"duration"`
}

// Finding is an actionable OSINT / security observation.
type Finding struct {
	Severity string `json:"severity"` // info, low, medium, high
	Category string `json:"category"`
	Message  string `json:"message"`
}

// DNSResult holds resolved DNS records.
type DNSResult struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME []string `json:"cname,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
}

// CertInfo describes a single certificate in the chain.
type CertInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	DNSNames     []string  `json:"dns_names,omitempty"`
	SerialNumber string    `json:"serial_number"`
	IsCA         bool      `json:"is_ca"`
	DaysUntilExp int       `json:"days_until_expiry"`
}

// TLSResult holds TLS handshake and certificate chain data.
type TLSResult struct {
	Version     string     `json:"version"`
	CipherSuite string     `json:"cipher_suite"`
	ServerName  string     `json:"server_name"`
	Chain       []CertInfo `json:"chain,omitempty"`
	ALPN        []string   `json:"alpn,omitempty"`
}

// Banner is a TCP banner grab result.
type Banner struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Error   string `json:"error,omitempty"`
}

// RedirectHop is one step in an HTTP redirect chain.
type RedirectHop struct {
	URL         string `json:"url"`
	Host        string `json:"host,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
	CrossDomain bool   `json:"cross_domain,omitempty"`
}

// HTTPResult holds an HTTP(S) header audit or URL probe.
type HTTPResult struct {
	URL           string            `json:"url"`
	StatusCode    int               `json:"status_code"`
	FinalURL      string            `json:"final_url,omitempty"`
	FinalHost     string            `json:"final_host,omitempty"`
	Redirects     []RedirectHop     `json:"redirects,omitempty"`
	Server        string            `json:"server,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	SecurityGaps  []string          `json:"security_gaps,omitempty"`
	Technologies  []string          `json:"technologies,omitempty"`
	ContentLength int64             `json:"content_length,omitempty"`
	RedirectCount int               `json:"redirect_count"`
	Error         string            `json:"error,omitempty"`
	Page          *PageAnalysis     `json:"page,omitempty"`
}

// ASNInfo is an IP→ASN mapping (via Team Cymru DNS).
type ASNInfo struct {
	IP        string `json:"ip"`
	ASN       string `json:"asn,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	CC        string `json:"cc,omitempty"`
	Registry  string `json:"registry,omitempty"`
	Allocated string `json:"allocated,omitempty"`
	ASName    string `json:"as_name,omitempty"`
}

// Enrichment holds derived infrastructure intel.
type Enrichment struct {
	CDN   []string  `json:"cdn,omitempty"`
	ASN   []ASNInfo `json:"asn,omitempty"`
	Hints []string  `json:"hints,omitempty"`
}

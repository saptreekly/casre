package scanner

import (
	"sort"
	"strings"
)

// MitreRef is a MITRE ATT&CK technique linked to a finding.
// Confidence reflects how directly CASRE evidence supports the technique
// (CASRE observes pre-compromise infrastructure / lure behavior, not post-exploit TTPs).
type MitreRef struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Tactic     string `json:"tactic"`
	Confidence string `json:"confidence,omitempty"` // high, medium, low
}

// MitreHit is a deduped technique rollup for a scan result.
type MitreHit struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Tactic     string `json:"tactic"`
	Confidence string `json:"confidence,omitempty"`
	Count      int    `json:"count"`
}

type mitreTech struct {
	id, name, tactic string
}

// Local ATT&CK subset relevant to recon / phishing chains.
var mitreCatalog = map[string]mitreTech{
	"T1566":     {id: "T1566", name: "Phishing", tactic: "Initial Access"},
	"T1566.002": {id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access"},
	"T1204":     {id: "T1204", name: "User Execution", tactic: "Execution"},
	"T1204.001": {id: "T1204.001", name: "Malicious Link", tactic: "Execution"},
	"T1036":     {id: "T1036", name: "Masquerading", tactic: "Defense Evasion"},
	"T1036.005": {id: "T1036.005", name: "Match Legitimate Name or Location", tactic: "Defense Evasion"},
	"T1656":     {id: "T1656", name: "Impersonation", tactic: "Defense Evasion"},
	"T1583":     {id: "T1583", name: "Acquire Infrastructure", tactic: "Resource Development"},
	"T1583.001": {id: "T1583.001", name: "Domains", tactic: "Resource Development"},
	"T1583.006": {id: "T1583.006", name: "Web Services", tactic: "Resource Development"},
	"T1584":     {id: "T1584", name: "Compromise Infrastructure", tactic: "Resource Development"},
	"T1608":     {id: "T1608", name: "Stage Capabilities", tactic: "Resource Development"},
	"T1608.001": {id: "T1608.001", name: "Upload Malware", tactic: "Resource Development"},
	"T1608.005": {id: "T1608.005", name: "Link Target", tactic: "Resource Development"},
	"T1102":     {id: "T1102", name: "Web Service", tactic: "Command and Control"},
	"T1027":     {id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion"},
	"T1056.003": {id: "T1056.003", name: "Web Portal Capture", tactic: "Collection"},
	"T1557":     {id: "T1557", name: "Adversary-in-the-Middle", tactic: "Credential Access"},
	"T1189":     {id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access"},
	"T1071.001": {id: "T1071.001", name: "Web Protocols", tactic: "Command and Control"},
	"T1190":     {id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access"},
	"T1040":     {id: "T1040", name: "Network Sniffing", tactic: "Credential Access"},
}

type mitreRule struct {
	category string // empty = any
	contains []string
	ids      []string
	conf     string
}

// Rules are evaluated in order; first match wins per technique id (merged across rules).
var mitreRules = []mitreRule{
	{category: "phish", contains: []string{"cloud object storage"}, ids: []string{"T1583.006", "T1608.001", "T1566.002"}, conf: "high"},
	{category: "phish", contains: []string{"brand impersonation"}, ids: []string{"T1656", "T1036.005", "T1566.002"}, conf: "high"},
	{category: "phish", contains: []string{"phishing kit fingerprint"}, ids: []string{"T1608.001", "T1566.002", "T1204.001"}, conf: "high"},
	{category: "phish", contains: []string{"turnstile", "fake browser check"}, ids: []string{"T1656", "T1036.005", "T1566.002"}, conf: "high"},
	{category: "phish", contains: []string{"interstitial", "browser-check"}, ids: []string{"T1656", "T1036.005"}, conf: "medium"},
	{category: "phish", contains: []string{"js/meta redirect", "meta refresh"}, ids: []string{"T1566.002", "T1204.001", "T1608.005"}, conf: "high"},
	{category: "phish", contains: []string{"external destination", "embedded campaign"}, ids: []string{"T1566.002", "T1608.005"}, conf: "medium"},
	{category: "phish", contains: []string{"password input"}, ids: []string{"T1056.003", "T1566.002"}, conf: "high"},
	{category: "phish", contains: []string{"form posts off-site"}, ids: []string{"T1056.003", "T1566.002", "T1102"}, conf: "high"},
	{category: "phish", contains: []string{"download / payload"}, ids: []string{"T1204", "T1608.001", "T1566.002"}, conf: "high"},
	{category: "phish", contains: []string{"app / deep-link", "deepview"}, ids: []string{"T1566.002", "T1204.001", "T1608.005"}, conf: "medium"},
	{category: "phish", contains: []string{"external brand/logo"}, ids: []string{"T1656", "T1036.005"}, conf: "medium"},
	{category: "fuzz", contains: []string{".env", ".git", "backup"}, ids: []string{"T1083", "T1005", "T1552.001"}, conf: "high"},
	{category: "fuzz", contains: []string{"admin", "login", "wp-", "owa", "panel"}, ids: []string{"T1078", "T1190", "T1133"}, conf: "high"},
	{category: "fuzz", contains: []string{"fuzz"}, ids: []string{"T1595.002", "T1190"}, conf: "medium"},

	{category: "url", contains: []string{"sendgrid", "mailchimp", "mandrill", "sparkpost", "mailgun", "amazon ses", "click-tracking", "constant contact"}, ids: []string{"T1566.002", "T1583", "T1608.005"}, conf: "high"},
	{category: "url", contains: []string{"branch app.link", "url shortener"}, ids: []string{"T1566.002", "T1608.005", "T1102"}, conf: "medium"},
	{category: "url", contains: []string{"cross-domain redirect"}, ids: []string{"T1566.002", "T1102", "T1608.005"}, conf: "medium"},
	{category: "url", contains: []string{"final host differs", "redirect location host"}, ids: []string{"T1566.002", "T1608.005"}, conf: "medium"},
	{category: "url", contains: []string{"long redirect chain"}, ids: []string{"T1566.002", "T1027"}, conf: "medium"},
	{category: "url", contains: []string{"hidden query string", "fragment"}, ids: []string{"T1566.002", "T1027"}, conf: "low"},
	{category: "url", contains: []string{"userinfo"}, ids: []string{"T1036", "T1566.002"}, conf: "high"},
	{category: "url", contains: []string{"punycode", "idn"}, ids: []string{"T1036.005", "T1656"}, conf: "medium"},
	{category: "url", contains: []string{"raw ip"}, ids: []string{"T1566.002", "T1102"}, conf: "high"},
	{category: "url", contains: []string{"cleartext http", "https url redirects to cleartext"}, ids: []string{"T1557", "T1040"}, conf: "medium"},
	{category: "url", contains: []string{"credential/account related"}, ids: []string{"T1566.002", "T1056.003"}, conf: "medium"},

	{category: "http", contains: []string{"does not land on https"}, ids: []string{"T1557"}, conf: "low"},
	{category: "http", contains: []string{"missing headers"}, ids: []string{"T1190"}, conf: "low"},

	{category: "tls", contains: []string{"expired", "expir"}, ids: []string{"T1557"}, conf: "low"},
	{category: "tls", contains: []string{"self-signed", "hostname mismatch"}, ids: []string{"T1557", "T1036"}, conf: "medium"},

	{category: "dns", contains: []string{"no spf", "no dmarc", "spf"}, ids: []string{"T1566", "T1584"}, conf: "low"},
	{category: "banner", contains: []string{"open"}, ids: []string{"T1190", "T1071.001"}, conf: "low"},
}

// AnnotateMitre attaches ATT&CK technique refs to findings in place.
func AnnotateMitre(findings []Finding) []Finding {
	for i := range findings {
		if len(findings[i].Mitre) > 0 {
			continue
		}
		findings[i].Mitre = matchMitre(findings[i])
	}
	return findings
}

// MitreRollup collapses annotated findings into unique techniques (sorted by count desc).
func MitreRollup(findings []Finding) []MitreHit {
	type agg struct {
		hit   MitreHit
		rank  int
		count int
	}
	byID := map[string]*agg{}
	confRank := map[string]int{"high": 3, "medium": 2, "low": 1}

	for _, f := range findings {
		for _, m := range f.Mitre {
			a, ok := byID[m.ID]
			if !ok {
				a = &agg{hit: MitreHit{ID: m.ID, Name: m.Name, Tactic: m.Tactic, Confidence: m.Confidence}}
				byID[m.ID] = a
			}
			a.count++
			if confRank[m.Confidence] > a.rank {
				a.rank = confRank[m.Confidence]
				a.hit.Confidence = m.Confidence
				a.hit.Name = m.Name
				a.hit.Tactic = m.Tactic
			}
		}
	}

	out := make([]MitreHit, 0, len(byID))
	for _, a := range byID {
		h := a.hit
		h.Count = a.count
		out = append(out, h)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Confidence != out[j].Confidence {
			return confRank[out[i].Confidence] > confRank[out[j].Confidence]
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func matchMitre(f Finding) []MitreRef {
	cat := strings.ToLower(f.Category)
	msg := strings.ToLower(f.Message)
	seen := map[string]MitreRef{}

	for _, rule := range mitreRules {
		if rule.category != "" && rule.category != cat {
			continue
		}
		ok := len(rule.contains) == 0
		for _, needle := range rule.contains {
			if strings.Contains(msg, strings.ToLower(needle)) {
				ok = true
				break
			}
		}
		if !ok {
			continue
		}
		for _, id := range rule.ids {
			tech, exists := mitreCatalog[id]
			if !exists {
				continue
			}
			prev, had := seen[id]
			ref := MitreRef{
				ID:         tech.id,
				Name:       tech.name,
				Tactic:     tech.tactic,
				Confidence: rule.conf,
			}
			if !had || confBetter(rule.conf, prev.Confidence) {
				seen[id] = ref
			}
		}
	}

	if len(seen) == 0 {
		return nil
	}
	out := make([]MitreRef, 0, len(seen))
	for _, r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func confBetter(a, b string) bool {
	rank := map[string]int{"high": 3, "medium": 2, "low": 1}
	return rank[a] > rank[b]
}

// FormatMitreIDs returns a short tag string like "T1566.002 · T1656".
func FormatMitreIDs(refs []MitreRef) string {
	if len(refs) == 0 {
		return ""
	}
	ids := make([]string, len(refs))
	for i, r := range refs {
		ids[i] = r.ID
	}
	return strings.Join(ids, " · ")
}

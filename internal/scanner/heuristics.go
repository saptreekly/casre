package scanner

import (
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
)

// lookalikeBrands are common phishing impersonation targets, keyed by the core
// brand token compared against a candidate hostname's registrable label.
var lookalikeBrands = []string{
	"paypal", "apple", "icloud", "microsoft", "office365", "outlook", "google",
	"amazon", "netflix", "facebook", "instagram", "whatsapp", "linkedin",
	"docusign", "adobe", "dropbox", "chase", "wellsfargo", "bankofamerica",
	"americanexpress", "citibank", "coinbase", "binance", "metamask", "steam",
	"fedex", "ups", "usps", "dhl", "spotify", "twitter", "github", "okta",
}

// homoglyphFold maps common confusable characters to their ASCII look-alikes.
var homoglyphFold = map[rune]rune{
	'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g',
	'à': 'a', 'á': 'a', 'â': 'a', 'ã': 'a', 'ä': 'a', 'å': 'a', 'а': 'a', // cyrillic a
	'ð': 'd',
	'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e', 'е': 'e', // cyrillic e
	'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ı': 'i',
	'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o', 'ø': 'o', 'о': 'o', // cyrillic o
	'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u',
	'ç': 'c', 'с': 'c', // cyrillic c
	'ñ': 'n',
	'ý': 'y', 'ÿ': 'y', 'у': 'y', // cyrillic u looks like y
	'р': 'p', // cyrillic er
	'ѕ': 's', // cyrillic dze
	'ԁ': 'd',
	'ｇ': 'g',
}

// foldConfusables normalizes a label to lowercase ASCII look-alikes and drops
// separators, so "paypa1-secure" and "pаypal" both collapse toward "paypal".
func foldConfusables(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r == '-' || r == '_' || r == '.' {
			continue
		}
		if repl, ok := homoglyphFold[r]; ok {
			b.WriteRune(repl)
			continue
		}
		if r <= unicode.MaxASCII {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// LookalikeScore checks whether a host visually impersonates a known brand
// without being that brand's real domain. Returns the matched brand and a
// 0–100 score (higher = closer impersonation), or ("", 0) if none.
func LookalikeScore(host string) (string, int) {
	reg := RegistrableDomain(host)
	if reg == "" {
		return "", 0
	}
	sld := reg
	if i := strings.IndexByte(reg, '.'); i > 0 {
		sld = reg[:i]
	}
	// Also consider subdomain labels ("paypal.login-verify.com").
	labels := strings.Split(strings.ToLower(host), ".")
	candidates := []string{sld}
	for _, l := range labels {
		if l != sld && l != "" {
			candidates = append(candidates, l)
		}
	}

	bestBrand := ""
	bestScore := 0
	for _, brand := range lookalikeBrands {
		foldedBrand := foldConfusables(brand)
		// Exact real domain: not a lookalike.
		if sld == brand {
			return "", 0
		}
		for _, cand := range candidates {
			folded := foldConfusables(cand)
			if folded == "" {
				continue
			}
			score := brandSimilarity(brand, foldedBrand, cand, folded)
			if score > bestScore {
				bestScore = score
				bestBrand = brand
			}
		}
	}
	if bestScore < 55 {
		return "", 0
	}
	return bestBrand, bestScore
}

func brandSimilarity(brand, foldedBrand, cand, folded string) int {
	// Confusable-fold exact match: strong signal (e.g. "paypa1" == "paypal").
	if folded == foldedBrand {
		if cand == brand {
			return 0 // identical real token, handled by caller
		}
		return 95
	}
	// Brand embedded as a distinct token in a longer label.
	if folded != foldedBrand && strings.Contains(folded, foldedBrand) && len(foldedBrand) >= 4 {
		return 80
	}
	// Small edit distance on the folded forms.
	if len(foldedBrand) >= 4 {
		d := levenshtein(folded, foldedBrand)
		switch {
		case d == 1:
			return 85
		case d == 2 && len(foldedBrand) >= 6:
			return 65
		}
	}
	return 0
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

// ShannonEntropy returns the per-character Shannon entropy (bits) of s.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// DGAScore rates how likely the registrable label is algorithmically generated
// (0–100). It blends entropy, length, digit density, and consonant runs.
func DGAScore(host string) (int, float64) {
	reg := RegistrableDomain(host)
	if reg == "" {
		return 0, 0
	}
	label := reg
	if i := strings.IndexByte(reg, '.'); i > 0 {
		label = reg[:i]
	}
	if len(label) < 7 {
		return 0, ShannonEntropy(label)
	}
	ent := ShannonEntropy(label)

	digits, vowels, consRun, maxConsRun := 0, 0, 0, 0
	for _, r := range label {
		switch {
		case r >= '0' && r <= '9':
			digits++
			consRun = 0
		case strings.ContainsRune("aeiou", r):
			vowels++
			consRun = 0
		case r >= 'a' && r <= 'z':
			consRun++
			if consRun > maxConsRun {
				maxConsRun = consRun
			}
		default:
			consRun = 0
		}
	}
	n := float64(len(label))
	vowelRatio := float64(vowels) / n
	digitRatio := float64(digits) / n

	score := 0.0
	if ent >= 3.6 {
		score += (ent - 3.6) * 40 // up to ~+20 for very high entropy
	}
	if vowelRatio < 0.30 {
		score += (0.30 - vowelRatio) * 90
	}
	if digitRatio > 0.25 {
		score += (digitRatio - 0.25) * 60
	}
	if maxConsRun >= 5 {
		score += float64(maxConsRun-4) * 8
	}
	if n >= 15 {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	return int(score), ent
}

// TLSTrust interprets a target's certificate for phishing-relevant trust signals.
// Returns a 0–100 "distrust" contribution and human notes.
func TLSTrust(r Result) (int, []string) {
	if r.TLS == nil || len(r.TLS.Chain) == 0 {
		return 0, nil
	}
	leaf := r.TLS.Chain[0]
	var notes []string
	distrust := 0

	if strings.EqualFold(strings.TrimSpace(leaf.Subject), strings.TrimSpace(leaf.Issuer)) {
		distrust += 25
		notes = append(notes, "self-signed certificate")
	}
	issuer := strings.ToLower(leaf.Issuer)
	switch {
	case strings.Contains(issuer, "let's encrypt"), strings.Contains(issuer, "lets encrypt"),
		strings.Contains(issuer, "r3"), strings.Contains(issuer, "e1"), strings.Contains(issuer, "e5"),
		strings.Contains(issuer, "zerossl"), strings.Contains(issuer, "google trust services"),
		strings.Contains(issuer, "buypass"):
		distrust += 6
		notes = append(notes, "free/automated CA ("+shortSubject(leaf.Issuer)+")")
	}

	if !leaf.NotBefore.IsZero() {
		ageHours := time.Since(leaf.NotBefore).Hours()
		switch {
		case ageHours <= 48:
			distrust += 22
			notes = append(notes, "certificate issued in last 48h")
		case ageHours <= 24*7:
			distrust += 12
			notes = append(notes, "certificate issued in last 7d")
		}
	}
	if leaf.DaysUntilExp < 0 {
		distrust += 15
		notes = append(notes, "certificate expired")
	}

	sans := len(leaf.DNSNames)
	if sans >= 50 {
		distrust += 8
		notes = append(notes, fmt.Sprintf("broad SAN list (%d names)", sans))
	}
	for _, name := range leaf.DNSNames {
		if strings.HasPrefix(name, "*.") {
			notes = append(notes, "wildcard certificate")
			break
		}
	}
	if distrust > 100 {
		distrust = 100
	}
	return distrust, notes
}

// HeuristicFindings runs all local heuristics against a result.
func HeuristicFindings(r Result) []Finding {
	var out []Finding
	seenHost := map[string]bool{}
	addHostHeuristics := func(host string) {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || seenHost[host] || IsIPHost(host) {
			return
		}
		seenHost[host] = true

		if brand, score := LookalikeScore(host); brand != "" {
			sev := "medium"
			if score >= 85 {
				sev = "high"
			}
			out = append(out, Finding{
				Severity: sev,
				Category: "intel",
				Message:  fmt.Sprintf("lookalike of %q (%s, similarity %d)", brand, host, score),
			})
		}
		if score, ent := DGAScore(host); score >= 60 {
			sev := "low"
			if score >= 80 {
				sev = "medium"
			}
			out = append(out, Finding{
				Severity: sev,
				Category: "intel",
				Message:  fmt.Sprintf("algorithmic/DGA-like hostname %q (score %d, entropy %.2f)", host, score, ent),
			})
		}
	}

	addHostHeuristics(r.Host)
	addHostHeuristics(r.FinalHost)
	if r.Graph != nil {
		for _, n := range r.Graph.Nodes {
			addHostHeuristics(n.Host)
		}
	}

	if distrust, notes := TLSTrust(r); distrust >= 20 {
		sev := "low"
		if distrust >= 40 {
			sev = "medium"
		}
		out = append(out, Finding{
			Severity: sev,
			Category: "intel",
			Message:  "TLS trust concerns: " + strings.Join(notes, "; "),
		})
	}
	return out
}

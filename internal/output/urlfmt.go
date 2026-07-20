package output

import (
	"net/url"
	"sort"
	"strings"
)

// Notable query keys surfaced in compact URL display (phishing/campaign trackers).
var notableQueryKeys = map[string]bool{
	"go": true, "s1": true, "s2": true, "s3": true,
	"deploy": true, "user": true, "email_id": true, "email": true,
	"source_id": true, "sub1": true, "sub2": true, "uid": true,
	"pid": true, "act": true, "nav": true,
}

// CompactURL returns a short analyst-friendly URL: scheme://host/path + notable
// query keys. Long/base64 param values are collapsed (e.g. var=‹base64›).
func CompactURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return truncateMiddle(raw, 72)
	}
	out := u.Scheme + "://" + u.Host
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if len(path) > 40 {
		path = truncateMiddle(path, 40)
	}
	out += path

	q := u.Query()
	if len(q) == 0 {
		if u.Fragment != "" {
			frag := u.Fragment
			if len(frag) > 24 {
				frag = truncateMiddle(frag, 24)
			}
			out += "#" + frag
		}
		return out
	}

	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	other := 0
	for _, k := range keys {
		vals := q[k]
		if len(vals) == 0 {
			continue
		}
		v := vals[0]
		if notableQueryKeys[strings.ToLower(k)] {
			parts = append(parts, k+"="+compactParamValue(v, 28))
			continue
		}
		if looksLikeBase64Param(v) {
			parts = append(parts, k+"=‹base64›")
			continue
		}
		other++
	}
	if len(parts) > 0 {
		out += "?" + strings.Join(parts, "&")
	}
	if other > 0 {
		if len(parts) == 0 {
			out += "?"
		} else {
			out += "&"
		}
		out += "+" + itoa(other) + " params"
	}
	return out
}

func compactParamValue(v string, max int) string {
	v = strings.TrimSpace(v)
	if looksLikeBase64Param(v) {
		return "‹base64›"
	}
	if len(v) > max {
		return truncateMiddle(v, max)
	}
	return v
}

func looksLikeBase64Param(s string) bool {
	if len(s) < 24 {
		return false
	}
	pad := 0
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '+', r == '/', r == '-', r == '_':
			continue
		case r == '=':
			pad++
			if pad > 2 {
				return false
			}
		default:
			return false
		}
	}
	// Prefer long opaque blobs.
	return len(s) >= 32
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// CampaignSummary builds a one-line host chain from graph nodes (e.g. cloaker → IP → host ×3 → final).
func CampaignSummary(hosts []string) string {
	if len(hosts) == 0 {
		return ""
	}
	type run struct {
		label string
		n     int
	}
	var runs []run
	for _, h := range hosts {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" {
			continue
		}
		if len(runs) > 0 && runs[len(runs)-1].label == h {
			runs[len(runs)-1].n++
			continue
		}
		runs = append(runs, run{label: h, n: 1})
	}
	parts := make([]string, 0, len(runs))
	for _, r := range runs {
		if r.n > 1 {
			parts = append(parts, r.label+" ×"+itoa(r.n))
		} else {
			parts = append(parts, r.label)
		}
	}
	return strings.Join(parts, " → ")
}

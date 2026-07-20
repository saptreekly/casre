package scanner

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"
)

// Target is a host and optional full URL to investigate.
type Target struct {
	Host     string // infrastructure host to scan
	URL      string // absolute URL probed over the wire (no fragment)
	RawInput string // exactly what the analyst pasted
	Fragment string // client-only fragment (often abused for tracking params)
}

// ParseTarget turns a host or full URL into a Target.
// Fragments are retained for analysis but stripped from the wire URL
// (browsers never send #... to the server).
func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, fmt.Errorf("empty target")
	}

	if !strings.Contains(raw, "://") && !strings.HasPrefix(raw, "//") {
		host := raw
		if i := strings.IndexByte(host, '/'); i >= 0 {
			return ParseTarget("https://" + raw)
		}
		host = strings.TrimSuffix(host, ".")
		if host == "" {
			return Target{}, fmt.Errorf("empty host")
		}
		return Target{Host: host, RawInput: raw}, nil
	}

	if strings.HasPrefix(raw, "//") {
		raw = "https:" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("parse url: %w", err)
	}
	if u.Host == "" {
		return Target{}, fmt.Errorf("url missing host: %q", raw)
	}
	host := u.Hostname()
	if host == "" {
		return Target{}, fmt.Errorf("url missing hostname: %q", raw)
	}

	frag := u.Fragment
	u.Fragment = ""
	return Target{
		Host:     host,
		URL:      u.String(),
		RawInput: raw,
		Fragment: frag,
	}, nil
}

// HostEqual compares hostnames case-insensitively, ignoring trailing dots.
func HostEqual(a, b string) bool {
	a = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".")
	b = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(b)), ".")
	return a == b
}

// HostFromURL extracts hostname from a URL string.
func HostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// IsIPHost reports whether host is a literal IP.
func IsIPHost(host string) bool {
	return net.ParseIP(host) != nil
}

// FragmentLooksLikeQuery reports fragments that encode a hidden query string.
func FragmentLooksLikeQuery(frag string) bool {
	frag = strings.TrimSpace(frag)
	if frag == "" {
		return false
	}
	if strings.HasPrefix(frag, "?") || strings.HasPrefix(frag, "/") {
		return strings.Contains(frag, "=")
	}
	return strings.Contains(frag, "=") && strings.Contains(frag, "&")
}

// DecodeBase64QueryFragment tries to base64-decode a fragment into a query string.
// Returns the decoded query (e.g. "go=1&s1=2") and true on success.
func DecodeBase64QueryFragment(frag string) (string, bool) {
	raw := strings.TrimSpace(frag)
	raw = strings.TrimPrefix(raw, "?")
	raw = strings.TrimPrefix(raw, "/")
	if raw == "" || !looksLikeBase64(raw) {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(raw)
	}
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(raw)
	}
	if err != nil || len(decoded) == 0 {
		return "", false
	}
	s := string(decoded)
	if !isPrintableASCII(s) {
		return "", false
	}
	if !strings.Contains(s, "=") {
		return "", false
	}
	// Prefer query-shaped payloads (key=value).
	if strings.Contains(s, "&") || strings.Contains(s, "=") {
		return s, true
	}
	return "", false
}

func looksLikeBase64(s string) bool {
	if len(s) < 8 {
		return false
	}
	pad := 0
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/', r == '-', r == '_':
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
	return true
}

func isPrintableASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || (r < 0x20 && r != '\t' && r != '\n' && r != '\r') {
			return false
		}
	}
	return true
}

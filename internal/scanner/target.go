package scanner

import (
	"fmt"
	"net"
	"net/url"
	"strings"
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

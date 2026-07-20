package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Evidence is a saved HTML snapshot of a cloaker/lander page.
type Evidence struct {
	Role      string `json:"role"`
	URL       string `json:"url"`
	Host      string `json:"host"`
	Title     string `json:"title,omitempty"`
	Path      string `json:"path"`
	Bytes     int    `json:"bytes"`
	ContentType string `json:"content_type,omitempty"`
}

var reUnsafeFile = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// ShouldSnapshot reports whether this role gets an HTML evidence file.
func ShouldSnapshot(role string) bool {
	return role == RoleCloaker || role == RoleLander
}

// SaveEvidenceHTML writes body to dir and returns metadata. No-op if dir/body empty.
func SaveEvidenceHTML(dir, role, rawURL, host, title, contentType string, body []byte) (*Evidence, error) {
	if dir == "" || len(body) == 0 {
		return nil, nil
	}
	if !ShouldSnapshot(role) {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	hostPart := host
	if hostPart == "" {
		hostPart = HostFromURL(rawURL)
	}
	if hostPart == "" {
		hostPart = "unknown"
	}
	hostPart = sanitizeFilePart(hostPart)
	rolePart := sanitizeFilePart(role)
	ts := time.Now().UTC().Format("20060102T150405Z")
	name := fmt.Sprintf("%s_%s_%s.html", rolePart, hostPart, ts)
	path := filepath.Join(dir, name)

	// Avoid clobbering if multiple hops share host in the same second.
	if _, err := os.Stat(path); err == nil {
		name = fmt.Sprintf("%s_%s_%s_%d.html", rolePart, hostPart, ts, time.Now().UnixNano()%10000)
		path = filepath.Join(dir, name)
	}

	if err := os.WriteFile(path, body, 0o644); err != nil {
		return nil, err
	}
	return &Evidence{
		Role:        role,
		URL:         rawURL,
		Host:        host,
		Title:       title,
		Path:        path,
		Bytes:       len(body),
		ContentType: contentType,
	}, nil
}

func sanitizeFilePart(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = reUnsafeFile.ReplaceAllString(s, "_")
	if len(s) > 48 {
		s = s[:48]
	}
	if s == "" {
		return "x"
	}
	return s
}

package scanner

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// DefangIOC neutralizes an indicator for safe sharing in tickets/email:
// hxxp, [.] , [:] , [at]. Applied to URLs, domains, and IPs.
func DefangIOC(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	s = strings.ReplaceAll(s, "https://", "hxxps[://]")
	s = strings.ReplaceAll(s, "http://", "hxxp[://]")
	s = strings.ReplaceAll(s, "ftp://", "fxp[://]")
	s = strings.ReplaceAll(s, "@", "[at]")
	// Defang remaining dots not already inside a bracket group.
	s = strings.ReplaceAll(s, ".", "[.]")
	// Undo double-bracketing introduced on the scheme separators.
	s = strings.ReplaceAll(s, "[://]", "://")
	s = strings.ReplaceAll(s, "hxxps://", "hxxps[://]")
	s = strings.ReplaceAll(s, "hxxp://", "hxxp[://]")
	s = strings.ReplaceAll(s, "fxp://", "fxp[://]")
	return s
}

// ExportIOCsCSV renders an IOC set as CSV text (type,value,defanged,context,severity,host).
func ExportIOCsCSV(set *IOCSet) string {
	if set == nil {
		return ""
	}
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"type", "value", "defanged", "context", "severity", "host"})
	for _, ioc := range set.All {
		_ = w.Write([]string{
			ioc.Type, ioc.Value, DefangIOC(ioc.Value), ioc.Context, ioc.Severity, ioc.Host,
		})
	}
	w.Flush()
	return b.String()
}

// stixBundle is a minimal STIX 2.1 bundle.
type stixBundle struct {
	Type    string       `json:"type"`
	ID      string       `json:"id"`
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type        string   `json:"type"`
	SpecVersion string   `json:"spec_version"`
	ID          string   `json:"id"`
	Created     string   `json:"created,omitempty"`
	Modified    string   `json:"modified,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	PatternType string   `json:"pattern_type,omitempty"`
	ValidFrom   string   `json:"valid_from,omitempty"`
	Labels      []string `json:"labels,omitempty"`
	Confidence  int      `json:"confidence,omitempty"`
}

// ExportIOCsSTIX renders an IOC set as a STIX 2.1 bundle JSON string.
func ExportIOCsSTIX(set *IOCSet, host string) string {
	if set == nil {
		return ""
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	bundle := stixBundle{
		Type: "bundle",
		ID:   "bundle--" + deterministicUUID("casre-bundle-"+host+now),
	}
	for _, ioc := range set.All {
		pattern := stixPattern(ioc)
		if pattern == "" {
			continue
		}
		id := "indicator--" + deterministicUUID(ioc.Type+":"+ioc.Value)
		obj := stixObject{
			Type:        "indicator",
			SpecVersion: "2.1",
			ID:          id,
			Created:     now,
			Modified:    now,
			Name:        fmt.Sprintf("%s %s", ioc.Type, ioc.Value),
			Description: ioc.Context,
			Pattern:     pattern,
			PatternType: "stix",
			ValidFrom:   now,
			Labels:      []string{"malicious-activity"},
			Confidence:  severityConfidence(ioc.Severity),
		}
		bundle.Objects = append(bundle.Objects, obj)
	}
	buf, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return ""
	}
	return string(buf)
}

func stixPattern(ioc IOC) string {
	v := strings.ReplaceAll(ioc.Value, "'", "")
	switch ioc.Type {
	case "domain":
		return fmt.Sprintf("[domain-name:value = '%s']", v)
	case "url":
		return fmt.Sprintf("[url:value = '%s']", v)
	case "ip":
		if net.ParseIP(ioc.Value) != nil && strings.Contains(ioc.Value, ":") {
			return fmt.Sprintf("[ipv6-addr:value = '%s']", v)
		}
		return fmt.Sprintf("[ipv4-addr:value = '%s']", v)
	default:
		return ""
	}
}

func severityConfidence(sev string) int {
	switch strings.ToLower(sev) {
	case "high":
		return 85
	case "medium":
		return 60
	case "low":
		return 40
	default:
		return 20
	}
}

// deterministicUUID builds a stable RFC-4122-shaped v4 string from a seed so
// re-exports of the same IOC keep the same STIX id (no external uuid dep).
func deterministicUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

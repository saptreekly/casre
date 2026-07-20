package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var wellKnown = map[int]string{
	21:   "ftp",
	22:   "ssh",
	25:   "smtp",
	80:   "http",
	110:  "pop3",
	143:  "imap",
	443:  "https",
	445:  "smb",
	3306: "mysql",
	3389: "rdp",
	5432: "postgres",
	6379: "redis",
	8080: "http-alt",
	8443: "https-alt",
}

// GrabBanners probes TCP ports concurrently and reads response banners.
func GrabBanners(ctx context.Context, host string, ports []int, timeout time.Duration, limiter waitFunc) []Banner {
	results := make([]Banner, len(ports))
	var wg sync.WaitGroup

	for i, port := range ports {
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			if limiter != nil {
				if err := limiter(ctx); err != nil {
					results[idx] = Banner{Port: p, Error: err.Error()}
					return
				}
			}
			results[idx] = grabOne(ctx, host, p, timeout)
		}(i, port)
	}
	wg.Wait()
	return results
}

type waitFunc func(context.Context) error

func grabOne(ctx context.Context, host string, port int, timeout time.Duration) Banner {
	b := Banner{Port: port, Service: wellKnown[port]}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		b.Error = err.Error()
		return b
	}
	defer conn.Close()
	b.Open = true

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send a lightweight probe for silent services.
	switch port {
	case 80, 8080, 8000:
		_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	case 443, 8443:
		// TLS-wrapped; skip plaintext banner — caller uses TLS module.
		b.Banner = "[tls-wrapped]"
		return b
	case 25:
		// SMTP greets first; no send needed.
	default:
		// Many services banner spontaneously; for others nudge with CRLF.
		_, _ = conn.Write([]byte("\r\n"))
	}

	reader := bufio.NewReaderSize(conn, 1024)
	buf := make([]byte, 512)
	n, err := reader.Read(buf)
	if n > 0 {
		b.Banner = sanitizeBanner(string(buf[:n]))
	} else if err != nil && b.Banner == "" {
		// Open but silent is still useful.
		b.Banner = ""
	}

	if b.Service == "" && b.Banner != "" {
		b.Service = guessService(b.Banner)
	}
	return b
}

func sanitizeBanner(s string) string {
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.TrimSpace(s)
	if len(s) > 256 {
		s = s[:256] + "…"
	}
	return s
}

func guessService(banner string) string {
	lower := strings.ToLower(banner)
	switch {
	case strings.Contains(lower, "ssh"):
		return "ssh"
	case strings.Contains(lower, "ftp"):
		return "ftp"
	case strings.Contains(lower, "smtp") || strings.HasPrefix(lower, "220"):
		return "smtp"
	case strings.Contains(lower, "http/"):
		return "http"
	case strings.Contains(lower, "mysql"):
		return "mysql"
	case strings.Contains(lower, "redis"):
		return "redis"
	case strings.Contains(lower, "postgres"):
		return "postgres"
	default:
		return "unknown"
	}
}

// BannerFindings highlights interesting open services.
func BannerFindings(banners []Banner) []Finding {
	var findings []Finding
	for _, b := range banners {
		if !b.Open {
			continue
		}
		switch b.Port {
		case 22:
			findings = append(findings, Finding{
				Severity: "info",
				Category: "port",
				Message:  fmt.Sprintf("SSH open — banner: %s", truncate(b.Banner, 80)),
			})
		case 21:
			findings = append(findings, Finding{
				Severity: "medium",
				Category: "port",
				Message:  "FTP service exposed",
			})
		case 3389:
			findings = append(findings, Finding{
				Severity: "medium",
				Category: "port",
				Message:  "RDP (3389) exposed to the internet",
			})
		case 445:
			findings = append(findings, Finding{
				Severity: "high",
				Category: "port",
				Message:  "SMB (445) exposed to the internet",
			})
		case 6379:
			findings = append(findings, Finding{
				Severity: "high",
				Category: "port",
				Message:  "Redis (6379) appears reachable",
			})
		case 3306, 5432:
			findings = append(findings, Finding{
				Severity: "high",
				Category: "port",
				Message:  fmt.Sprintf("database port %d reachable", b.Port),
			})
		case 25:
			findings = append(findings, Finding{
				Severity: "low",
				Category: "port",
				Message:  "SMTP banner available — check open relay separately",
			})
		}
	}
	return findings
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

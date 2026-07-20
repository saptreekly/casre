package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// ProbeTLS dials TLS on port 443 and extracts the certificate chain.
func ProbeTLS(ctx context.Context, host string, timeout time.Duration, insecure bool) (*TLSResult, error) {
	result, err := dialTLS(ctx, host, timeout, insecure)
	if err != nil && !insecure {
		// Retry with skip-verify so we can still harvest the presented chain.
		return dialTLS(ctx, host, timeout, true)
	}
	return result, err
}

func dialTLS(ctx context.Context, host string, timeout time.Duration, insecure bool) (*TLSResult, error) {
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: insecure, //nolint:gosec // intentional for recon of misconfigured hosts
		MinVersion:         tls.VersionTLS10,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	conn := tls.Client(rawConn, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result := &TLSResult{
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ServerName:  state.ServerName,
	}
	if state.NegotiatedProtocol != "" {
		result.ALPN = []string{state.NegotiatedProtocol}
	}

	now := time.Now()
	for _, cert := range state.PeerCertificates {
		result.Chain = append(result.Chain, CertInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			DNSNames:     cert.DNSNames,
			SerialNumber: cert.SerialNumber.Text(16),
			IsCA:         cert.IsCA,
			DaysUntilExp: int(cert.NotAfter.Sub(now).Hours() / 24),
		})
	}

	return result, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// TLSFindings converts certificate/TLS state into actionable findings.
func TLSFindings(tlsResult *TLSResult) []Finding {
	if tlsResult == nil || len(tlsResult.Chain) == 0 {
		return nil
	}
	var findings []Finding
	leaf := tlsResult.Chain[0]

	switch tlsResult.Version {
	case "TLS1.0", "TLS1.1":
		findings = append(findings, Finding{
			Severity: "high",
			Category: "tls",
			Message:  fmt.Sprintf("obsolete TLS version negotiated: %s", tlsResult.Version),
		})
	}

	if leaf.DaysUntilExp < 0 {
		findings = append(findings, Finding{
			Severity: "high",
			Category: "tls",
			Message:  "leaf certificate is expired",
		})
	} else if leaf.DaysUntilExp <= 14 {
		findings = append(findings, Finding{
			Severity: "medium",
			Category: "tls",
			Message:  fmt.Sprintf("leaf certificate expires in %d days", leaf.DaysUntilExp),
		})
	} else if leaf.DaysUntilExp <= 30 {
		findings = append(findings, Finding{
			Severity: "low",
			Category: "tls",
			Message:  fmt.Sprintf("leaf certificate expires in %d days", leaf.DaysUntilExp),
		})
	}

	if n := len(leaf.DNSNames); n > 0 {
		findings = append(findings, Finding{
			Severity: "info",
			Category: "tls",
			Message:  fmt.Sprintf("leaf cert covers %d SAN name(s)", n),
		})
	}

	if strings.Contains(strings.ToLower(leaf.Issuer), "let's encrypt") {
		findings = append(findings, Finding{
			Severity: "info",
			Category: "tls",
			Message:  "issued by Let's Encrypt",
		})
	}

	return findings
}

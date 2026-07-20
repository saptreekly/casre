# CASRE — Concurrent Attack Surface Recon Engine

High-speed Go CLI for external infrastructure recon and phishing URL investigation.

Maps DNS, TLS, banners, HTTP, CDN/ASN enrichment, and — for full URLs — page signals plus an automatic hop graph (redirects, JS/meta refresh, deepview destinations).

## Install

Requires [Go](https://go.dev/dl/) 1.22+.

```bash
# Install latest to GOPATH/bin (ensure ~/go/bin is on PATH)
go install github.com/saptreekly/casre/cmd/casre@latest

# Or clone and build locally
git clone https://github.com/saptreekly/casre.git
cd casre
go build -o ~/.local/bin/casre ./cmd/casre
```

Confirm:

```bash
casre -h
```

## Usage

### Host recon

```bash
casre example.com
casre -v example.com
casre -modules dns,tls,enrich -ports 22,80,443 scanme.nmap.org
```

### Phishing / suspicious URLs

Quote URLs so the shell does not treat `&` as a background operator.

```bash
casre 'https://storage.googleapis.com/bucket/lure.html#?act=cl&pid=1'
casre -v 'https://bit.ly/suspicious'
casre -depth 8 -max-urls 40 'https://lure.example/path'
casre -no-follow 'https://lure.example/path'   # single probe, no graph crawl
```

URL mode follows HTTP redirects hop-by-hop, extracts page signals (title, fake Turnstile, cloud-bucket hosting, brand logos, forms, deep links), and prints a GRAPH of visited nodes.

### Batch / JSON / diff

```bash
# File of hosts or URLs (one per line); also accepts stdin
casre -f scope.txt
casre -f urls.txt -json -c 200 -rate 100

# Baseline + later comparison
casre -o baseline.json example.com
casre -diff baseline.json example.com
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c` | `100` | Max concurrent targets |
| `-rate` | `50` | Global ops/sec (`0` = unlimited) |
| `-timeout` | `3` | Per-connection timeout (seconds) |
| `-ports` | `80,443,22` | TCP ports for banner grab |
| `-modules` | `dns,tls,banner,http,enrich` | Modules to enable |
| `-depth` | `5` | Max hop depth for URL graph crawl |
| `-max-urls` | `25` | Max URLs to probe per graph |
| `-no-follow` | off | Disable automatic URL graph crawling |
| `-v` | off | Verbose text (full SANs, info findings) |
| `-o` | | Save full JSON report |
| `-diff` | | Compare against a previous `-o` report |
| `-json` | off | NDJSON to stdout |
| `-q` | off | Quiet progress on stderr |
| `-insecure` | off | Skip TLS certificate verification |
| `-no-color` / `-color` | auto | ANSI color control |

## Modules

| Module | What it does |
|--------|----------------|
| **dns** | A, AAAA, CNAME, MX, NS, TXT (+ SPF/DMARC signals) |
| **tls** | Handshake version, cipher, cert chain, SANs, expiry |
| **banner** | TCP connect + banner grab on selected ports |
| **http** | Redirects, headers, security-header gaps, tech fingerprints, page analysis |
| **enrich** | CDN detection, Team Cymru ASN, mail/hosting hints |

## Authorization

Only scan hosts and URLs you own or have explicit permission to test.

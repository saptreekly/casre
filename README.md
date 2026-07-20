# CASRE — Concurrent Attack Surface Recon Engine

Interactive TUI for phishing-URL investigation and light external recon.

Paste a suspicious link, optionally tune crawl settings, scan, then walk the campaign story, redirect chain, alerts, IOCs, and host facts — without drowning in base64 query blobs.

## Install

Requires [Go](https://go.dev/dl/) 1.22+.

```bash
git clone https://github.com/saptreekly/casre.git
cd casre
go build -o ~/.local/bin/casre ./cmd/casre
```

Ensure `~/.local/bin` is on your `PATH`.

## Usage

```bash
casre
```

Needs an interactive terminal (TTY). Optional: pass URLs as arguments to pre-fill the targets box:

```bash
casre 'https://storage.googleapis.com/bucket/lure.html#?…'
```

### Home

1. Paste one or more URLs (one per line)
2. **Scan** — `Tab` → Enter, or `Ctrl+S`
3. Press `o` for **options** (crawl profiles, depth, max pages, path fuzzing, campaign mode)

### Results tabs (`1`–`6`)

| Key | Tab | Contents |
|-----|-----|----------|
| `1` | **Story** | Verdict narrative, confidence, kill-chain timeline, blast radius, attribution, coverage gaps, technique mix |
| `2` | **Chain** | Redirect hop graph with status, via, and role |
| `3` | **Alerts** | Findings by severity (high/medium first; `i` toggles info) |
| `4` | **Indicators** | Domains, IPs, URLs, ASNs |
| `5` | **Host** | DNS, TLS, open ports, CDN/ASN enrichment |
| `6` | **Diff** | Changes vs the previous scan after `r` rescan |

### Keys

| Key | Action |
|-----|--------|
| `1`–`6` | Switch tabs |
| `↑` `↓` | Move selection (Story, Chain, Alerts, Indicators, Host) |
| `c` | Copy selected value / URL |
| `f` / Enter | Toggle full URL (Chain, Indicators) |
| `i` | Show/hide info-severity alerts |
| `r` | Rescan and compare |
| `o` | Options (from home) |
| `esc` | New scan |
| `q` / `Ctrl+C` | Quit |

## Crawl profiles

Set under **options** (`o`):

| Profile | Behavior |
|---------|----------|
| **Quick** | Shallow campaign crawl, no path fuzz |
| **Deep** | Longer chains + path fuzz on cloaker/lander hosts |
| **Wide** | More pages, campaign mode off, path fuzz on |
| **Custom** | Manual depth / max pages / toggles |

**Campaign mode** prefers ESP → cloaker → lander style chains and stops expanding brand/CDN/social decoys. **Path fuzzing** probes common kit/admin paths on lander hosts after the crawl.

## What it looks for

- Redirect / cloaker patterns (`location` assigns, concat deobfuscation, `atob`, kit fingerprints)
- Brand impersonation (Microsoft 365, Apple, Google, DocuSign, PayPal, Okta, banks, shipping, and others)
- Cloudflare Turnstile and cloud-storage hosting signals
- DNS, TLS, banners, HTTP, ASN/CDN enrichment
- MITRE ATT&CK tags on findings where mapped

## Authorization

Use only against systems you are authorized to test.

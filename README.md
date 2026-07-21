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
| `1` | **Story** | Verdict, confidence, kill-chain timeline, blast radius, attribution, coverage gaps, page facts (obfuscation, form exfil, scripts), and intel (domain age, CT siblings, favicon, campaign links) |
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
| `e` | Export IOCs to CSV + STIX 2.1 in the working directory |
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
| **Quick** | Shallow campaign crawl · 8 parallel probes · lite path fuzz |
| **Deep** | Longer chains · 16 parallel probes · fuller path fuzz |
| **Wide** | More pages · 24 parallel probes · campaign off · fuller path fuzz |
| **Custom** | Manual depth / max pages / parallel probes / toggles |

**Campaign mode** prefers ESP → cloaker → lander style chains and stops expanding brand/CDN/social decoys.

**Parallel probes** (`HopWorkers`) control how many hop/fuzz requests run at once within a single target (1–32). More probes make deep crawls finish faster; they do not increase depth by themselves — pair with Deep/Wide or higher max pages. Global rate limiting still caps request rate.

**Path fuzzing** is on by default (toggle in options). It uses:

- Lite GETs (no redirect follow, no HTML parse)
- Soft-404 canary baselines to ignore catch-all pages
- Skip of already-crawled URLs and cloud-storage hosts
- Core admin/kit paths first, with adaptive expand after hits
- Short timeouts and early abort on dead hosts

## Page & script analysis

- Redirect / cloaker patterns (`location` assigns, concat deobfuscation, `atob`, kit fingerprints)
- Capped external `<script src>` skim for redirects and obfuscation (Quick 2 · default 3 · Deep/Wide 5)
- JS obfuscation signals (`eval` / `Function` / `fromCharCode` / packed loaders) — confidence and alerts, not hop spam
- Form exfil detail (cross-origin action, hidden fields, `autocomplete=off`)
- Hidden UI / overlays (full-page iframes, hidden captcha, visibility-hidden login)
- Brand impersonation (Microsoft 365, Apple, Google, DocuSign, PayPal, Okta, banks, shipping, and others)
- Cloudflare Turnstile and cloud-storage hosting signals

Also collects DNS, TLS, banners, HTTP, ASN/CDN enrichment, and MITRE ATT&CK tags on findings where mapped.

## Intelligence & correlation

Keyless external intel runs by default (no API keys, capped and rate-limited):

- **Domain age** via RDAP (`rdap.org`) — registration date, registrar, expiry. Freshly registered domains raise the verdict and confidence.
- **Certificate Transparency siblings** via `crt.sh` — related hostnames on the same registrable domain, folded into the blast radius.
- **Favicon fingerprint** — Shodan-style MurmurHash3 (`http.favicon.hash:<n>`) for infrastructure pivoting.

Local heuristics (no network) run on every target:

- **Lookalike / homoglyph** detection against ~30 common phishing brands (confusable-fold + edit distance), e.g. `paypa1.com`, `micros0ft-login.com`.
- **Hostname entropy / DGA** score to flag algorithmically generated domains.
- **TLS trust** scoring — self-signed, free/automated CA, freshly issued, expired, or overly broad certificates.

**Cross-target correlation** groups a batch of scanned targets that share an IP, ASN, certificate serial, favicon hash, or kit fingerprint. Related targets show in each target's Story as campaign links.

### Opt-in reputation (API keys)

Set any of these environment variables to enrich the Intel section with third-party reputation:

| Variable | Source |
|----------|--------|
| `CASRE_VT_API_KEY` | VirusTotal domain report (malicious/suspicious engine counts) |
| `CASRE_URLSCAN_API_KEY` | urlscan.io prior scans and latest verdict |
| `CASRE_SHODAN_API_KEY` | Shodan favicon-hash host count (infra cluster size) |

### IOC export

Press `e` in the results view to write the current target's indicators to `casre-iocs-<host>-<timestamp>.csv` and `.stix.json` in the working directory. The CSV includes defanged (`hxxp[://]evil[.]com`) values; the STIX 2.1 bundle emits `indicator` objects with stable IDs for SIEM/MISP ingestion.

## Authorization

Use only against systems you are authorized to test.

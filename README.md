# CASRE — Concurrent Attack Surface Recon Engine

High-speed Go CLI for external infrastructure recon and phishing URL investigation.

Maps DNS, TLS, banners, HTTP, CDN/ASN enrichment, and — for full URLs — campaign hop graphs, page signals, MITRE ATT&CK tags, a verdict score/narrative, and IOC indicators in the report.

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
casre -budget 45 -hop-workers 12 'https://lure.example/path'
casre -evidence ./evidence 'https://lure.example/path'
casre -full-crawl -max-urls 40 'https://lure.example/path'  # broader spider
casre -no-follow 'https://lure.example/path'                # single probe
```

URL mode (default **campaign** crawl):

1. Follows ESP → cloaker → deepview → lander hop-by-hop (parallel probes)
2. Classifies nodes (`tracker` / `cloaker` / `deepview` / `lander` / `decoy`) — landers require strong signals (cleartext from cloaker, credentials, suspicious TLD); brand deepview destinations are not auto-landers
3. Stops expanding brand / CDN / social decoys
4. Prints **VERDICT** (score + short narrative) and an **IOC** section in the tree

### Evidence snapshots

```bash
casre -evidence ./evidence 'https://storage.googleapis.com/bucket/lure.html'
```

Writes HTML files for **cloaker** and **lander** nodes into the directory and lists them under **EVIDENCE** in the report (also in JSON `evidence`).

### Batch / JSON / diff

```bash
casre -f scope.txt
casre -f urls.txt -json -c 200 -rate 100

casre -o baseline.json example.com
casre -diff baseline.json example.com
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c` | `100` | Max concurrent targets |
| `-rate` | `50` | Global ops/sec (`0` = unlimited) |
| `-timeout` | `3` | Per-connection timeout (seconds) |
| `-budget` | auto | Wall-clock budget for URL hop crawl (seconds) |
| `-ports` | `80,443,22` | TCP ports for banner grab |
| `-modules` | `dns,tls,banner,http,enrich` | Modules to enable |
| `-depth` | `5` | Max hop depth for URL graph crawl |
| `-max-urls` | `25` | Max URLs to probe per graph |
| `-hop-workers` | `8` | Parallel hop probes per URL target |
| `-no-follow` | off | Disable automatic URL graph crawling |
| `-full-crawl` | off | Disable campaign stops (follow decoys more) |
| `-evidence` | | Save HTML snapshots of cloaker/lander pages to a directory |
| `-v` | off | Verbose text (full SANs, info findings, more IOCs) |
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

## Verdict & campaign graph

Each result includes a **VERDICT** block:

- `score` — 0–100 risk from phishing/recon signals
- `story` — short chain narrative (e.g. `fake CF interstitial → cleartext lander`)
- `signals` — top contributing reasons

Graph nodes are labeled by role. Campaign mode follows delivery infrastructure and landers; decoys (social, app stores, major CDNs/brands) are visited once and not expanded. Use `-full-crawl` when you intentionally want broader spidering.

## IOC indicators

Each report includes an **IOC** tree section (always on) with deduped:

| type | examples |
|------|----------|
| `domain` | lander / tracker hosts |
| `ip` | resolved A/AAAA |
| `url` | seed, hops, destinations, downloads |
| `asn` | Team Cymru enrich hits |

Long URL lists are truncated unless you pass `-v`. JSON output includes an `iocs` object per target.

## MITRE ATT&CK

Findings are tagged with relevant [ATT&CK](https://attack.mitre.org/) techniques (always on). Tags appear on each finding and as a deduped **MITRE** rollup in text output; JSON includes `mitre` on each finding plus a top-level `mitre` array.

Coverage focuses on what CASRE can observe: phishing delivery, lure staging (cloud buckets, deepviews), impersonation, and redirect chains — with confidence (`high` / `medium` / `low`). Post-compromise tactics are out of scope.

Low-confidence rollup rows are hidden unless you pass `-v`.

## Authorization

Only scan hosts and URLs you own or have explicit permission to test.

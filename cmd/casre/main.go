package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/saptreekly/casre/internal/config"
	"github.com/saptreekly/casre/internal/diff"
	"github.com/saptreekly/casre/internal/output"
	"github.com/saptreekly/casre/internal/scanner"
)

func main() {
	cfg := config.Default()

	var (
		targetsFile string
		portsFlag   string
		modulesFlag string
		timeoutSec  float64
		noColor     bool
		forceColor  bool
		outFile     string
		diffFile    string
		noFollow    bool
	)

	flag.StringVar(&targetsFile, "f", "", "file with targets (one host/domain per line); also accepts stdin")
	flag.IntVar(&cfg.Concurrency, "c", cfg.Concurrency, "max concurrent targets")
	flag.Float64Var(&cfg.RateLimit, "rate", cfg.RateLimit, "global rate limit (ops/sec, 0=unlimited)")
	flag.Float64Var(&timeoutSec, "timeout", cfg.Timeout.Seconds(), "per-connection timeout in seconds")
	flag.StringVar(&portsFlag, "ports", joinPorts(cfg.Ports), "comma-separated TCP ports for banner grab")
	flag.StringVar(&modulesFlag, "modules", "dns,tls,banner,http,enrich", "comma-separated modules to run")
	flag.BoolVar(&cfg.OutputJSON, "json", false, "emit NDJSON to stdout")
	flag.BoolVar(&cfg.Quiet, "q", false, "suppress progress on stderr")
	flag.BoolVar(&cfg.Verbose, "v", false, "verbose text output (full SANs, redirects, info findings)")
	flag.BoolVar(&cfg.InsecureTLS, "insecure", false, "skip TLS certificate verification")
	flag.BoolVar(&noFollow, "no-follow", false, "disable automatic phishing-graph crawling for URL inputs")
	flag.IntVar(&cfg.Depth, "depth", cfg.Depth, "max hop depth when following URL graphs")
	flag.IntVar(&cfg.MaxURLs, "max-urls", cfg.MaxURLs, "max URLs to probe while crawling a graph")
	flag.BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	flag.BoolVar(&forceColor, "color", false, "force ANSI colors even when stdout is not a TTY")
	flag.StringVar(&outFile, "o", "", "save full results to JSON report file")
	flag.StringVar(&diffFile, "diff", "", "compare this scan against a previous -o report")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `CASRE — Concurrent Attack Surface Recon Engine

High-speed Go scanner for external infrastructure mapping and phishing URL chains:
  DNS · TLS · banners · HTTP · CDN/ASN · page analysis · hop graph · MITRE ATT&CK tags

Usage:
  casre [flags] host1 [host2 ...]
  casre [flags] 'https://suspicious.example/path?a=1&b=2'
  casre -f urls.txt

Important: quote URLs so the shell does not treat & as a background operator:
  casre 'https://storage.googleapis.com/path?act=cl&pid=1'

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  casre example.com
  casre -v 'https://bit.ly/suspicious'
  casre -depth 8 -max-urls 40 'https://lure.example/a'
  casre -no-follow 'https://lure.example/a'
  casre -o baseline.json -f scope.txt

Use only against systems you are authorized to test.
`)
	}
	flag.Parse()

	cfg.Follow = !noFollow
	cfg.Timeout = time.Duration(timeoutSec * float64(time.Second))
	ports, err := parsePorts(portsFlag)
	if err != nil {
		fatal("ports: %v", err)
	}
	cfg.Ports = ports
	cfg.Modules = parseModules(modulesFlag)

	hosts, err := collectTargets(flag.Args(), targetsFile)
	if err != nil {
		fatal("%v", err)
	}
	if len(hosts) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	var oldReport *diff.Report
	if diffFile != "" {
		oldReport, err = diff.LoadReport(diffFile)
		if err != nil {
			fatal("diff: %v", err)
		}
	}

	targets := hosts

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	useColor := output.EnableColor(noColor, forceColor)
	engine := scanner.NewEngine(cfg)
	var writer output.Writer
	if cfg.OutputJSON {
		writer = output.NewJSONWriter(os.Stdout)
	} else {
		writer = output.NewTextWriter(os.Stdout, output.TextOptions{
			Color:   useColor,
			Verbose: cfg.Verbose,
		})
	}

	if !cfg.Quiet {
		meta := output.RunMeta{
			Targets:     len(targets),
			Concurrency: cfg.Concurrency,
			Rate:        cfg.RateLimit,
			Timeout:     cfg.Timeout,
			Modules:     modulesFlag,
			OutFile:     outFile,
			Follow:      cfg.Follow,
			Depth:       cfg.Depth,
			MaxURLs:     cfg.MaxURLs,
		}
		output.PrintHeader(os.Stderr, meta, useColor)
	}

	start := time.Now()
	resultsCh := engine.Run(ctx, targets)

	var (
		saved   []scanner.Result
		showBar = !cfg.Quiet && len(targets) > 1
	)

	for r := range resultsCh {
		if outFile != "" || oldReport != nil {
			saved = append(saved, r)
		}
		if err := writer.Write(r); err != nil {
			fatal("write: %v", err)
		}
		if showBar {
			scanned, _ := engine.Stats()
			pct := float64(scanned) / float64(len(targets)) * 100
			elapsed := time.Since(start)
			rate := float64(scanned) / elapsed.Seconds()
			fmt.Fprintf(os.Stderr, "\r[%3.0f%%] %d/%d  %.1f/s  %s",
				pct, scanned, len(targets), rate, elapsed.Round(time.Millisecond))
		}
	}
	_ = writer.Flush()

	if showBar {
		fmt.Fprintln(os.Stderr)
	}

	if outFile != "" {
		if err := diff.SaveReport(outFile, saved); err != nil {
			fatal("save -o: %v", err)
		}
	}

	if oldReport != nil {
		neu := &diff.Report{Version: 1, CreatedAt: time.Now().UTC(), Results: saved}
		changes := diff.Compare(oldReport, neu)
		fmt.Fprint(os.Stderr, "\n"+diff.FormatText(changes, useColor))
	}

	if !cfg.Quiet {
		scanned, failed := engine.Stats()
		output.PrintFooter(os.Stderr, output.DoneMeta{
			Targets: len(targets),
			Scanned: scanned,
			Failed:  failed,
			Elapsed: time.Since(start),
			OutFile: outFile,
			SavedN:  len(saved),
		}, useColor)
	}
}

func collectTargets(args []string, file string) ([]scanner.Target, error) {
	seen := make(map[string]struct{})
	var out []scanner.Target
	add := func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return nil
		}
		t, err := scanner.ParseTarget(s)
		if err != nil {
			return err
		}
		key := strings.ToLower(t.Host) + "\x00" + t.URL
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		out = append(out, t)
		return nil
	}

	for _, a := range args {
		if err := add(a); err != nil {
			return nil, err
		}
	}

	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("open targets file: %w", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		// Allow long spam URLs.
		buf := make([]byte, 0, 64*1024)
		sc.Buffer(buf, 1024*1024)
		for sc.Scan() {
			if err := add(sc.Text()); err != nil {
				return nil, err
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	if len(out) == 0 || (file == "" && len(args) == 0) {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			sc := bufio.NewScanner(os.Stdin)
			buf := make([]byte, 0, 64*1024)
			sc.Buffer(buf, 1024*1024)
			for sc.Scan() {
				if err := add(sc.Text()); err != nil {
					return nil, err
				}
			}
			if err := sc.Err(); err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

func parsePorts(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	var ports []int
	seen := make(map[int]struct{})
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		ports = append(ports, n)
	}
	return ports, nil
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

func parseModules(s string) config.Modules {
	m := config.Modules{}
	for _, part := range strings.Split(strings.ToLower(s), ",") {
		switch strings.TrimSpace(part) {
		case "dns":
			m.DNS = true
		case "tls":
			m.TLS = true
		case "banner", "ports":
			m.Banner = true
		case "http":
			m.HTTP = true
		case "enrich", "enrichment":
			m.Enrich = true
		case "all":
			m = config.Modules{DNS: true, TLS: true, Banner: true, HTTP: true, Enrich: true}
		}
	}
	return m
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "casre: "+format+"\n", args...)
	os.Exit(1)
}

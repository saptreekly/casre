package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/saptreekly/casre/internal/config"
	"github.com/saptreekly/casre/internal/output"
	"github.com/saptreekly/casre/internal/scanner"
	"github.com/saptreekly/casre/internal/tui"
)

func main() {
	if len(os.Args) > 1 {
		a := os.Args[1]
		if a == "-h" || a == "-help" || a == "--help" {
			fmt.Fprint(os.Stderr, `CASRE — interactive recon & phishing-chain TUI

  casre [url…]

Paste URLs in the app (or pass them as arguments), tune options with o,
scan, then browse Story · Chain · Alerts · Indicators · Host · Diff.

Use only against systems you are authorized to test.
`)
			os.Exit(0)
		}
		if strings.HasPrefix(a, "-") {
			fmt.Fprintln(os.Stderr, "casre: TUI only — run `casre` with no flags")
			os.Exit(2)
		}
	}

	if !output.IsStdoutTTY() {
		fmt.Fprintln(os.Stderr, "casre: needs an interactive terminal")
		os.Exit(2)
	}

	cfg := config.Default()
	seed := strings.TrimSpace(strings.Join(os.Args[1:], "\n"))

	err := tui.RunApp(cfg, seed, func(ctx context.Context, scanCfg config.Config, targets []scanner.Target) ([]scanner.Result, error) {
		engine := scanner.NewEngine(scanCfg)
		ch := engine.Run(ctx, targets)
		var out []scanner.Result
		for r := range ch {
			out = append(out, r)
		}
		return out, nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "casre: %v\n", err)
		os.Exit(1)
	}
}

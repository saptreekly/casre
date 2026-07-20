package output

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// RunMeta describes scan run parameters for status framing.
type RunMeta struct {
	Targets     int
	Concurrency int
	Rate        float64
	Timeout     time.Duration
	Modules     string
	OutFile     string
	Follow      bool
	Depth       int
	MaxURLs     int
	Campaign    bool
	HopWorkers  int
	Budget      time.Duration
	EvidenceDir string
}

// DoneMeta summarizes a finished run.
type DoneMeta struct {
	Targets  int
	Scanned  int64
	Failed   int64
	Elapsed  time.Duration
	OutFile  string
	SavedN   int
}

// PrintHeader writes a colorized run banner matching the tree report style.
func PrintHeader(w io.Writer, meta RunMeta, color bool) {
	c := newPalette(color)
	var b strings.Builder

	fmt.Fprintf(&b, "%sCASRE%s  %srecon%s\n", c.bold, c.reset, c.dim, c.reset)

	rate := "unlimited"
	if meta.Rate > 0 {
		rate = fmt.Sprintf("%.0f/s", meta.Rate)
	}

	rows := []struct{ k, v string }{
		{"targets", fmt.Sprintf("%d", meta.Targets)},
		{"workers", fmt.Sprintf("%d", meta.Concurrency)},
		{"rate", rate},
		{"timeout", meta.Timeout.String()},
		{"modules", meta.Modules},
	}
	if meta.Follow {
		mode := "campaign"
		if !meta.Campaign {
			mode = "full"
		}
		rows = append(rows, struct{ k, v string }{
			"follow", fmt.Sprintf("on · %s · depth=%d · max-urls=%d · workers=%d · budget=%s",
				mode, meta.Depth, meta.MaxURLs, meta.HopWorkers, meta.Budget.Round(time.Second)),
		})
	} else {
		rows = append(rows, struct{ k, v string }{"follow", "off"})
	}
	if meta.OutFile != "" {
		rows = append(rows, struct{ k, v string }{"save", meta.OutFile})
	}
	if meta.EvidenceDir != "" {
		rows = append(rows, struct{ k, v string }{"evidence", meta.EvidenceDir})
	}

	for i, row := range rows {
		branch := "├─ "
		if i == len(rows)-1 {
			branch = "└─ "
		}
		fmt.Fprintf(&b, "%s%s%s%s%-8s%s %s\n",
			c.dim, branch, c.reset,
			c.dim, row.k, c.reset,
			row.v,
		)
	}
	_, _ = io.WriteString(w, b.String())
}

// PrintFooter writes a colorized completion summary.
func PrintFooter(w io.Writer, meta DoneMeta, color bool) {
	c := newPalette(color)
	var b strings.Builder

	fmt.Fprintf(&b, "\n%sDONE%s\n", c.section, c.reset)

	rows := []struct {
		k, v, sev string
	}{
		{"scanned", fmt.Sprintf("%d/%d", meta.Scanned, meta.Targets), "ok"},
		{"failed", fmt.Sprintf("%d", meta.Failed), failedSev(meta.Failed)},
		{"elapsed", meta.Elapsed.Round(time.Millisecond).String(), ""},
	}
	if meta.OutFile != "" {
		rows = append(rows, struct{ k, v, sev string }{
			"saved", fmt.Sprintf("%s (%d)", meta.OutFile, meta.SavedN), "",
		})
	}

	for i, row := range rows {
		branch := "├─ "
		if i == len(rows)-1 {
			branch = "└─ "
		}
		valColor := c.value
		switch row.sev {
		case "ok":
			valColor = c.ok
		case "high":
			valColor = c.high
		case "medium":
			valColor = c.medium
		}
		fmt.Fprintf(&b, "%s%s%s%s%-8s%s %s%s%s\n",
			c.dim, branch, c.reset,
			c.dim, row.k, c.reset,
			valColor, row.v, c.reset,
		)
	}
	_, _ = io.WriteString(w, b.String())
}

func failedSev(n int64) string {
	if n > 0 {
		return "medium"
	}
	return "ok"
}

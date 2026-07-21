package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// OptInKeys holds API keys for opt-in reputation sources. Empty keys are skipped.
type OptInKeys struct {
	VirusTotal string
	URLScan    string
	Shodan     string
}

// OptInKeysFromEnv reads keys from the environment. All are optional.
func OptInKeysFromEnv() OptInKeys {
	return OptInKeys{
		VirusTotal: strings.TrimSpace(os.Getenv("CASRE_VT_API_KEY")),
		URLScan:    strings.TrimSpace(os.Getenv("CASRE_URLSCAN_API_KEY")),
		Shodan:     strings.TrimSpace(os.Getenv("CASRE_SHODAN_API_KEY")),
	}
}

// Any reports whether at least one key is configured.
func (k OptInKeys) Any() bool {
	return k.VirusTotal != "" || k.URLScan != "" || k.Shodan != ""
}

// EnrichReputation queries configured opt-in sources for a host and appends
// human-readable notes to the report's Reputation slice. No-op without keys.
func EnrichReputation(ctx context.Context, rep *IntelReport, keys OptInKeys, timeout time.Duration, wait func() error) {
	if rep == nil || !keys.Any() {
		return
	}
	reg := rep.RegDomain
	if reg == "" {
		reg = rep.Host
	}
	client := intelHTTPClient(timeout)

	if keys.VirusTotal != "" {
		if wait != nil {
			_ = wait()
		}
		if note := vtDomainReport(ctx, client, reg, keys.VirusTotal); note != "" {
			rep.Reputation = appendUnique(rep.Reputation, note)
		}
	}
	if keys.URLScan != "" {
		if wait != nil {
			_ = wait()
		}
		if note := urlscanSearch(ctx, client, reg, keys.URLScan); note != "" {
			rep.Reputation = appendUnique(rep.Reputation, note)
		}
	}
	if keys.Shodan != "" && rep.Favicon != nil && rep.Favicon.MMH3 != 0 {
		if wait != nil {
			_ = wait()
		}
		if note := shodanFaviconCount(ctx, client, rep.Favicon.MMH3, keys.Shodan); note != "" {
			rep.Reputation = appendUnique(rep.Reputation, note)
		}
	}
}

func vtDomainReport(ctx context.Context, client *http.Client, domain, key string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://www.virustotal.com/api/v3/domains/"+url.PathEscape(domain), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("x-apikey", key)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	var out struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
				Reputation int `json:"reputation"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return ""
	}
	s := out.Data.Attributes.LastAnalysisStats
	if s.Malicious == 0 && s.Suspicious == 0 {
		return ""
	}
	return fmt.Sprintf("VirusTotal: %d malicious / %d suspicious engines (reputation %d)",
		s.Malicious, s.Suspicious, out.Data.Attributes.Reputation)
}

func urlscanSearch(ctx context.Context, client *http.Client, domain, key string) string {
	q := url.QueryEscape("domain:" + domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://urlscan.io/api/v1/search/?q="+q+"&size=1", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("API-Key", key)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	var out struct {
		Total   int `json:"total"`
		Results []struct {
			Verdicts struct {
				Overall struct {
					Malicious bool `json:"malicious"`
					Score     int  `json:"score"`
				} `json:"overall"`
			} `json:"verdicts"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Total == 0 {
		return ""
	}
	note := fmt.Sprintf("urlscan.io: %d prior scan(s)", out.Total)
	if len(out.Results) > 0 && out.Results[0].Verdicts.Overall.Malicious {
		note += fmt.Sprintf(", latest flagged malicious (score %d)", out.Results[0].Verdicts.Overall.Score)
	}
	return note
}

func shodanFaviconCount(ctx context.Context, client *http.Client, mmh3 int32, key string) string {
	q := url.QueryEscape(fmt.Sprintf("http.favicon.hash:%d", mmh3))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.shodan.io/shodan/host/count?query="+q+"&key="+url.QueryEscape(key), nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	var out struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Total <= 1 {
		return ""
	}
	return fmt.Sprintf("Shodan: favicon hash matches %d hosts (infra cluster)", out.Total)
}

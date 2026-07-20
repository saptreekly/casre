package scanner

import (
	"net"
	"sort"
	"strings"
)

// IOC is one indicator extracted from a scan result.
type IOC struct {
	Type     string `json:"type"` // domain, ip, url, asn
	Value    string `json:"value"`
	Context  string `json:"context,omitempty"`
	Severity string `json:"severity,omitempty"`
	Host     string `json:"host,omitempty"`
}

// IOCSet is a deduped indicator bundle for SIEM / MISP / spreadsheets.
type IOCSet struct {
	Domains []IOC `json:"domains,omitempty"`
	IPs     []IOC `json:"ips,omitempty"`
	URLs    []IOC `json:"urls,omitempty"`
	ASNs    []IOC `json:"asns,omitempty"`
	All     []IOC `json:"all,omitempty"`
}

// ExtractIOCs collects domains, IPs, URLs, and ASNs from a result.
func ExtractIOCs(r Result) *IOCSet {
	set := &IOCSet{}
	seen := map[string]struct{}{}
	add := func(typ, value, ctx, sev, host string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := typ + "\x00" + strings.ToLower(value)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		ioc := IOC{Type: typ, Value: value, Context: ctx, Severity: sev, Host: host}
		set.All = append(set.All, ioc)
		switch typ {
		case "domain":
			set.Domains = append(set.Domains, ioc)
		case "ip":
			set.IPs = append(set.IPs, ioc)
		case "url":
			set.URLs = append(set.URLs, ioc)
		case "asn":
			set.ASNs = append(set.ASNs, ioc)
		}
	}

	sevForHost := func(host string) string {
		if r.Graph != nil {
			for _, n := range r.Graph.Nodes {
				if HostEqual(n.Host, host) {
					switch n.Role {
					case RoleCloaker, RoleLander:
						return "high"
					case RoleTracker, RoleDeepview:
						return "medium"
					case RoleDecoy:
						return "info"
					}
				}
			}
		}
		return "medium"
	}

	if r.Host != "" && net.ParseIP(r.Host) == nil {
		add("domain", r.Host, "seed", sevForHost(r.Host), r.Host)
	}
	if r.FinalHost != "" && net.ParseIP(r.FinalHost) == nil {
		add("domain", r.FinalHost, "final", sevForHost(r.FinalHost), r.FinalHost)
	}
	if r.InputURL != "" {
		add("url", stripFragment(r.InputURL), "seed", "medium", r.Host)
	}
	if r.RawInput != "" && strings.Contains(r.RawInput, "://") {
		add("url", r.RawInput, "raw-input", "medium", r.Host)
	}

	if r.Graph != nil {
		for _, n := range r.Graph.Nodes {
			ctx := n.Role
			if ctx == "" {
				ctx = "graph"
			}
			if n.Host != "" && net.ParseIP(n.Host) == nil {
				add("domain", n.Host, ctx, sevForHost(n.Host), n.Host)
			}
			if n.URL != "" {
				add("url", n.URL, ctx, sevForHost(n.Host), n.Host)
			}
		}
	}

	for _, h := range r.Hops {
		if h.Host != "" && net.ParseIP(h.Host) == nil {
			add("domain", h.Host, "hop", sevForHost(h.Host), h.Host)
		}
		if h.URL != "" {
			add("url", h.URL, "hop", sevForHost(h.Host), h.Host)
		}
		if h.Page != nil {
			for _, d := range h.Page.Destinations {
				add("url", d, "destination", "high", HostFromURL(d))
				if dh := HostFromURL(d); dh != "" && net.ParseIP(dh) == nil {
					add("domain", dh, "destination", "high", dh)
				}
			}
			for _, d := range h.Page.Downloads {
				add("url", d, "download", "high", HostFromURL(d))
			}
		}
		if h.Probe != nil && h.Probe.FinalURL != "" {
			add("url", h.Probe.FinalURL, "redirect", "medium", h.Probe.FinalHost)
		}
	}

	if r.Page != nil {
		for _, d := range r.Page.Destinations {
			add("url", d, "destination", "high", HostFromURL(d))
			if dh := HostFromURL(d); dh != "" {
				add("domain", dh, "destination", "high", dh)
			}
		}
	}

	if r.DNS != nil {
		for _, ip := range append(append([]string{}, r.DNS.A...), r.DNS.AAAA...) {
			add("ip", ip, "dns", "info", r.Host)
		}
	}
	if r.Enrich != nil {
		for _, a := range r.Enrich.ASN {
			if a.IP != "" {
				add("ip", a.IP, "asn", "info", r.Host)
			}
			if a.ASN != "" {
				val := "AS" + strings.TrimPrefix(a.ASN, "AS")
				if a.ASName != "" {
					val += " " + a.ASName
				}
				add("asn", val, "enrich", "info", r.Host)
			}
		}
	}

	sort.SliceStable(set.All, func(i, j int) bool {
		if set.All[i].Type != set.All[j].Type {
			return set.All[i].Type < set.All[j].Type
		}
		return set.All[i].Value < set.All[j].Value
	})
	if len(set.All) == 0 {
		return nil
	}
	return set
}

func stripFragment(u string) string {
	if i := strings.IndexByte(u, '#'); i >= 0 {
		return u[:i]
	}
	return u
}

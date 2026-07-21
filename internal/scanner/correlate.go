package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// Cluster groups scanned targets that share infrastructure or tooling.
type Cluster struct {
	Reason  string   `json:"reason"`  // "shared IP", "shared ASN", "shared cert", "shared favicon", "shared kit"
	Key     string   `json:"key"`     // the shared value
	Members []string `json:"members"` // hosts in the cluster (>=2)
}

// CorrelateCampaigns finds cross-target links (shared IP, ASN, cert serial,
// favicon hash, kit fingerprint) across a batch of results. It also annotates
// each result's IntelReport with its campaign peers.
func CorrelateCampaigns(results []Result) []Cluster {
	if len(results) < 2 {
		return nil
	}

	type dim struct {
		reason string
		values func(r Result) []string
	}
	dims := []dim{
		{"shared IP", func(r Result) []string {
			var v []string
			if r.DNS != nil {
				v = append(v, r.DNS.A...)
				v = append(v, r.DNS.AAAA...)
			}
			for _, a := range asnList(r) {
				if a.IP != "" {
					v = append(v, a.IP)
				}
			}
			return v
		}},
		{"shared ASN", func(r Result) []string {
			var v []string
			for _, a := range asnList(r) {
				if a.ASN != "" {
					v = append(v, "AS"+strings.TrimPrefix(a.ASN, "AS"))
				}
			}
			return v
		}},
		{"shared cert", func(r Result) []string {
			if r.TLS == nil || len(r.TLS.Chain) == 0 {
				return nil
			}
			leaf := r.TLS.Chain[0]
			if leaf.SerialNumber == "" {
				return nil
			}
			return []string{leaf.SerialNumber + " (" + shortSubject(leaf.Issuer) + ")"}
		}},
		{"shared favicon", func(r Result) []string {
			if r.Intel != nil && r.Intel.Favicon != nil && r.Intel.Favicon.MMH3 != 0 {
				return []string{fmt.Sprintf("mmh3:%d", r.Intel.Favicon.MMH3)}
			}
			return nil
		}},
		{"shared kit", func(r Result) []string {
			return kitFingerprints(r)
		}},
	}

	// value -> reason -> set of member hosts
	type bucket struct {
		reason  string
		key     string
		members map[string]struct{}
	}
	buckets := map[string]*bucket{}
	for _, d := range dims {
		for _, r := range results {
			host := strings.ToLower(strings.TrimSpace(r.Host))
			if host == "" {
				continue
			}
			for _, val := range d.values(r) {
				val = strings.TrimSpace(val)
				if val == "" {
					continue
				}
				k := d.reason + "\x00" + val
				b := buckets[k]
				if b == nil {
					b = &bucket{reason: d.reason, key: val, members: map[string]struct{}{}}
					buckets[k] = b
				}
				b.members[host] = struct{}{}
			}
		}
	}

	var clusters []Cluster
	peers := map[string]map[string]struct{}{}
	for _, b := range buckets {
		if len(b.members) < 2 {
			continue
		}
		members := make([]string, 0, len(b.members))
		for h := range b.members {
			members = append(members, h)
		}
		sort.Strings(members)
		clusters = append(clusters, Cluster{Reason: b.reason, Key: b.key, Members: members})
		for _, h := range members {
			if peers[h] == nil {
				peers[h] = map[string]struct{}{}
			}
			for _, other := range members {
				if other != h {
					peers[h][other] = struct{}{}
				}
			}
		}
	}

	sort.SliceStable(clusters, func(i, j int) bool {
		if len(clusters[i].Members) != len(clusters[j].Members) {
			return len(clusters[i].Members) > len(clusters[j].Members)
		}
		if clusters[i].Reason != clusters[j].Reason {
			return clusters[i].Reason < clusters[j].Reason
		}
		return clusters[i].Key < clusters[j].Key
	})

	for i := range results {
		host := strings.ToLower(strings.TrimSpace(results[i].Host))
		set := peers[host]
		if len(set) == 0 {
			continue
		}
		list := make([]string, 0, len(set))
		for p := range set {
			list = append(list, p)
		}
		sort.Strings(list)
		if results[i].Intel == nil {
			results[i].Intel = &IntelReport{Host: results[i].Host, RegDomain: RegistrableDomain(results[i].Host)}
		}
		results[i].Intel.CampaignPeers = list
	}

	return clusters
}

func asnList(r Result) []ASNInfo {
	if r.Enrich == nil {
		return nil
	}
	return r.Enrich.ASN
}

func kitFingerprints(r Result) []string {
	set := map[string]struct{}{}
	collect := func(p *PageAnalysis) {
		if p == nil {
			return
		}
		for _, k := range p.Kits {
			set[strings.ToLower(strings.TrimSpace(k))] = struct{}{}
		}
	}
	collect(r.Page)
	for _, h := range r.Hops {
		collect(h.Page)
	}
	var out []string
	for k := range set {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

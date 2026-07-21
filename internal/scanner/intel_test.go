package scanner

import (
	"strings"
	"testing"
	"time"
)

func TestMurmur3FaviconVectors(t *testing.T) {
	// Reference values from Python's mmh3.hash(seed=0), signed int32.
	cases := map[string]int32{
		"":      0,
		"foo":   -156908512,
		"hello": 613153351,
	}
	for in, want := range cases {
		got := int32(murmur3Hash32([]byte(in)))
		if got != want {
			t.Errorf("murmur3Hash32(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"login.evil.co.uk": "evil.co.uk",
		"a.b.example.com":  "example.com",
		"example.com":      "example.com",
		"1.2.3.4":          "",
	}
	for in, want := range cases {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRDAP(t *testing.T) {
	body := []byte(`{
		"events": [
			{"eventAction": "registration", "eventDate": "2020-01-02T00:00:00Z"},
			{"eventAction": "expiration", "eventDate": "2030-01-02T00:00:00Z"}
		],
		"entities": [
			{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]]}
		],
		"nameservers": [{"ldhName": "ns1.example.com"}],
		"status": ["client transfer prohibited"]
	}`)
	d := parseRDAP(body)
	if d == nil {
		t.Fatal("parseRDAP returned nil")
	}
	if d.Registrar != "Example Registrar, Inc." {
		t.Errorf("registrar = %q", d.Registrar)
	}
	if d.CreatedAt.Year() != 2020 {
		t.Errorf("created = %v", d.CreatedAt)
	}
	if d.AgeDays <= 0 {
		t.Errorf("age = %d, want > 0", d.AgeDays)
	}
	if len(d.Nameservers) != 1 || d.Nameservers[0] != "ns1.example.com" {
		t.Errorf("nameservers = %v", d.Nameservers)
	}
}

func TestParseCTSiblings(t *testing.T) {
	body := []byte(`[
		{"name_value": "www.evil.com\n*.evil.com"},
		{"name_value": "login.evil.com"},
		{"name_value": "login.evil.com"},
		{"name_value": "unrelated.example.org"},
		{"name_value": "evil.com"}
	]`)
	sibs, total := parseCTSiblings(body, "evil.com")
	if total != 2 {
		t.Fatalf("total = %d, want 2 (login + www)", total)
	}
	joined := strings.Join(sibs, ",")
	if !strings.Contains(joined, "login.evil.com") || !strings.Contains(joined, "www.evil.com") {
		t.Errorf("siblings = %v", sibs)
	}
	if strings.Contains(joined, "unrelated") || strings.Contains(joined, "evil.com,") && sibs[0] == "evil.com" {
		t.Errorf("apex/unrelated leaked into siblings: %v", sibs)
	}
}

func TestLookalikeScore(t *testing.T) {
	cases := []struct {
		host      string
		wantBrand string
		wantHit   bool
	}{
		{"paypa1.com", "paypal", true},
		{"micros0ft-login.com", "microsoft", true},
		{"paypal.com", "", false},
		{"accounts.google.com", "", false},
		{"example.com", "", false},
	}
	for _, c := range cases {
		brand, score := LookalikeScore(c.host)
		if c.wantHit && brand != c.wantBrand {
			t.Errorf("LookalikeScore(%q) = %q (score %d), want brand %q", c.host, brand, score, c.wantBrand)
		}
		if !c.wantHit && brand != "" {
			t.Errorf("LookalikeScore(%q) = %q (score %d), want no hit", c.host, brand, score)
		}
	}
}

func TestDGAScore(t *testing.T) {
	if score, _ := DGAScore("google.com"); score >= 60 {
		t.Errorf("google DGA score = %d, want low", score)
	}
	if score, _ := DGAScore("xkfjqzwvhbnmld.com"); score < 60 {
		t.Errorf("random host DGA score = %d, want >= 60", score)
	}
}

func TestTLSTrust(t *testing.T) {
	r := Result{TLS: &TLSResult{Chain: []CertInfo{{
		Subject:      "CN=evil.com",
		Issuer:       "CN=evil.com",
		NotBefore:    time.Now().Add(-2 * time.Hour),
		DaysUntilExp: 89,
	}}}}
	score, notes := TLSTrust(r)
	if score < 40 {
		t.Errorf("self-signed + fresh TLS distrust = %d, want >= 40 (%v)", score, notes)
	}
	if TLSTrust(Result{}); len(notes) == 0 {
		t.Errorf("expected notes for self-signed cert")
	}
}

func TestCorrelateCampaignsSharedIP(t *testing.T) {
	results := []Result{
		{Host: "a.com", DNS: &DNSResult{A: []string{"1.2.3.4"}}},
		{Host: "b.com", DNS: &DNSResult{A: []string{"1.2.3.4"}}},
		{Host: "c.com", DNS: &DNSResult{A: []string{"9.9.9.9"}}},
	}
	clusters := CorrelateCampaigns(results)
	if len(clusters) == 0 {
		t.Fatal("expected at least one cluster")
	}
	found := false
	for _, cl := range clusters {
		if cl.Reason == "shared IP" && cl.Key == "1.2.3.4" && len(cl.Members) == 2 {
			found = true
		}
	}
	if !found {
		t.Errorf("shared IP cluster not found: %+v", clusters)
	}
	// a.com and b.com should be annotated as peers; c.com should not.
	if results[0].Intel == nil || len(results[0].Intel.CampaignPeers) != 1 || results[0].Intel.CampaignPeers[0] != "b.com" {
		t.Errorf("a.com peers = %+v", results[0].Intel)
	}
	if results[2].Intel != nil && len(results[2].Intel.CampaignPeers) > 0 {
		t.Errorf("c.com should have no peers, got %+v", results[2].Intel.CampaignPeers)
	}
}

func TestDefangIOC(t *testing.T) {
	cases := map[string]string{
		"http://evil.com/login": "hxxp[://]evil[.]com/login",
		"evil.com":              "evil[.]com",
		"1.2.3.4":               "1[.]2[.]3[.]4",
	}
	for in, want := range cases {
		if got := DefangIOC(in); got != want {
			t.Errorf("DefangIOC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExportIOCsCSVAndSTIX(t *testing.T) {
	set := &IOCSet{All: []IOC{
		{Type: "domain", Value: "evil.com", Context: "seed", Severity: "high", Host: "evil.com"},
		{Type: "ip", Value: "1.2.3.4", Context: "dns", Severity: "info", Host: "evil.com"},
		{Type: "url", Value: "http://evil.com/x", Context: "hop", Severity: "medium", Host: "evil.com"},
	}}
	csv := ExportIOCsCSV(set)
	if !strings.Contains(csv, "type,value,defanged") || !strings.Contains(csv, "evil[.]com") {
		t.Errorf("CSV missing header or defanged value:\n%s", csv)
	}
	stix := ExportIOCsSTIX(set, "evil.com")
	if !strings.Contains(stix, `"type": "bundle"`) {
		t.Errorf("STIX not a bundle:\n%s", stix)
	}
	if strings.Count(stix, `"type": "indicator"`) != 3 {
		t.Errorf("expected 3 STIX indicators:\n%s", stix)
	}
	if !strings.Contains(stix, "domain-name:value = 'evil.com'") {
		t.Errorf("STIX missing domain pattern:\n%s", stix)
	}
}

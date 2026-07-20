package output

import (
	"strings"
	"testing"
)

func TestCompactURLNotableKeys(t *testing.T) {
	raw := "http://foxfigure.com/public/?:nav=default::index&go=1&s1=2313506&s2=810546196"
	got := CompactURL(raw)
	if !strings.Contains(got, "foxfigure.com") {
		t.Fatalf("host missing: %q", got)
	}
	if !strings.Contains(got, "go=1") || !strings.Contains(got, "s1=") {
		t.Fatalf("notable keys missing: %q", got)
	}
	if strings.Contains(got, "base64") {
		t.Fatalf("unexpected base64: %q", got)
	}
}

func TestCompactURLCollapsesBase64Param(t *testing.T) {
	raw := "http://foxfigure.com/?var=Om5hdj1jbGljazo6dHJhY2tlciZkZXBsb3k9MjMxMzUwNiZ1c2VyPWp3ZWVrbHk="
	got := CompactURL(raw)
	if !strings.Contains(got, "var=‹base64›") {
		t.Fatalf("expected collapsed var, got %q", got)
	}
	if strings.Contains(got, "Om5hdj1jbGljazo6") {
		t.Fatalf("raw base64 leaked: %q", got)
	}
}

func TestCompactURLPathAndHost(t *testing.T) {
	raw := "https://storage.googleapis.com/264you/HREFB.html"
	got := CompactURL(raw)
	if got != "https://storage.googleapis.com/264you/HREFB.html" {
		t.Fatalf("got %q", got)
	}
}

func TestCampaignSummary(t *testing.T) {
	got := CampaignSummary([]string{
		"storage.googleapis.com",
		"49.13.68.203",
		"foxfigure.com",
		"foxfigure.com",
		"foxfigure.com",
		"www.unotosite.com",
	})
	want := "storage.googleapis.com → 49.13.68.203 → foxfigure.com ×3 → www.unotosite.com"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

package scanner_test

import (
	"strings"
	"testing"

	"github.com/saptreekly/casre/internal/scanner"
)

func TestParseTargetHost(t *testing.T) {
	got, err := scanner.ParseTarget("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "example.com" || got.URL != "" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseTargetURLKeepsQuery(t *testing.T) {
	raw := "https://storage.googleapis.com/devilex/devilex1.html?act=cl&pid=9359_md&uid=2"
	got, err := scanner.ParseTarget(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "storage.googleapis.com" {
		t.Fatalf("host=%q", got.Host)
	}
	if !strings.Contains(got.URL, "act=cl") || !strings.Contains(got.URL, "pid=9359_md") {
		t.Fatalf("url lost query: %q", got.URL)
	}
}

func TestParseTargetStripsFragment(t *testing.T) {
	got, err := scanner.ParseTarget("https://example.com/a#frag")
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://example.com/a" {
		t.Fatalf("expected fragment stripped from wire url, got %q", got.URL)
	}
	if got.Fragment != "frag" {
		t.Fatalf("expected fragment retained, got %q", got.Fragment)
	}
}

func TestParseTargetHiddenQueryInFragment(t *testing.T) {
	raw := "https://storage.googleapis.com/devilex/devilex1.html#?act=cl&pid=9359_md&uid=2"
	got, err := scanner.ParseTarget(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://storage.googleapis.com/devilex/devilex1.html" {
		t.Fatalf("wire url=%q", got.URL)
	}
	if !scanner.FragmentLooksLikeQuery(got.Fragment) {
		t.Fatalf("expected fragment query detection for %q", got.Fragment)
	}
}

func TestDecodeBase64QueryFragment(t *testing.T) {
	frag := "?Z289MSZzMT0yMzEzNTA2JnMyPTgxMDU0NjE5NiZzMz1HTEI="
	decoded, ok := scanner.DecodeBase64QueryFragment(frag)
	if !ok {
		t.Fatal("expected base64 decode success")
	}
	if decoded != "go=1&s1=2313506&s2=810546196&s3=GLB" {
		t.Fatalf("decoded=%q", decoded)
	}

	t.Run("url findings", func(t *testing.T) {
		tgt, err := scanner.ParseTarget("https://storage.googleapis.com/264you/HREFB.html" + "#" + frag)
		if err != nil {
			t.Fatal(err)
		}
		findings := scanner.URLFindings(tgt, nil)
		var sawDecode, sawParams bool
		for _, f := range findings {
			if strings.Contains(f.Message, "base64-decodes to query:") && strings.Contains(f.Message, "go=1") {
				sawDecode = true
			}
			if strings.Contains(f.Message, "decoded fragment params:") &&
				strings.Contains(f.Message, "go") &&
				strings.Contains(f.Message, "s1") &&
				strings.Contains(f.Message, "s3") {
				sawParams = true
			}
		}
		if !sawDecode || !sawParams {
			t.Fatalf("missing decode findings: %+v", findings)
		}
	})
}

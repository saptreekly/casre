package output

import (
	"strings"
	"testing"
)

func TestWrapValueBreaksAtSeparators(t *testing.T) {
	u := "https://storage.googleapis.com/264you/HREFB.html#?Z289MSZzMT0yMzEzNTA2JnMyPTgxMDU0NjE5NiZzMz1HTEI="
	parts := wrapValue(u, 56)
	if len(parts) < 2 {
		t.Fatalf("expected wrap, got %v", parts)
	}
	joined := strings.Join(parts, "")
	if joined != u {
		t.Fatalf("wrap lost data:\n got %q\nwant %q", joined, u)
	}
	if !strings.HasSuffix(parts[0], ".html") {
		t.Fatalf("expected break before fragment, got first=%q", parts[0])
	}
	if !strings.HasPrefix(parts[1], "#?") {
		t.Fatalf("expected fragment on continuation, got %q", parts[1])
	}
}

func TestWrapValueShortUnchanged(t *testing.T) {
	got := wrapValue("hello", 40)
	if len(got) != 1 || got[0] != "hello" {
		t.Fatalf("got %v", got)
	}
}

func TestSectionKeyWidth(t *testing.T) {
	w := sectionKeyWidth([]treeLine{
		{key: "input"},
		{key: "fragment"},
		{key: "finalhost"},
		{key: "js-redir"},
	})
	if w != 9 { // finalhost
		t.Fatalf("key width=%d want 9", w)
	}
}

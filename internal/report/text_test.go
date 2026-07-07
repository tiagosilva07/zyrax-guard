package report

import (
	"strings"
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

func blockResult(msg string) verdict.Result {
	return verdict.Result{
		Ecosystem:  "npm",
		Name:       "evil-pkg",
		Version:    "1.0.0",
		Verdict:    verdict.Block,
		VerdictStr: "BLOCK",
		Signals:    []verdict.Signal{{Check: verdict.RuleKnownMalware, Level: verdict.LevelBlock, Message: msg}},
	}
}

func TestTextReportBasic(t *testing.T) {
	var b strings.Builder
	if err := (&Text{W: &b}).Report([]verdict.Result{blockResult("MAL-1: bad package")}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"✗ evil-pkg@1.0.0 — BLOCK", "MAL-1: bad package", "to override:  zyrax-guard allow evil-pkg"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// Advisory summaries come from OSV — community-influenceable content. Raw ANSI
// escapes in a summary could forge a "✓ SAFE" line over a real BLOCK verdict;
// raw newlines could forge whole extra result lines.
func TestTextReportSanitizesRegistryStrings(t *testing.T) {
	var b strings.Builder
	msg := "MAL-2: bad\x1b[2K\x1b[32m✓ evil-pkg@1.0.0 — SAFE\nfake-line" + string(rune(0x200B)) + "hidden"
	if err := (&Text{W: &b}).Report([]verdict.Result{blockResult(msg)}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "\x1b[2K") {
		t.Errorf("ANSI escape from advisory summary leaked to terminal:\n%q", out)
	}
	if strings.Contains(out, string(rune(0x200B))) {
		t.Errorf("zero-width rune leaked to terminal:\n%q", out)
	}
	if strings.Contains(out, "\nfake-line") {
		t.Errorf("injected newline leaked — spoofed output line possible:\n%q", out)
	}
	if !strings.Contains(out, "MAL-2: bad") {
		t.Errorf("legitimate advisory text lost:\n%q", out)
	}
}

func TestSanitize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain text", "plain text"},
		{"esc\x1b[31mred", "esc[31mred"}, // ESC dropped, printable remainder kept
		{"a\nb\rc\td", "a b c d"},        // line/format breaks become spaces
		{"zero" + string(rune(0x200B)) + "width" + string(rune(0x2066)) + "bidi", "zerowidthbidi"}, // Cf runes dropped
		{"del\x7fchar", "delchar"},           // DEL dropped
		{"ünïcode – ok ✓", "ünïcode – ok ✓"}, // normal unicode untouched
	}
	for _, c := range cases {
		if got := Sanitize(c.in); got != c.want {
			t.Errorf("Sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

package report

import (
	"strings"
	"unicode"
)

// Sanitize strips control and hidden-format runes from registry-derived text
// before it reaches a terminal or an AI agent. OSV advisory summaries (and any
// other registry metadata) are community-influenceable: raw ANSI escapes can
// forge or overwrite verdict lines, hidden unicode can smuggle instructions,
// and raw newlines can spoof extra output lines. Line breaks and tabs become a
// single space; every other rune in the unicode C categories (control, format,
// surrogate, private-use) is dropped. Printable text passes through untouched.
func Sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			if !space {
				b.WriteRune(' ')
				space = true
			}
		case unicode.In(r, unicode.C):
			// dropped: ESC and other controls, zero-width/bidi format runes
		default:
			b.WriteRune(r)
			space = false
		}
	}
	return b.String()
}

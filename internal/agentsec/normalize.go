// Package-level note: foldForMatch produces a lossy, lowercased view of text used ONLY
// for keyword/pattern matching against obfuscated agent configs. Excerpts and line numbers
// must come from the original text, never from this folded form.
package agentsec

import (
	"strings"
	"unicode"
)

// homoglyphs maps common non-Latin look-alikes to their ASCII equivalent.
var homoglyphs = map[rune]rune{
	// Cyrillic
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
	'х': 'x', 'у': 'y', 'і': 'i', 'ѕ': 's', 'һ': 'h',
	'А': 'a', 'Е': 'e', 'О': 'o', 'Р': 'p', 'С': 'c', 'Х': 'x',
	// Greek
	'ο': 'o', 'α': 'a', 'ε': 'e', 'ρ': 'p', 'υ': 'u', 'ι': 'i',
}

// leet maps leetspeak digits/symbols to letters (lossy — keyword check only).
var leet = map[rune]rune{
	'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's',
}

// stripFormatRunes drops Unicode format/zero-width/control characters that smuggle
// instructions past human review and substring matching.
func stripFormatRunes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		// unicode.Cf covers zero-width spaces, bidi controls, BOM, word joiners, etc.
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		// Explicit BOM (U+FEFF) — also in Cf but belt-and-suspenders.
		if r == 0xFEFF {
			continue
		}
		// Word joiner / invisible operators U+2060–U+2064 (also in Cf).
		if r >= 0x2060 && r <= 0x2064 {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// foldRune normalizes a single rune: full-width → ASCII, homoglyph → ASCII, then lowercase.
func foldRune(r rune) rune {
	// Full-width ASCII block: U+FF01 (！) to U+FF5E (～)
	if r >= 0xFF01 && r <= 0xFF5E {
		r = r - 0xFF01 + '!'
	}
	if m, ok := homoglyphs[r]; ok {
		r = m
	}
	return unicode.ToLower(r)
}

// foldForMatch returns a lowercased, de-obfuscated, separator-collapsed view of s for
// keyword/substring matching: strips format runes, folds homoglyphs/full-width/leet, and
// collapses any run of non-alphanumeric characters (including newlines) to a single space.
func foldForMatch(s string) string {
	s = stripFormatRunes(s)
	var b strings.Builder
	b.Grow(len(s))
	lastWasSep := false
	for _, r := range s {
		r = foldRune(r)
		if l, ok := leet[r]; ok {
			r = l
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			lastWasSep = false
			continue
		}
		if !lastWasSep {
			b.WriteByte(' ')
			lastWasSep = true
		}
	}
	return strings.TrimSpace(b.String())
}

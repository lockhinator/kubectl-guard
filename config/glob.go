package config

// Glob matching for context and namespace name patterns.
//
// Context and namespace names are NAMES, not filesystem paths, so they are
// matched with shell-like glob semantics rather than path semantics. This
// package deliberately does not use path/filepath.Match, which:
//
//   - refuses to let '*' or '?' cross a '/' separator, so `prod-*` does not
//     match `prod/us/east/1` and `*prod*` does not match `a/prod/b`;
//   - is OS-dependent (on Windows '\' is a separator and escaping is disabled),
//     so the same config protects different clusters on different machines;
//   - returns ErrBadPattern for a malformed pattern such as `prod-[`. Callers
//     that ignore that error (as this package once did) silently protect
//     NOTHING — a security tool failing open on a typo.
//
// matchGlob is total: it never returns an error, and a malformed pattern
// degrades to a literal match rather than to "matches nothing" via a dropped
// error. Reporting malformed patterns to the user is the job of config
// validation, not of the matcher.
//
// Supported syntax:
//
//	*        matches any sequence of characters, including '/' and ':'
//	?        matches exactly one character
//	[abc]    matches one character in the set
//	[a-z]    matches one character in the range
//	[^abc]   matches one character NOT in the set
//	\x       matches the literal character x (escapes *, ?, [, and \)
//
// An unterminated '[' matches a literal '['. A trailing '\' matches a literal
// '\'. Matching is over runes, so a multi-byte character counts as one '?'.
//
// Only '^' negates a class. '!' is an ordinary set member, NOT a negation,
// even though most shells accept '[!abc]'. This is deliberate and load-bearing:
// filepath.Match (the previous implementation) also treats '!' as a literal, so
// honoring '[!abc]' as a negation would make an upgrade turn `prod-[!a]` from
// "protects prod-a and prod-!" into "protects everything except prod-a" —
// silently UN-protecting a context.
//
// The governing invariant is: for any single-byte name, filepath.Match matching
// implies matchGlob matches. In other words, swapping in this matcher can only
// ever protect MORE, never less. TestGlobNeverNarrowsVsFilepathMatch enforces it
// by differential testing against filepath.Match.
//
// The invariant is stated over single-byte names because filepath.Match walks the
// name byte-by-byte underneath a '*', letting a '?' or a class match a
// continuation byte of a multi-byte rune decoded alone as utf8.RuneError
// (filepath.Match("*??", "怀") is true). matchGlob is rune-based and does not
// reproduce that. No realistic context or namespace name is affected — they are
// ASCII — and the family is pinned by TestGlobIsRuneBasedNotByteBased.

// matchGlob reports whether name matches the glob pattern. It is OS-independent
// and treats every character in name — including '/' — as an ordinary rune.
func matchGlob(pattern, name string) bool {
	pat := []rune(pattern)
	str := []rune(name)

	// Iterative backtracking: on a mismatch, rewind to the most recent '*' and
	// let it absorb one more character. This is O(len(pat)*len(str)) worst case
	// with no recursion, so a pathological pattern cannot blow the stack.
	p, s := 0, 0
	starP, starS := -1, 0

	for s < len(str) {
		if p < len(pat) && pat[p] == '*' {
			// Remember where the star was, and try matching the rest of the
			// pattern against the rest of the string with the star absorbing
			// nothing so far.
			starP, starS = p, s
			p++
			continue
		}
		if p < len(pat) {
			if next, ok := matchOne(pat, p, str[s]); ok {
				p = next
				s++
				continue
			}
		}
		if starP >= 0 {
			// Mismatch after a star: give the star one more character.
			starS++
			s = starS
			p = starP + 1
			continue
		}
		return false
	}

	// The string is exhausted; the pattern matches only if what remains is
	// stars (each absorbing the empty string).
	for p < len(pat) && pat[p] == '*' {
		p++
	}
	return p == len(pat)
}

// matchOne matches the single pattern unit starting at pat[p] against the rune
// r, returning the index just past that unit. A "unit" is one of: '?', an
// escaped literal, a '[...]' character class, or a plain literal. It is never
// called with pat[p] == '*'.
func matchOne(pat []rune, p int, r rune) (next int, ok bool) {
	switch pat[p] {
	case '?':
		return p + 1, true
	case '\\':
		if p+1 < len(pat) {
			return p + 2, pat[p+1] == r
		}
		// Trailing backslash: match it literally rather than eat the pattern.
		return p + 1, r == '\\'
	case '[':
		return matchClass(pat, p, r)
	default:
		return p + 1, pat[p] == r
	}
}

// matchClass matches a '[...]' character class starting at pat[p] (which is
// '[') against r, returning the index just past the closing ']'.
//
// An unterminated class is not an error: '[' matches itself literally, and the
// caller continues from the next rune. That keeps matchGlob total, so a typo in
// a protected-context pattern degrades predictably instead of being swallowed
// as "no match" (i.e. "not protected").
//
// Only '^' negates. See the package comment: treating '!' as a negation would
// narrow `[!a]` relative to filepath.Match and un-protect a context on upgrade.
func matchClass(pat []rune, p int, r rune) (next int, ok bool) {
	i := p + 1

	negated := false
	if i < len(pat) && pat[i] == '^' {
		negated = true
		i++
	}

	matched := false
	// A ']' immediately after '[' (or after the negation) is a literal member,
	// not the terminator — the POSIX rule.
	first := true

	for i < len(pat) {
		if pat[i] == ']' && !first {
			return i + 1, matched != negated
		}
		first = false

		// Read the low atom. Both endpoints of a range must be read through
		// classAtom so that an escaped endpoint (`[\*-z]`, `[a-\z]`) is decoded
		// to the character it escapes. Reading the range endpoints raw silently
		// produced a NARROWER set than filepath.Match — which un-protects a
		// context on upgrade. See TestClassRangeEndpointsHonorEscapes.
		lo, next := classAtom(pat, i)
		i = next

		// A '-' followed by anything but the class terminator makes this a range.
		if i+1 < len(pat) && pat[i] == '-' && pat[i+1] != ']' {
			hi, next := classAtom(pat, i+1)
			i = next
			if lo <= r && r <= hi {
				matched = true
			}
			continue
		}

		if lo == r {
			matched = true
		}
	}

	// Unterminated class: '[' is a literal.
	return p + 1, r == '['
}

// classAtom reads the single character-class atom at pat[i] — either an escaped
// character ('\x' -> x) or a plain rune — and returns it with the index just
// past it. It is the only place a class member or range endpoint is decoded, so
// escapes cannot be honored in one position and ignored in another.
func classAtom(pat []rune, i int) (rune, int) {
	if pat[i] == '\\' && i+1 < len(pat) {
		return pat[i+1], i + 2
	}
	return pat[i], i + 1
}

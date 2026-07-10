package config

import (
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		// Literals.
		{"exact match", "prod-cluster", "prod-cluster", true},
		{"literal mismatch", "prod-cluster", "staging", false},
		{"empty pattern, empty input", "", "", true},
		{"empty pattern, non-empty input", "", "a", false},
		{"non-empty pattern, empty input", "a", "", false},

		// '*' — the headline fix: it crosses '/' (filepath.Match does not).
		//
		// NB: issue #30's acceptance criterion is written as "`prod-*` matches
		// `prod-us-east-1` AND `prod/us/east/1`". The second half is a typo in
		// the ticket: the literal `prod-` cannot prefix `prod/` under ANY glob
		// semantics. The criterion's INTENT — '*' spans '/' — is captured by the
		// two cases below, where the literal prefix does match.
		{"star suffix", "prod-*", "prod-us-east-1", true},
		{"star crosses slash", "prod-*", "prod-us/east/1", true},
		{"star crosses slash from bare prefix", "prod*", "prod/us/east/1", true},
		{"literal dash still required", "prod-*", "prod/us/east/1", false},
		{"star crosses many slashes", "prod*", "prod/a/b/c/d", true},
		{"bare star matches slashes", "*", "a/b/c", true},
		{"star prefix", "*-production", "us-east-production", true},
		{"star both sides", "*prod*", "myprodcluster", true},
		{"star both sides crosses slash", "*prod*", "a/prod/b", true},
		{"star matches empty", "prod*", "prod", true},
		{"star no match", "prod-*", "staging-us-east-1", false},
		{"consecutive stars collapse", "**prod**", "a/prod/b", true},
		{"star crosses colon", "*", "arn:aws:eks:us-east-1", true},

		// '?' — exactly one character, and it too crosses '/'.
		{"question one char", "prod-?", "prod-a", true},
		{"question needs a char", "prod-?", "prod-", false},
		{"question not two chars", "prod-?", "prod-ab", false},
		{"question matches slash", "a?b", "a/b", true},
		{"question matches one rune not one byte", "?", "é", true},
		{"question rejects two runes", "?", "éé", false},

		// Character classes.
		{"class member", "prod-[abc]", "prod-a", true},
		{"class non-member", "prod-[abc]", "prod-d", false},
		{"class range", "prod-[a-z]", "prod-q", true},
		{"class range miss", "prod-[a-z]", "prod-Q", false},
		{"class negated caret", "prod-[^a]", "prod-b", true},
		{"class negated caret excludes", "prod-[^a]", "prod-a", false},
		// '!' is a LITERAL set member, not a negation — matching filepath.Match.
		// Negating on '!' would un-protect `prod-a` for the pattern `prod-[!a]`
		// on upgrade. See TestGlobNeverNarrowsVsFilepathMatch.
		{"bang is a literal member not a negation", "prod-[!a]", "prod-a", true},
		{"bang is a literal member", "prod-[!a]", "prod-!", true},
		{"bang class excludes others", "prod-[!a]", "prod-b", false},
		{"class literal close bracket first", "prod-[]]", "prod-]", true},
		{"class caret literal when not first", "prod-[a^]", "prod-^", true},
		{"class trailing dash is literal", "prod-[a-]", "prod--", true},
		{"class trailing dash still matches a", "prod-[a-]", "prod-a", true},
		{"class multiple ranges", "[a-c][0-9]", "b7", true},
		{"class with star after", "[a-c]*", "b-anything/here", true},
		{"class reversed range matches nothing", "[z-a]", "m", false},

		// Escaped range endpoints. An earlier draft read range endpoints raw, so
		// an escaped endpoint silently produced a NARROWER set than
		// filepath.Match and un-protected a context on upgrade. Each of these is
		// a real counterexample found by differential fuzzing; filepath.Match
		// returns true for every one. See TestClassRangeEndpointsHonorEscapes.
		{"escaped low range endpoint", `[\*-z]`, "[", true},
		{"escaped high range endpoint", `[a-\z]`, "m", true},
		{"escaped low endpoint bang", `[\!-a]`, "^", true},
		{"escaped high endpoint caret", `[?-\^]`, "]", true},
		{"escaped endpoints in a context pattern", `prod-[a-\z]`, "prod-x", true},
		{"escaped member still literal", `[\a-c]`, "b", true},

		// Escapes — a literal '*', '?', '[', or '\' in a name.
		{"escaped star", `prod\*`, "prod*", true},
		{"escaped star not wildcard", `prod\*`, "prod-x", false},
		{"escaped question", `prod\?`, "prod?", true},
		{"escaped bracket", `prod\[`, "prod[", true},
		{"escaped backslash", `a\\b`, `a\b`, true},
		{"trailing backslash is literal", `prod\`, `prod\`, true},

		// Malformed patterns degrade to literals, NOT to "matches nothing".
		// filepath.Match returns ErrBadPattern here; the old code dropped the
		// error and silently protected nothing. See TestMatchGlobDoesNotFailOpen.
		{"unterminated class is literal", "prod-[", "prod-[", true},
		{"unterminated class does not match member", "prod-[abc", "prod-a", false},

		// Backtracking correctness.
		{"backtrack simple", "*a*b*c*", "xxaxxbxxcxx", true},
		{"backtrack fail", "*a*b*c*", "xxaxxcxxbxx", false},
		{"star then literal at end", "*cluster", "prod-cluster", true},
		{"star then literal at end miss", "*cluster", "prod-clusterx", false},
		{"star backtracks over class", "*[0-9]", "abc7", true},
		{"star backtracks over escape", `*\*`, "abc*", true},

		// Real-world context names.
		{"eks arn", "arn:aws:eks:*:*:cluster/prod-*", "arn:aws:eks:us-east-1:123456789:cluster/prod-main", true},
		{"eks arn star spans everything", "arn:aws:eks:*", "arn:aws:eks:us-east-1:123456789:cluster/prod-main", true},
		{"gke path style", "gke_*_prod-*", "gke_myproject_us-central1_prod-main", true},
		{"slash separated context", "*/prod", "team-a/prod", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchGlob(tt.pattern, tt.input); got != tt.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.input, got, tt.want)
			}
		})
	}
}

// TestMatchGlobDoesNotFailOpen pins the reason this matcher exists. The old
// implementation was:
//
//	if matched, _ := filepath.Match(pattern, context); matched { ... }
//
// filepath.Match returns ErrBadPattern for a malformed pattern, and the dropped
// error meant "no match" — so a typo like `prod-[` protected NOTHING while
// looking configured. matchGlob is total: a malformed pattern matches itself
// literally, and never silently degrades to "unprotected everything".
//
// Reverting IsContextProtected to filepath.Match makes this test fail.
func TestMatchGlobDoesNotFailOpen(t *testing.T) {
	const badPattern = "prod-["

	// Establish the premise: filepath.Match really does error and report no
	// match for this pattern, which is what made the old code fail open.
	if matched, err := filepath.Match(badPattern, "prod-["); err == nil || matched {
		t.Fatalf("premise broken: filepath.Match(%q, %q) = (%v, %v); want (false, ErrBadPattern)",
			badPattern, "prod-[", matched, err)
	}

	// matchGlob is total and matches the literal.
	if !matchGlob(badPattern, "prod-[") {
		t.Errorf("matchGlob(%q, %q) = false; a malformed pattern must degrade to a literal match", badPattern, "prod-[")
	}

	// And it still does not pretend to be a wildcard.
	if matchGlob(badPattern, "prod-a") {
		t.Errorf("matchGlob(%q, %q) = true; malformed pattern must not match as a class", badPattern, "prod-a")
	}
}

// TestMatchGlobIsOSIndependent locks in the acceptance criterion that behavior
// is identical on Linux/macOS/Windows. filepath.Match's treatment of '\' and of
// the path separator is OS-specific; matchGlob's is not. These assertions are
// about matchGlob's own semantics and hold on every platform.
func TestMatchGlobIsOSIndependent(t *testing.T) {
	// '/' is an ordinary rune to matchGlob on every OS.
	if !matchGlob("a*b", "a/b") {
		t.Error(`matchGlob("a*b", "a/b") = false; '*' must cross '/' on every OS`)
	}
	// '\' always escapes; it is never a separator.
	if !matchGlob(`a\*b`, "a*b") {
		t.Error(`matchGlob("a\\*b", "a*b") = false; '\' must escape on every OS`)
	}
	if matchGlob(`a\*b`, "axb") {
		t.Error(`matchGlob("a\\*b", "axb") = true; escaped '*' must not act as a wildcard`)
	}
}

// TestMatchGlobPathological guards the iterative backtracking implementation
// against catastrophic behavior on a star-heavy pattern. A naive recursive
// matcher blows the stack or hangs here; this must return promptly.
func TestMatchGlobPathological(t *testing.T) {
	pattern := strings.Repeat("a*", 40) + "b"
	input := strings.Repeat("a", 400) // never matches: no trailing 'b'
	if matchGlob(pattern, input) {
		t.Error("expected no match for a pathological star pattern")
	}
	if !matchGlob(pattern, input+"b") {
		t.Error("expected a match once the trailing 'b' is present")
	}
}

// TestGlobSemanticsDivergeFromFilepathMatch documents, as executable evidence,
// exactly which behaviors changed — so a future reader can see this was a
// deliberate semantic swap and not an accident. Every divergence WIDENS what a
// pattern matches (or makes a dropped error impossible), so no context that was
// protected before becomes unprotected now.
func TestGlobSemanticsDivergeFromFilepathMatch(t *testing.T) {
	cases := []struct {
		pattern, input string
	}{
		{"prod-*", "prod-us/east/1"}, // filepath.Match: false ('*' won't cross '/')
		{"prod*", "prod/us/east/1"},  // filepath.Match: false
		{"*prod*", "a/prod/b"},       // filepath.Match: false
		{"*", "a/b/c"},               // filepath.Match: false
		{"a?b", "a/b"},               // filepath.Match: false ('?' won't match '/')
	}
	for _, c := range cases {
		old, err := filepath.Match(c.pattern, c.input)
		if err != nil {
			t.Fatalf("filepath.Match(%q, %q) unexpected error: %v", c.pattern, c.input, err)
		}
		if old {
			t.Fatalf("premise broken: filepath.Match(%q, %q) already matched", c.pattern, c.input)
		}
		if !matchGlob(c.pattern, c.input) {
			t.Errorf("matchGlob(%q, %q) = false; want true (this is the point of the change)", c.pattern, c.input)
		}
	}
}

// TestGlobNeverNarrowsVsFilepathMatch is the security invariant of this change,
// enforced by differential testing rather than by argument.
//
// Swapping the matcher must never UN-protect a context or namespace that the
// previous filepath.Match implementation protected. Formally:
//
//	for all (pattern, name):  filepath.Match(pattern, name) == true
//	                            =>  matchGlob(pattern, name) == true
//
// The converse is allowed and expected — matchGlob deliberately matches MORE
// (that is the whole point of #30). Patterns where filepath.Match returns
// ErrBadPattern are skipped: there the old code silently returned "no match"
// (i.e. unprotected), so any behavior of the total matcher is a widening.
//
// This test has caught two real defects:
//
//  1. An earlier draft honored '!' as a class negation, so `[!a]` matched "b"
//     but no longer matched "a". filepath.Match treats '!' as a literal member,
//     so upgrading would have silently stopped protecting a context. matchClass
//     now negates on '^' only.
//  2. An earlier draft read character-class range endpoints raw, so `[a-\z]`
//     parsed its high endpoint as '\' rather than 'z' and `[\*-z]` was not
//     parsed as a range at all. Both narrowed. matchClass now decodes every
//     endpoint through classAtom.
//
// Defect (2) escaped an earlier version of THIS test, which capped generated
// patterns at 4 runes — the shortest narrowing pattern, `[a-\b]`, is 6. The
// length bounds below are load-bearing, not decorative: do not lower them.
//
// Multi-byte runes are deliberately excluded from the generated NAME alphabet.
// filepath.Match walks the name byte-by-byte underneath a '*', so any single-rune
// matcher after a star ('?' or a class) can be satisfied by a continuation byte
// of a multi-byte rune decoded alone as RuneError — filepath.Match("*[^é]",
// "^Abé") and filepath.Match("*??", "怀") are both true. matchGlob is correctly
// rune-based and returns false for both. Reproducing that byte-vs-rune pathology
// is not desirable, so the invariant is asserted over single-byte names, and the
// excluded family is pinned by TestGlobIsRuneBasedNotByteBased.
func TestGlobNeverNarrowsVsFilepathMatch(t *testing.T) {
	// Alphabets dense in glob metacharacters, so the search explores classes,
	// escapes, negation, ranges and separators rather than letters. '\' MUST be
	// in the pattern alphabet: it is what defect (2) hid behind.
	patAlpha := []rune(`abcz01/*?[]!^-\.:_`)
	nameAlpha := []rune(`abcz01/!^-\[].:_`)

	// Two passes. Short patterns produce far more positive filepath.Match cases
	// (density); long patterns are the only ones that can express an escaped
	// range endpoint such as `[a-\z]` (reach). Both matter, so run both.
	//
	// The reach pass needs an order of magnitude more iterations for the same
	// number of positives: a random 5-9 rune pattern over a metacharacter-dense
	// alphabet rarely matches a random name. Measured ~500 positives per 3M
	// iterations, in ~0.6s. The minPositives floors are calibrated to that and
	// exist to make a vacuous pass impossible.
	passes := []struct {
		name                     string
		minPatLen, maxPatLen     int
		minNameLen, maxNameLen   int
		iterations, minPositives int
	}{
		{"dense-short", 1, 4, 0, 4, 300_000, 3_000},
		{"reaching-long", 5, 9, 0, 6, 3_000_000, 300},
	}

	r := rand.New(rand.NewSource(20260709))
	total := 0

	for _, pass := range passes {
		checked := 0
		for i := 0; i < pass.iterations; i++ {
			pattern := randStr(r, patAlpha, pass.minPatLen, pass.maxPatLen)
			name := randStr(r, nameAlpha, pass.minNameLen, pass.maxNameLen)

			old, err := filepath.Match(pattern, name)
			if err != nil {
				// Malformed for filepath.Match => it reported "no match" and the
				// old call site dropped the error. Nothing to preserve.
				continue
			}
			if !old {
				continue
			}
			checked++
			if !matchGlob(pattern, name) {
				t.Fatalf("NARROWING [%s]: filepath.Match(%q, %q) = true but matchGlob = false; "+
					"this pattern would stop protecting %q on upgrade", pass.name, pattern, name, name)
			}
		}
		// Guard against a vacuous pass (a generator that never produces a match).
		if checked < pass.minPositives {
			t.Fatalf("pass %q exercised only %d positive filepath.Match cases (want >= %d); "+
				"the generator is not covering enough of the space for this invariant to mean anything",
				pass.name, checked, pass.minPositives)
		}
		t.Logf("pass %q: verified widening-only over %d positive filepath.Match cases", pass.name, checked)
		total += checked
	}
	t.Logf("total positive cases verified: %d", total)
}

// TestGlobNeverNarrowsCoversEscapedRanges proves the generator above can
// actually reach the shape of defect (2). Without this, raising the length cap
// could be silently undone by a later edit and the invariant test would go back
// to passing vacuously against escaped-range narrowing.
func TestGlobNeverNarrowsCoversEscapedRanges(t *testing.T) {
	patAlpha := []rune(`abcz01/*?[]!^-\.:_`)
	r := rand.New(rand.NewSource(20260709))

	found := 0
	for i := 0; i < 400_000 && found == 0; i++ {
		p := randStr(r, patAlpha, 1, 9)
		// A range whose low or high endpoint is escaped: "\x-" or "-\x".
		for j := 0; j+3 < len(p); j++ {
			if (p[j] == '\\' && p[j+2] == '-') || (p[j] == '-' && p[j+1] == '\\') {
				found++
				break
			}
		}
	}
	if found == 0 {
		t.Fatal("the fuzz generator never produced an escaped range endpoint; " +
			"TestGlobNeverNarrowsVsFilepathMatch cannot see the defect class it guards")
	}
}

// TestClassRangeEndpointsHonorEscapes is the focused regression test for the
// escaped-range-endpoint narrowing. Reverting classAtom (reading pat[i]/pat[i+2]
// raw) makes every case here fail.
func TestClassRangeEndpointsHonorEscapes(t *testing.T) {
	cases := []struct{ pattern, name string }{
		{`[\*-z]`, "["},           // escaped LOW endpoint: range '*'..'z'
		{`[a-\z]`, "m"},           // escaped HIGH endpoint: range 'a'..'z'
		{`[\!-a]`, "^"},           // escaped low, '!'..'a'
		{`[?-\^]`, "]"},           // escaped high, '?'..'^'
		{`[\a-c]`, "b"},           // escaped low that escapes a plain letter
		{`[a-\c]`, "b"},           // escaped high that escapes a plain letter
		{`prod-[a-\z]`, "prod-x"}, // the shape that un-protected a real context
	}
	for _, c := range cases {
		// Premise: filepath.Match — the behavior we must not narrow — matches.
		old, err := filepath.Match(c.pattern, c.name)
		if err != nil {
			t.Fatalf("premise broken: filepath.Match(%q, %q) errored: %v", c.pattern, c.name, err)
		}
		if !old {
			t.Fatalf("premise broken: filepath.Match(%q, %q) = false; expected true", c.pattern, c.name)
		}
		if !matchGlob(c.pattern, c.name) {
			t.Errorf("NARROWING: matchGlob(%q, %q) = false, want true "+
				"(a range endpoint's escape was not decoded)", c.pattern, c.name)
		}
	}
}

// TestGlobIsRuneBasedNotByteBased pins the one FAMILY of cases where matchGlob
// deliberately diverges from filepath.Match in the narrowing direction, so the
// divergence can only move on purpose.
//
// filepath.Match walks the NAME byte-by-byte underneath a '*'. Any single-rune
// matcher that follows the star ('?' or a character class) can therefore be
// satisfied by an interior continuation byte of a multi-byte rune, decoded alone
// as utf8.RuneError. matchGlob decodes the name into runes up front, sees one
// rune, and does not match.
//
// This is a family, not a single shape: a single-rune matcher after a '*' can be
// satisfied by a continuation byte of ANY multi-byte rune the star's byte-wise
// scan lands inside. The multi-byte rune need not be the last rune of the name
// (`filepath.Match("*??x", "怀x")` is true), and the star need not lead
// (`filepath.Match("a*??", "a怀")` is true). A leading-or-interior '*' IS
// required: it is the only construct in filepath.Match that iterates byte
// offsets — its matchChunk is itself rune-based, so `a?b` vs `a怀b` and
// `[怀-鿿]` vs `怀` agree with matchGlob.
//
// Reproducing filepath's byte-vs-rune bug is not a goal — every realistic
// Kubernetes context/namespace name (DNS labels, `arn:aws:eks:…`,
// `gke_project_region_cluster`, `user@host`, slash paths) is ASCII, so no such
// name is reachable here. Everything OUTSIDE this family is widening-only; that
// is what TestGlobNeverNarrowsVsFilepathMatch asserts over single-byte names.
func TestGlobIsRuneBasedNotByteBased(t *testing.T) {
	cases := []struct {
		pattern, name, why string
	}{
		{"*[^é]", "^Abé", "negated class matches a continuation byte as RuneError"},
		{"*??", "怀", "two '?' match the two continuation bytes of a 3-byte rune"},
		{"*???", "怀.", "same, with a trailing ASCII rune"},
		{"*??x", "怀x", "the multi-byte rune need not be the last rune of the name"},
		{"a*??", "a怀", "the star need not be leading"},
	}

	for _, c := range cases {
		old, err := filepath.Match(c.pattern, c.name)
		if err != nil {
			t.Fatalf("filepath.Match(%q, %q) errored: %v", c.pattern, c.name, err)
		}
		if !old {
			t.Logf("filepath.Match(%q, %q) no longer matches; the byte-vs-rune quirk this "+
				"case documents may have been fixed upstream (%s)", c.pattern, c.name, c.why)
			continue
		}
		if matchGlob(c.pattern, c.name) {
			t.Errorf("matchGlob(%q, %q) = true; expected false — matchGlob is rune-based "+
				"and must not reproduce filepath.Match's byte-wise matching (%s)",
				c.pattern, c.name, c.why)
		}
	}

	// The converse, which bounds the family: WITHOUT a '*' there is no byte-wise
	// scan, so filepath.Match and matchGlob agree even on multi-byte names. If one
	// of these ever diverges, the carve-out above is wider than documented.
	agree := []struct{ pattern, name string }{
		{"a?b", "a怀b"}, // '?' against an interior multi-byte rune
		{"[怀-鿿]", "怀"}, // a class range with multi-byte endpoints
		{`[\怀]`, "怀"},  // an escaped multi-byte class member
		{"[^a]", "怀"},  // a negated class, no star
		{"怀", "怀"},     // a plain multi-byte literal
	}
	for _, c := range agree {
		old, err := filepath.Match(c.pattern, c.name)
		if err != nil {
			continue // filepath rejects the pattern; nothing to compare
		}
		if got := matchGlob(c.pattern, c.name); got != old {
			t.Errorf("matchGlob(%q, %q) = %v but filepath.Match = %v; without a '*' the two "+
				"must agree, so the documented byte-vs-rune carve-out is wider than claimed",
				c.pattern, c.name, got, old)
		}
	}
}

func randStr(r *rand.Rand, alpha []rune, minLen, maxLen int) string {
	n := minLen + r.Intn(maxLen-minLen+1)
	out := make([]rune, n)
	for i := range out {
		out[i] = alpha[r.Intn(len(alpha))]
	}
	return string(out)
}

func TestIsNamespaceProtectedUsesGlob(t *testing.T) {
	tests := []struct {
		name      string
		patterns  []string
		namespace string
		protected bool
	}{
		{"exact", []string{"kube-system"}, "kube-system", true},
		{"no match", []string{"kube-system"}, "default", false},
		{"prefix glob", []string{"prod-*"}, "prod-app", true},
		{"prefix glob miss", []string{"prod-*"}, "staging-app", false},
		{"contains glob", []string{"*prod*"}, "my-prod-ns", true},
		{"single char", []string{"ns-?"}, "ns-1", true},
		{"class", []string{"env-[a-c]"}, "env-b", true},
		{"class miss", []string{"env-[a-c]"}, "env-z", false},
		{"none configured", nil, "kube-system", false},
		{"second pattern matches", []string{"a-*", "kube-*"}, "kube-public", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{ProtectedNamespaces: tt.patterns}
			if got := cfg.IsNamespaceProtected(tt.namespace); got != tt.protected {
				t.Errorf("IsNamespaceProtected(%q) with %v = %v, want %v",
					tt.namespace, tt.patterns, got, tt.protected)
			}
		})
	}
}

// TestEscapedRangeStillProtects is the config-level regression for the
// escaped-range narrowing, on BOTH protection paths. A security review proved
// end-to-end that with `prod-[a-\z]` configured, `kubectl delete pod x` on
// context `prod-x` was gated by the previous matcher and ran unchallenged under
// the buggy new one — on the context path and the namespace path alike.
func TestEscapedRangeStillProtects(t *testing.T) {
	const pattern, name = `prod-[a-\z]`, "prod-x"

	ctxCfg := &Config{ProtectedContexts: []string{pattern}}
	if !ctxCfg.IsContextProtected(name) {
		t.Errorf("IsContextProtected(%q) with pattern %q = false; context is UNPROTECTED", name, pattern)
	}

	nsCfg := &Config{ProtectedNamespaces: []string{pattern}}
	if !nsCfg.IsNamespaceProtected(name) {
		t.Errorf("IsNamespaceProtected(%q) with pattern %q = false; namespace is UNPROTECTED", name, pattern)
	}
}

// TestContextAndNamespaceShareOneMatcher enforces the ticket's consistency
// requirement: the same pattern must mean the same thing in both fields.
func TestContextAndNamespaceShareOneMatcher(t *testing.T) {
	patterns := []string{"prod-*", "*prod*", "a?b", "env-[a-c]", "arn:aws:*:cluster/*", "prod/*"}
	inputs := []string{"prod-1", "a/prod/b", "a/b", "env-b", "arn:aws:eks:cluster/x", "prod/us/east", "staging"}

	for _, p := range patterns {
		for _, in := range inputs {
			ctxCfg := &Config{ProtectedContexts: []string{p}}
			nsCfg := &Config{ProtectedNamespaces: []string{p}}
			if a, b := ctxCfg.IsContextProtected(in), nsCfg.IsNamespaceProtected(in); a != b {
				t.Errorf("pattern %q vs %q: context=%v namespace=%v; the two must agree", p, in, a, b)
			}
		}
	}
}

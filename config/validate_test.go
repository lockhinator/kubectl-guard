package config

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		wantProblem string // substring expected in exactly one problem; "" = valid
	}{
		{"empty config is valid", Config{}, ""},
		{"fully valid config", Config{
			ProtectedContexts:   []string{"prod-*", "arn:aws:eks:*:*:cluster/prod-*"},
			ProtectedNamespaces: []string{"kube-system", "prod-[a-z]"},
			ProtectedResources:  []string{"secret", "configmap"},
			ConfirmMode:         ConfirmModeTypeName,
			AuditMode:           AuditModeGated,
			ContextMode:         ContextModeBlock,
			NamespaceMode:       NamespaceModeConfirm,
		}, ""},

		{"invalid confirm_mode", Config{ConfirmMode: "typname"}, "confirm_mode"},
		{"invalid audit_mode", Config{AuditMode: "sometimes"}, "audit_mode"},
		{"invalid context_mode", Config{ContextMode: "blck"}, "context_mode"},
		{"invalid namespace_mode", Config{NamespaceMode: "hard"}, "namespace_mode"},

		{"valid agent-relay confirm mode", Config{ConfirmMode: ConfirmModeAgentRelay}, ""},

		{"unterminated glob in contexts", Config{ProtectedContexts: []string{"prod-["}}, "protected_contexts"},
		{"unterminated glob in namespaces", Config{ProtectedNamespaces: []string{"kube-["}}, "protected_namespaces"},
		{"dangling escape in context", Config{ProtectedContexts: []string{`prod\`}}, "dangling"},

		{"empty resource entry", Config{ProtectedResources: []string{"secret", ""}}, "protected_resources"},
		{"whitespace resource entry", Config{ProtectedResources: []string{"   "}}, "protected_resources"},

		{"negative confirm timeout", Config{ConfirmTimeoutSeconds: -1}, "confirm_timeout_seconds"},
		{"zero confirm timeout is valid", Config{ConfirmTimeoutSeconds: 0}, ""},
		{"positive confirm timeout is valid", Config{ConfirmTimeoutSeconds: 60}, ""},
		{"max confirm timeout is valid", Config{ConfirmTimeoutSeconds: MaxConfirmTimeoutSeconds}, ""},
		{"over-max confirm timeout rejected", Config{ConfirmTimeoutSeconds: MaxConfirmTimeoutSeconds + 1}, "too large"},
		// The value that overflows time.Duration to a negative (silent
		// wait-forever) must be rejected, not silently accepted.
		{"overflow confirm timeout rejected", Config{ConfirmTimeoutSeconds: 9223372037}, "too large"},

		{"valid globs with classes and escapes", Config{
			ProtectedContexts: []string{"prod-[abc]", "prod-[!x]", "prod-[a-z]", `lit\[eral`, "*prod*"},
		}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems := tt.cfg.Validate()
			if tt.wantProblem == "" {
				if len(problems) != 0 {
					t.Errorf("Validate() = %v, want no problems", problems)
				}
				return
			}
			found := false
			for _, p := range problems {
				if strings.Contains(p, tt.wantProblem) {
					found = true
				}
			}
			if !found {
				t.Errorf("Validate() = %v, want a problem containing %q", problems, tt.wantProblem)
			}
		})
	}
}

// TestValidateReportsAllProblems: Validate accumulates every problem, not just
// the first, so `config validate` gives the user the whole list at once.
func TestValidateReportsAllProblems(t *testing.T) {
	cfg := Config{
		ConfirmMode:        "typname",
		ContextMode:        "blck",
		ProtectedContexts:  []string{"prod-["},
		ProtectedResources: []string{""},
	}
	if got := len(cfg.Validate()); got != 4 {
		t.Errorf("Validate() reported %d problems, want 4: %v", got, cfg.Validate())
	}
}

func TestValidateGlobPattern(t *testing.T) {
	valid := []string{
		"", "prod-cluster", "prod-*", "*prod*", "prod-?", "prod-[abc]",
		"prod-[a-z]", "prod-[!x]", "prod-[^x]", "prod-[]]", `prod\*`,
		`prod\[`, `prod\\`, "arn:aws:eks:*:*:cluster/prod-*", "a[b]c[d]e",
	}
	for _, p := range valid {
		if err := validateGlobPattern(p); err != nil {
			t.Errorf("validateGlobPattern(%q) = %v, want nil", p, err)
		}
	}

	invalid := []struct{ pattern, want string }{
		{"prod-[", "unterminated"},
		{"prod-[abc", "unterminated"},
		{"[a-z", "unterminated"},
		{"a[b]c[d", "unterminated"},
		{`prod\`, "dangling"},
		{`a\`, "dangling"},
	}
	for _, tt := range invalid {
		err := validateGlobPattern(tt.pattern)
		if err == nil {
			t.Errorf("validateGlobPattern(%q) = nil, want error containing %q", tt.pattern, tt.want)
			continue
		}
		if !strings.Contains(err.Error(), tt.want) {
			t.Errorf("validateGlobPattern(%q) = %q, want it to contain %q", tt.pattern, err, tt.want)
		}
	}
}

// classDegradesToLiteral reports whether matchClass, asked to match the class
// opened at pat[open], hit its "unterminated '[' -> literal" fallback. That
// fallback is the observable moment the matcher's leniency silently discards the
// user's class syntax — exactly what validateGlobPattern must flag. matchClass's
// index progression is independent of the rune it matches against, so any rune
// (here 'a') reveals the same structural outcome.
func classDegradesToLiteral(pat []rune, open int) bool {
	next, _ := matchClass(pat, open, 'a')
	return next == open+1 // the literal-'[' fallback returns p+1
}

// patternDegrades reports whether matchGlob silently treats any metacharacter of
// pattern as a literal because the pattern is malformed — i.e. an unterminated
// '[' class or a trailing '\'. This is the runtime "protects less than the user
// wrote" condition that validateGlobPattern is meant to catch.
func patternDegrades(pattern string) bool {
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '\\':
			if i == len(runes)-1 {
				return true // dangling escape: matchOne matches a literal '\'
			}
			i++
		case '[':
			if classDegradesToLiteral(runes, i) {
				return true
			}
			// Skip past a well-formed class so a later '[' inside it is not
			// re-examined out of context.
			j := i + 1
			if j < len(runes) && runes[j] == '^' {
				j++
			}
			first := true
			for j < len(runes) {
				if runes[j] == ']' && !first {
					break
				}
				if runes[j] == '\\' && j+1 < len(runes) {
					j++
				}
				first = false
				j++
			}
			i = j
		}
	}
	return false
}

// TestValidateGlobConsistentWithMatcher is the differential invariant tying the
// strict validator to the lenient matcher, proved over the whole small-pattern
// space rather than a spot check:
//
//	validateGlobPattern(p) == nil  <=>  matchGlob does NOT degrade p to a literal.
//
// A validator that ACCEPTS a pattern the matcher degrades would give false
// assurance — a protected_contexts entry that silently matches nothing intended
// (the exact hole #26 exists to close). A validator that REJECTS a pattern the
// matcher handles cleanly would raise false alarms and needlessly fail closed.
// Neither may happen, for any pattern.
func TestValidateGlobConsistentWithMatcher(t *testing.T) {
	alphabet := []rune{'a', '*', '?', '[', ']', '^', '!', '-', '\\'}

	// Exhaustively enumerate every pattern up to length 5 over the
	// metacharacter-dense alphabet.
	var rec func(prefix []rune)
	checked := 0
	rec = func(prefix []rune) {
		p := string(prefix)
		accepts := validateGlobPattern(p) == nil
		degrades := patternDegrades(p)
		if accepts == degrades {
			t.Fatalf("inconsistency for %q: validator accepts=%v, matcher degrades=%v", p, accepts, degrades)
		}
		checked++
		if len(prefix) == 5 {
			return
		}
		for _, r := range alphabet {
			rec(append(prefix, r))
		}
	}
	rec(nil)

	if checked < 10000 {
		t.Fatalf("only %d patterns exercised; enumeration is not covering the space", checked)
	}
	t.Logf("validator/matcher consistent over %d patterns", checked)
}

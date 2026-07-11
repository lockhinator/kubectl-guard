package config

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestProtectedPatternBareRoundTrip: a config with only bare-string patterns
// (Mode == "") must re-marshal to bare strings, not {pattern, mode} objects, so
// an existing string-only config round-trips unchanged (back-compat).
func TestProtectedPatternBareRoundTrip(t *testing.T) {
	cfg := &Config{
		ProtectedContexts:   Patterns("prod-*", "staging-*"),
		ProtectedNamespaces: Patterns("kube-system"),
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "pattern:") || strings.Contains(s, "mode:") {
		t.Errorf("bare patterns must marshal as strings, got object form:\n%s", s)
	}
	// And unmarshal back to the same slices.
	var back Config
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(back.ProtectedContexts, Patterns("prod-*", "staging-*")) {
		t.Errorf("round-trip contexts = %#v", back.ProtectedContexts)
	}
	if !reflect.DeepEqual(back.ProtectedNamespaces, Patterns("kube-system")) {
		t.Errorf("round-trip namespaces = %#v", back.ProtectedNamespaces)
	}
}

// TestProtectedPatternMixedParse: a config mixing a bare string and a
// {pattern, mode} object parses both forms, and an explicit-mode entry marshals
// back to the object form.
func TestProtectedPatternMixedParse(t *testing.T) {
	const y = `protected_contexts:
  - "prod-*"
  - pattern: "staging-*"
    mode: confirm
  - pattern: "prod-critical-*"
    mode: block
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(y), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []ProtectedPattern{
		{Pattern: "prod-*", Mode: ""},
		{Pattern: "staging-*", Mode: "confirm"},
		{Pattern: "prod-critical-*", Mode: "block"},
	}
	if !reflect.DeepEqual(cfg.ProtectedContexts, want) {
		t.Fatalf("parsed = %#v, want %#v", cfg.ProtectedContexts, want)
	}
	// Re-marshal: bare stays bare, explicit stays object.
	out, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "- prod-*") {
		t.Errorf("bare pattern should re-marshal bare, got:\n%s", s)
	}
	if !strings.Contains(s, "pattern: staging-*") || !strings.Contains(s, "mode: confirm") {
		t.Errorf("explicit-mode pattern should re-marshal as object, got:\n%s", s)
	}
}

// TestEffectiveContextModeInheritsGlobal: a pattern with no explicit mode inherits
// the global context_mode.
func TestEffectiveContextModeInheritsGlobal(t *testing.T) {
	cfg := &Config{ProtectedContexts: Patterns("prod-*"), ContextMode: ContextModeBlock}
	if got := cfg.EffectiveContextMode("prod-1"); got != ContextModeBlock {
		t.Errorf("inherit global block: got %q", got)
	}
	cfg.ContextMode = ContextModeConfirm
	if got := cfg.EffectiveContextMode("prod-1"); got != ContextModeConfirm {
		t.Errorf("inherit global confirm: got %q", got)
	}
	// No pattern matches -> global.
	if got := cfg.EffectiveContextMode("dev"); got != ContextModeConfirm {
		t.Errorf("no match should return global, got %q", got)
	}
}

// TestEffectiveContextModeExplicitOverridesGlobal: an explicit per-pattern mode is
// honored as-is, even when the global mode differs — including an explicit confirm
// while the global is block.
func TestEffectiveContextModeExplicitOverridesGlobal(t *testing.T) {
	cfg := &Config{
		ProtectedContexts: []ProtectedPattern{{Pattern: "staging-*", Mode: ContextModeConfirm}},
		ContextMode:       ContextModeBlock,
	}
	if got := cfg.EffectiveContextMode("staging-1"); got != ContextModeConfirm {
		t.Errorf("explicit confirm should override global block, got %q", got)
	}
}

// TestEffectiveContextModeMostRestrictive: when a context matches multiple
// patterns, the MOST RESTRICTIVE resolved mode wins (block beats confirm).
func TestEffectiveContextModeMostRestrictive(t *testing.T) {
	cfg := &Config{
		ProtectedContexts: []ProtectedPattern{
			{Pattern: "prod-*", Mode: ContextModeConfirm},
			{Pattern: "prod-critical-*", Mode: ContextModeBlock},
		},
		ContextMode: ContextModeConfirm,
	}
	if got := cfg.EffectiveContextMode("prod-critical-1"); got != ContextModeBlock {
		t.Errorf("most restrictive should be block (matches both), got %q", got)
	}
	if got := cfg.EffectiveContextMode("prod-web"); got != ContextModeConfirm {
		t.Errorf("only confirm pattern matches, got %q", got)
	}
}

// TestEffectiveNamespaceModeAndMostRestrictive mirrors the context tests plus the
// all-patterns MostRestrictiveNamespaceMode used for --all-namespaces.
func TestEffectiveNamespaceModeAndMostRestrictive(t *testing.T) {
	cfg := &Config{
		ProtectedNamespaces: []ProtectedPattern{
			{Pattern: "kube-system", Mode: ContextModeBlock},
			{Pattern: "team-*", Mode: ContextModeConfirm},
		},
		NamespaceMode: NamespaceModeConfirm,
	}
	if got := cfg.EffectiveNamespaceMode("kube-system"); got != NamespaceModeBlock {
		t.Errorf("kube-system should be block, got %q", got)
	}
	if got := cfg.EffectiveNamespaceMode("team-a"); got != NamespaceModeConfirm {
		t.Errorf("team-a should be confirm, got %q", got)
	}
	if got := cfg.EffectiveNamespaceMode("other"); got != NamespaceModeConfirm {
		t.Errorf("unmatched should be global confirm, got %q", got)
	}
	// Any pattern is block -> MostRestrictive is block.
	if got := cfg.MostRestrictiveNamespaceMode(); got != NamespaceModeBlock {
		t.Errorf("MostRestrictiveNamespaceMode = %q, want block", got)
	}
}

// TestEffectiveModesForActorPerPatternBase: the actor-effective modes start from
// the per-pattern base, then are tightened by the actor policy (block only).
func TestEffectiveModesForActorPerPatternBase(t *testing.T) {
	cfg := &Config{
		ProtectedContexts: []ProtectedPattern{{Pattern: "prod-*", Mode: ContextModeConfirm}},
		ContextMode:       ContextModeConfirm,
		NamespaceMode:     NamespaceModeConfirm,
		ActorPolicies:     []ActorPolicy{{Actor: "agent-*", ContextMode: ContextModeBlock}},
	}
	// Human: per-pattern confirm, no actor tightening.
	if ctx, _ := cfg.EffectiveModesForActor("alice", "prod-1", "default"); ctx != ContextModeConfirm {
		t.Errorf("human on confirm pattern = %q, want confirm", ctx)
	}
	// Agent: actor policy tightens confirm -> block.
	if ctx, _ := cfg.EffectiveModesForActor("agent-x", "prod-1", "default"); ctx != ContextModeBlock {
		t.Errorf("agent on confirm pattern = %q, want block (actor tightens)", ctx)
	}
}

// TestAddContextWithMode covers add, update/upgrade, same-mode no-op, invalid
// rejection, and that a plain AddContext never touches an existing mode.
func TestAddContextWithMode(t *testing.T) {
	cfg := &Config{}
	if !cfg.AddContextWithMode("prod-*", ContextModeConfirm) {
		t.Fatal("add new should return true")
	}
	// Upgrade confirm -> block updates and returns true.
	if !cfg.AddContextWithMode("prod-*", ContextModeBlock) {
		t.Fatal("upgrade should return true")
	}
	if cfg.ProtectedContexts[0].Mode != ContextModeBlock {
		t.Errorf("mode not upgraded: %+v", cfg.ProtectedContexts[0])
	}
	// Same mode is a no-op.
	if cfg.AddContextWithMode("prod-*", ContextModeBlock) {
		t.Error("same mode should be no-op (false)")
	}
	// Invalid mode rejected, no change.
	if cfg.AddContextWithMode("prod-*", "nonsense") {
		t.Error("invalid mode must be rejected")
	}
	if cfg.ProtectedContexts[0].Mode != ContextModeBlock {
		t.Errorf("invalid mode must not change existing entry: %+v", cfg.ProtectedContexts[0])
	}
	// Plain AddContext on an existing block pattern is a pure no-op — it must NOT
	// downgrade the mode to inherit (the key safety property).
	if cfg.AddContext("prod-*") {
		t.Error("plain add of existing pattern should be no-op")
	}
	if cfg.ProtectedContexts[0].Mode != ContextModeBlock {
		t.Errorf("plain re-add must not touch mode: %+v", cfg.ProtectedContexts[0])
	}
}

// TestValidateRejectsInvalidPatternMode: a per-pattern mode that is not
// confirm/block is a validation problem (fail closed).
func TestValidateRejectsInvalidPatternMode(t *testing.T) {
	cfg := &Config{
		ProtectedContexts:   []ProtectedPattern{{Pattern: "prod-*", Mode: "blck"}},
		ProtectedNamespaces: []ProtectedPattern{{Pattern: "kube-system", Mode: "nope"}},
	}
	problems := cfg.Validate()
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, "protected_contexts") || !strings.Contains(joined, "invalid mode") {
		t.Errorf("expected a context invalid-mode problem, got: %v", problems)
	}
	if !strings.Contains(joined, "protected_namespaces") {
		t.Errorf("expected a namespace invalid-mode problem, got: %v", problems)
	}
}

// TestValidateRejectsEmptyPattern: an empty pattern (from a missing/misspelled
// `pattern:` key, e.g. {mode: block} with no pattern) protects nothing and must
// fail validation, so the config fails closed instead of silently dropping the
// intended protection. #79 (security review).
func TestValidateRejectsEmptyPattern(t *testing.T) {
	// Simulates a typo'd `patern:` decoding to Pattern:"" with a mode set.
	cfg := &Config{
		ProtectedContexts:   []ProtectedPattern{{Pattern: "", Mode: "block"}},
		ProtectedNamespaces: []ProtectedPattern{{Pattern: "", Mode: "confirm"}},
	}
	problems := cfg.Validate()
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, "protected_contexts") || !strings.Contains(joined, "empty pattern") {
		t.Errorf("expected a context empty-pattern problem, got: %v", problems)
	}
	if !strings.Contains(joined, "protected_namespaces") {
		t.Errorf("expected a namespace empty-pattern problem, got: %v", problems)
	}
}

// TestWeakeningPatternModeDowngrade: downgrading a pattern's mode (block ->
// confirm) is weakening; upgrading (confirm -> block) is not.
func TestWeakeningPatternModeDowngrade(t *testing.T) {
	old := &Config{ProtectedContexts: []ProtectedPattern{{Pattern: "prod-*", Mode: ContextModeBlock}}}
	old.ApplyDefaults()

	downgrade := &Config{ProtectedContexts: []ProtectedPattern{{Pattern: "prod-*", Mode: ContextModeConfirm}}}
	downgrade.ApplyDefaults()
	if w := WeakensProtection(old, downgrade); len(w) == 0 {
		t.Error("block -> confirm should be weakening")
	}

	// block -> inherit while global is confirm is also a downgrade.
	inherit := &Config{ProtectedContexts: []ProtectedPattern{{Pattern: "prod-*", Mode: ""}}, ContextMode: ContextModeConfirm}
	inherit.ApplyDefaults()
	if w := WeakensProtection(old, inherit); len(w) == 0 {
		t.Error("block -> inherit(confirm) should be weakening")
	}

	// Upgrade is not weakening.
	upBase := &Config{ProtectedContexts: []ProtectedPattern{{Pattern: "prod-*", Mode: ContextModeConfirm}}}
	upBase.ApplyDefaults()
	upNew := &Config{ProtectedContexts: []ProtectedPattern{{Pattern: "prod-*", Mode: ContextModeBlock}}}
	upNew.ApplyDefaults()
	if w := WeakensProtection(upBase, upNew); len(w) != 0 {
		t.Errorf("confirm -> block should NOT be weakening, got %v", w)
	}
}

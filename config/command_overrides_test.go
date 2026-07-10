package config

import "testing"

func TestClassifyOverride(t *testing.T) {
	cfg := &Config{CommandOverrides: CommandOverrides{
		Safe:          []string{"weird-read", " Padded "},
		StateAltering: []string{"my-plugin"},
		UnsafeSafe:    []string{"logs"},
	}}
	cases := []struct {
		verb string
		want CommandClass
	}{
		{"weird-read", ClassSafe},
		{"WEIRD-READ", ClassSafe}, // case-insensitive
		{"padded", ClassSafe},     // trimmed
		{"my-plugin", ClassStateAltering},
		{"logs", ClassStateAltering}, // unsafe_safe resolves as state-altering
		{"get", ClassNone},           // no override → built-in
		{"", ClassNone},
	}
	for _, tc := range cases {
		if got := cfg.ClassifyOverride(tc.verb); got != tc.want {
			t.Errorf("ClassifyOverride(%q) = %v, want %v", tc.verb, got, tc.want)
		}
	}
}

// TestClassifyOverrideMostRestrictive: a verb in BOTH safe and state_altering
// resolves as state-altering (most restrictive).
func TestClassifyOverrideMostRestrictive(t *testing.T) {
	cfg := &Config{CommandOverrides: CommandOverrides{
		Safe:          []string{"contested"},
		StateAltering: []string{"contested"},
	}}
	if got := cfg.ClassifyOverride("contested"); got != ClassStateAltering {
		t.Errorf("a verb in both lists = %v, want ClassStateAltering (most restrictive)", got)
	}
}

func TestSetAndRemoveCommandOverride(t *testing.T) {
	cfg := &Config{}
	if !cfg.SetCommandOverride("Logs", ClassStateAltering) {
		t.Fatal("set dangerous should succeed")
	}
	if cfg.ClassifyOverride("logs") != ClassStateAltering {
		t.Error("logs should be state-altering after set")
	}
	// Re-classify to safe: must move lists, not duplicate.
	if !cfg.SetCommandOverride("logs", ClassSafe) {
		t.Fatal("reclassify should succeed")
	}
	if cfg.ClassifyOverride("logs") != ClassSafe {
		t.Error("logs should be safe after reclassify")
	}
	if len(cfg.CommandOverrides.StateAltering) != 0 {
		t.Errorf("reclassify left logs in state_altering: %v", cfg.CommandOverrides.StateAltering)
	}
	// Invalid inputs.
	if cfg.SetCommandOverride("", ClassSafe) {
		t.Error("empty verb must be rejected")
	}
	if cfg.SetCommandOverride("x", ClassNone) {
		t.Error("ClassNone must be rejected")
	}
	// Remove.
	if !cfg.RemoveCommandOverride("logs") {
		t.Error("remove should report present")
	}
	if cfg.RemoveCommandOverride("logs") {
		t.Error("second remove should report absent")
	}
	if cfg.ClassifyOverride("logs") != ClassNone {
		t.Error("logs should have no override after removal")
	}
}

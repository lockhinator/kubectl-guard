package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestInitFromEnv(t *testing.T) {
	t.Setenv(EnvProtectedContexts, "prod-*, prod-cluster")
	t.Setenv(EnvProtectedResources, "secret,configmap")
	t.Setenv(EnvConfirmMode, ConfirmModeTypeName)

	cfg, ok := InitFromEnv()
	if !ok {
		t.Fatal("ok = false, want true (protection values were provided)")
	}
	if !reflect.DeepEqual(cfg.ProtectedContexts, Patterns("prod-*", "prod-cluster")) {
		t.Errorf("ProtectedContexts = %v, want [prod-* prod-cluster]", cfg.ProtectedContexts)
	}
	if !reflect.DeepEqual(cfg.ProtectedResources, []string{"secret", "configmap"}) {
		t.Errorf("ProtectedResources = %v, want [secret configmap]", cfg.ProtectedResources)
	}
	if cfg.ConfirmMode != ConfirmModeTypeName {
		t.Errorf("ConfirmMode = %q, want %q", cfg.ConfirmMode, ConfirmModeTypeName)
	}
}

func TestInitFromEnvEmpty(t *testing.T) {
	t.Setenv(EnvProtectedContexts, "")
	t.Setenv(EnvProtectedResources, "")
	t.Setenv(EnvConfirmMode, "")

	_, ok := InitFromEnv()
	if ok {
		t.Error("ok = true, want false when no protection values are set")
	}
}

func TestInitFromEnvIgnoresInvalidConfirmMode(t *testing.T) {
	t.Setenv(EnvProtectedContexts, "prod-*")
	t.Setenv(EnvConfirmMode, "bogus")

	cfg, ok := InitFromEnv()
	if !ok {
		t.Fatal("ok = false, want true (contexts provided)")
	}
	// An invalid mode is ignored; ApplyDefaults restores the default.
	if cfg.ConfirmMode != ConfirmModeSimple {
		t.Errorf("ConfirmMode = %q, want default %q", cfg.ConfirmMode, ConfirmModeSimple)
	}
}

func TestInitFromFlags(t *testing.T) {
	cfg := InitFromFlags("prod-*,prod-cluster", "secret", ConfirmModeTypeName)
	if !reflect.DeepEqual(cfg.ProtectedContexts, Patterns("prod-*", "prod-cluster")) {
		t.Errorf("ProtectedContexts = %v", cfg.ProtectedContexts)
	}
	if !reflect.DeepEqual(cfg.ProtectedResources, []string{"secret"}) {
		t.Errorf("ProtectedResources = %v", cfg.ProtectedResources)
	}
	if cfg.ConfirmMode != ConfirmModeTypeName {
		t.Errorf("ConfirmMode = %q, want %q", cfg.ConfirmMode, ConfirmModeTypeName)
	}
}

// TestBootstrapMode covers the headless first-run posture. Unset means deny;
// an unrecognized value ALSO means deny (fail closed) but is reported invalid
// so the caller can warn — a typo must never silently produce an unprotected
// guard.
func TestBootstrapMode(t *testing.T) {
	tests := []struct {
		env       string
		wantMode  string
		wantValid bool
	}{
		{"", BootstrapDeny, true},
		{"deny", BootstrapDeny, true},
		{"empty", BootstrapEmpty, true},
		{"prompt", BootstrapPrompt, true},
		{"DENY", BootstrapDeny, true},
		{"Empty", BootstrapEmpty, true},
		{"  deny  ", BootstrapDeny, true},
		{"emtpy", BootstrapDeny, false}, // typo
		{"none", BootstrapDeny, false},  // plausible-but-wrong
		{"false", BootstrapDeny, false}, // truthy-looking
		{"0", BootstrapDeny, false},     // truthy-looking
	}
	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			t.Setenv(EnvBootstrap, tt.env)
			mode, valid := BootstrapMode()
			if mode != tt.wantMode || valid != tt.wantValid {
				t.Errorf("BootstrapMode() with %q = (%q, %v), want (%q, %v)",
					tt.env, mode, valid, tt.wantMode, tt.wantValid)
			}
		})
	}
}

// TestBootstrapModeNeverSilentlyUnprotected: every input that is not exactly
// "empty" must resolve to a mode that does not write an unprotected config.
func TestBootstrapModeNeverSilentlyUnprotected(t *testing.T) {
	for _, v := range []string{"", "deny", "prompt", "emtpy", "EMTPY", "no", "yes", "1", "empty "} {
		t.Setenv(EnvBootstrap, v)
		mode, _ := BootstrapMode()
		if mode == BootstrapEmpty && strings.TrimSpace(strings.ToLower(v)) != BootstrapEmpty {
			t.Errorf("BootstrapMode() with %q = empty; only an exact \"empty\" may opt into an unprotected config", v)
		}
	}
}

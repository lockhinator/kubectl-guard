package config

import (
	"path/filepath"
	"testing"
)

// TestPathEnvOverride: KUBECTL_GUARD_CONFIG overrides the config location; the
// default (HOME-based) is unchanged; a blank env value falls back. #36.
func TestPathEnvOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := filepath.Join(home, ".kubectl-guard.yaml")

	t.Setenv(EnvConfig, "")
	if got, err := Path(); err != nil || got != want {
		t.Fatalf("default Path() = %q (err %v), want %q", got, err, want)
	}

	custom := filepath.Join(t.TempDir(), "custom.yaml")
	t.Setenv(EnvConfig, custom)
	if got, _ := Path(); got != custom {
		t.Errorf("Path() with env = %q, want %q", got, custom)
	}

	// Whitespace-only override is ignored (falls back to the default).
	t.Setenv(EnvConfig, "   ")
	if got, _ := Path(); got != want {
		t.Errorf("Path() with blank env = %q, want default %q", got, want)
	}
}

// TestAuditPathPrecedence: env > config field > default, and env wins over the
// config field so a runner can redirect the log without editing a mounted config.
// #36.
func TestAuditPathPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvAuditLog, "")
	def := filepath.Join(home, ".kubectl-guard-audit.log")

	if got, _ := AuditPath(nil); got != def {
		t.Errorf("default AuditPath = %q, want %q", got, def)
	}

	cfgPath := filepath.Join(t.TempDir(), "from-config.log")
	if got, _ := AuditPath(&Config{AuditLog: cfgPath}); got != cfgPath {
		t.Errorf("AuditPath(cfg.AuditLog) = %q, want %q", got, cfgPath)
	}

	envPath := filepath.Join(t.TempDir(), "from-env.log")
	t.Setenv(EnvAuditLog, envPath)
	if got, _ := AuditPath(&Config{AuditLog: cfgPath}); got != envPath {
		t.Errorf("AuditPath with env = %q, want %q (env must win over config field)", got, envPath)
	}
}

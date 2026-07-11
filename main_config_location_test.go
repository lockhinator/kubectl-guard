package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigLocationEnvOverride: with KUBECTL_GUARD_CONFIG set, the config is
// read/written at that path (not the HOME default) and `config path` reports it.
// #36. Runs runConfigCommand in-process (helpers from main_config_cmd_test.go).
func TestConfigLocationEnvOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	custom := filepath.Join(t.TempDir(), "guard.yaml")
	t.Setenv("KUBECTL_GUARD_CONFIG", custom)
	t.Setenv("KUBECTL_GUARD_AUDIT_LOG", "")

	out, err := runConfigInProc(t, "path")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, custom) {
		t.Errorf("config path = %q, want it to contain %q", strings.TrimSpace(out), custom)
	}

	mustRun(t, "add-context", "prod-*")
	if _, err := os.Stat(custom); err != nil {
		t.Errorf("config not written at KUBECTL_GUARD_CONFIG path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".kubectl-guard.yaml")); !os.IsNotExist(err) {
		t.Errorf("config unexpectedly written at the HOME default (env override ignored)")
	}

	// Read-back goes through the override too.
	if got := loadCfg(t).ProtectedContexts; len(got) != 1 || got[0].Pattern != "prod-*" {
		t.Errorf("config read back from custom path = %v, want [prod-*]", got)
	}
}

// TestAuditLogEnvOverride: KUBECTL_GUARD_AUDIT_LOG redirects the audit log. #36.
func TestAuditLogEnvOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KUBECTL_GUARD_CONFIG", filepath.Join(t.TempDir(), "guard.yaml"))
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	t.Setenv("KUBECTL_GUARD_AUDIT_LOG", auditPath)

	// A config mutation is audited; the entry must land at the override path.
	mustRun(t, "add-context", "prod-*")
	if _, err := os.Stat(auditPath); err != nil {
		t.Errorf("audit not written at KUBECTL_GUARD_AUDIT_LOG path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".kubectl-guard-audit.log")); !os.IsNotExist(err) {
		t.Errorf("audit unexpectedly written at the HOME default")
	}
}

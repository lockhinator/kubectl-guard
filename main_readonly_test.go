package main

import (
	"strings"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// TestReadOnlyIntegration exercises freeze end to end via the built binary:
// state-altering commands are Blocked (exit 2) and audited as read-only-mode,
// --yes does not override, reads pass. #94.
func TestReadOnlyIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	_, stderr, code, audit := runGuardBin(t, "read_only: true\naudit_mode: all\n", "delete", "pod", "nginx")
	if code != 2 {
		t.Fatalf("delete under read_only exit %d, want 2 (blocked); stderr=%s", code, stderr)
	}
	if !strings.Contains(audit, "read-only-mode") {
		t.Errorf("audit missing read-only-mode reason:\n%s", audit)
	}

	if _, _, code, _ := runGuardBin(t, "read_only: true\n", "get", "pods"); code != 0 {
		t.Errorf("get under read_only exit %d, want 0 (reads pass)", code)
	}
	if _, _, code, _ := runGuardBin(t, "read_only: true\n", "--yes", "delete", "pod", "nginx"); code != 2 {
		t.Errorf("--yes under read_only exit %d, want 2 (--yes must NOT override freeze)", code)
	}
}

// TestFreezeUnfreeze: the freeze/unfreeze commands toggle read_only on disk, and
// unfreeze is treated as a protection-weakening change. #94.
func TestFreezeUnfreeze(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KUBECTL_GUARD_CONFIG", "")
	t.Setenv("KUBECTL_GUARD_AUDIT_LOG", "")

	if err := runFreeze(true); err != nil {
		t.Fatal(err)
	}
	if cfg := loadCfg(t); !cfg.ReadOnly {
		t.Fatalf("freeze did not set read_only")
	}
	if err := runFreeze(false); err != nil {
		t.Fatal(err)
	}
	if cfg := loadCfg(t); cfg.ReadOnly {
		t.Fatalf("unfreeze did not clear read_only")
	}

	// Unfreeze is a protection-weakening change (flagged by WeakensProtection).
	frozen := &config.Config{ReadOnly: true}
	thawed := &config.Config{ReadOnly: false}
	if w := config.WeakensProtection(frozen, thawed); len(w) == 0 {
		t.Errorf("unfreeze (read_only true→false) should be weakening, got none")
	}
}

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestBlockModeNotBypassedByYes: with context_mode: block, a state-altering
// command is hard-blocked and --yes cannot override it (exit 2, kubectl never
// runs). This is the core safety property of block mode.
func TestBlockModeNotBypassedByYes(t *testing.T) {
	stdout, _, code := runGuardWithEnv(t,
		"protected_contexts:\n  - prod-*\ncontext_mode: block\n",
		nil,
		"--context=prod-cluster", "--yes", "delete", "pod", "nginx")

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (block mode must NOT be bypassed by --yes)", code)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout (kubectl must not run), got %q", stdout)
	}
}

// TestBlockModeAuditReason: the audit log records a block-mode refusal as
// "blocked" with reason "protected-context-block-mode" (not "protected-resource").
func TestBlockModeAuditReason(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\ncontext_mode: block\naudit_mode: all\n")
	kubectlDir := writeFakeKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--context=prod-cluster", "delete", "pod", "nginx")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() != 2 {
			t.Fatalf("exit code = %d, want 2", ee.ExitCode())
		} else if !ok {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	data, rerr := os.ReadFile(home + "/.kubectl-guard-audit.log")
	if rerr != nil {
		t.Fatalf("audit log not written: %v", rerr)
	}
	s := string(data)
	if !strings.Contains(s, `"outcome":"blocked"`) {
		t.Errorf("audit should record blocked, got:\n%s", s)
	}
	if !strings.Contains(s, `"reason":"protected-context-block-mode"`) {
		t.Errorf("audit reason should be protected-context-block-mode, got:\n%s", s)
	}
}

// TestBlockModeJSONReason: in --json mode, a block-mode refusal reports the
// block-mode reason (not "protected-resource") and no resource token.
func TestBlockModeJSONReason(t *testing.T) {
	_, stderr, code := runGuardWithEnv(t,
		"protected_contexts:\n  - prod-*\ncontext_mode: block\n",
		nil,
		"--json", "--context=prod-cluster", "delete", "pod", "nginx")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "protected-context-block-mode") {
		t.Errorf("json reason should mention block-mode, got: %s", stderr)
	}
	if strings.Contains(stderr, `"resource":`) {
		t.Errorf("block-mode json should not carry a resource token, got: %s", stderr)
	}
}

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestDryRunPassesThroughAndAudited: a dry-run apply on a protected context is
// forwarded to the real kubectl (no prompt) and audited as "dry-run".
func TestDryRunPassesThroughAndAudited(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\naudit_mode: all\n")
	kubectlDir := writeFakeKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--context=prod-cluster", "apply", "--dry-run=client", "-f", "deploy.yaml")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() != 0 {
			t.Fatalf("exit code = %d, want 0 (dry-run should pass through): stderr=%s", ee.ExitCode(), errBuf.String())
		} else if !ok {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	// The command was forwarded to the fake kubectl (which echoes args).
	if !strings.Contains(outBuf.String(), "apply") || !strings.Contains(outBuf.String(), "deploy.yaml") {
		t.Errorf("expected the command forwarded to kubectl, got stdout=%q", outBuf.String())
	}
	// No confirmation prompt should appear.
	if strings.Contains(strings.ToLower(errBuf.String()), "confirm") {
		t.Errorf("dry-run must not prompt, got stderr=%q", errBuf.String())
	}

	data, rerr := os.ReadFile(home + "/.kubectl-guard-audit.log")
	if rerr != nil {
		t.Fatalf("audit log not written: %v", rerr)
	}
	if !strings.Contains(string(data), `"outcome":"dry-run"`) {
		t.Errorf("audit should record outcome dry-run, got:\n%s", string(data))
	}
}

// TestDryRunNonePrompts: --dry-run=none still gates (prompts/aborts without a TTY).
func TestDryRunNonePrompts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\n")
	kubectlDir := writeFakeKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--context=prod-cluster", "apply", "--dry-run=none", "-f", "deploy.yaml")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	// No TTY -> RequireConfirmation aborts with exit 4 (not forwarded).
	if code != 4 {
		t.Errorf("exit code = %d, want 4 (--dry-run=none should gate and abort without TTY)", code)
	}
}

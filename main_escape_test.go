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

// runGuardWithEnv is like runGuardWithConfig but also sets extra env vars
// (e.g. KUBECTL_GUARD_CONFIRM, KUBECTL_GUARD_BYPASS). A timeout guards against
// any unexpected interactive prompt hanging the test.
func runGuardWithEnv(t *testing.T, cfgYAML string, extraEnv []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	if cfgYAML != "" {
		writeConfig(t, home, cfgYAML)
	}
	kubectlDir := writeFakeKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	env := []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	env = append(env, extraEnv...)
	cmd.Env = env
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("guard hung (interactive prompt likely launched): %v", ctx.Err())
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error running guard: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), code
}

// TestYesAutoConfirmsRequireConfirmation: on a protected context, --yes runs
// the command (forwards to kubectl) without prompting, and the audit log
// records "auto-confirmed".
func TestYesAutoConfirmsRequireConfirmation(t *testing.T) {
	stdout, stderr, code := runGuardWithEnv(t,
		"protected_contexts:\n  - prod-*\n",
		nil,
		"--context=prod-cluster", "--yes", "delete", "pod", "nginx")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (--yes should auto-confirm and run)", code)
	}
	if !strings.Contains(stdout, "delete pod nginx") {
		t.Errorf("expected the command to be forwarded to kubectl, got stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "auto-confirm") && !strings.Contains(stderr, "Auto-confirming") {
		t.Errorf("expected an auto-confirm warning on stderr, got %q", stderr)
	}
}

// TestYesEnvAutoConfirms: KUBECTL_GUARD_CONFIRM=yes behaves like the --yes flag.
func TestYesEnvAutoConfirms(t *testing.T) {
	stdout, _, code := runGuardWithEnv(t,
		"protected_contexts:\n  - prod-*\n",
		[]string{"KUBECTL_GUARD_CONFIRM=yes"},
		"--context=prod-cluster", "delete", "pod", "nginx")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "delete pod nginx") {
		t.Errorf("expected the command to be forwarded, got stdout=%q", stdout)
	}
}

// TestYesDoesNotBypassBlocked: --yes must NOT bypass a protected-resource
// Block. A blocked command stays blocked (exit 2, kubectl never runs).
func TestYesDoesNotBypassBlocked(t *testing.T) {
	stdout, _, code := runGuardWithEnv(t,
		"protected_resources:\n  - secret\n",
		nil,
		"--yes", "get", "secret")

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (Blocked must NOT be bypassed by --yes)", code)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout (kubectl must not run), got %q", stdout)
	}
}

// TestAutoConfirmedAuditEntry asserts the audit log records outcome
// "auto-confirmed" (not "confirmed") when --yes is used.
func TestAutoConfirmedAuditEntry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\naudit_mode: all\n")
	kubectlDir := writeFakeKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--context=prod-cluster", "--yes", "delete", "pod", "nginx")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() != 0 {
			t.Fatalf("exit code = %d, want 0: %v", ee.ExitCode(), err)
		} else if !ok {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	data, rerr := os.ReadFile(home + "/.kubectl-guard-audit.log")
	if rerr != nil {
		t.Fatalf("audit log not written: %v", rerr)
	}
	s := string(data)
	if !strings.Contains(s, "auto-confirmed") {
		t.Errorf("audit log should record 'auto-confirmed', got:\n%s", s)
	}
	if strings.Contains(s, "\"outcome\":\"confirmed\"") {
		t.Errorf("audit log must not record plain 'confirmed' for --yes, got:\n%s", s)
	}
}

// TestBypassEnvRunsCommand: KUBECTL_GUARD_BYPASS disables the guard entirely —
// even a protected-resource command runs against the real kubectl.
func TestBypassEnvRunsCommand(t *testing.T) {
	stdout, stderr, code := runGuardWithEnv(t,
		"protected_resources:\n  - secret\nprotected_contexts:\n  - prod-*\n",
		[]string{"KUBECTL_GUARD_BYPASS=1"},
		"get", "secret")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (bypass should run the command)", code)
	}
	if !strings.Contains(stdout, "get secret") {
		t.Errorf("expected the command to be forwarded under bypass, got stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "BYPASS") {
		t.Errorf("expected a bypass warning on stderr, got %q", stderr)
	}
}

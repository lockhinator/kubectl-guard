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

// runGuardBin runs the built guard against a fake kubectl with the given config
// written to a temp HOME, returning stdout, stderr, exit code, and the audit log.
func runGuardBin(t *testing.T, cfgYAML string, args ...string) (stdout, stderr string, code int, auditLog string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, cfgYAML)
	writeKubeconfig(t, home, "fake-context", nil)
	kubectlDir := writeFakeKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("guard hung: %v", ctx.Err())
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error running guard: %v", err)
		}
	}
	if data, rerr := os.ReadFile(home + "/.kubectl-guard-audit.log"); rerr == nil {
		auditLog = string(data)
	}
	return outBuf.String(), errBuf.String(), code, auditLog
}

// TestPortForwardUnprotectedContextPassesThroughAndAudited covers the #71
// acceptance criterion "Both pass through on an unprotected context
// (unchanged), and are audited".
func TestPortForwardUnprotectedContextPassesThroughAndAudited(t *testing.T) {
	stdout, stderr, code, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=dev-cluster", "port-forward", "svc/api", "8080:80")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (unprotected context passes through): stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "port-forward") {
		t.Errorf("expected the command forwarded to kubectl, got stdout=%q", stdout)
	}
	if !strings.Contains(audit, `"outcome":"allowed"`) {
		t.Errorf("audit should record outcome allowed, got:\n%s", audit)
	}
	if !strings.Contains(audit, "port-forward") {
		t.Errorf("audit should record the port-forward command, got:\n%s", audit)
	}
}

// TestProxyUnprotectedContextAudited: same for proxy.
func TestProxyUnprotectedContextAudited(t *testing.T) {
	_, stderr, code, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=dev-cluster", "proxy")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0: stderr=%s", code, stderr)
	}
	if !strings.Contains(audit, `"outcome":"allowed"`) || !strings.Contains(audit, "proxy") {
		t.Errorf("audit should record proxy as allowed, got:\n%s", audit)
	}
}

// TestPortForwardProtectedContextGatedAndAudited: on a protected context with
// no TTY, port-forward must abort with the needs-confirmation exit code (4)
// rather than open a tunnel, and the abort must be audited.
func TestPortForwardProtectedContextGatedAndAudited(t *testing.T) {
	stdout, _, code, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=prod-cluster", "port-forward", "svc/prod-postgres", "5432:5432")

	if code != 4 {
		t.Fatalf("exit code = %d, want 4 (gated, aborted without TTY)", code)
	}
	if strings.Contains(stdout, "port-forward") {
		t.Errorf("port-forward must NOT be forwarded to kubectl on a protected context, got stdout=%q", stdout)
	}
	if !strings.Contains(audit, `"outcome":"aborted"`) {
		t.Errorf("audit should record outcome aborted, got:\n%s", audit)
	}
}

// TestProxyProtectedContextBlockModeAudited: in block mode, proxy is hard
// refused (exit 2) with no prompt offered.
func TestProxyProtectedContextBlockModeAudited(t *testing.T) {
	stdout, _, code, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\ncontext_mode: block\naudit_mode: all\n",
		"--context=prod-cluster", "proxy")

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (blocked)", code)
	}
	if strings.Contains(stdout, "proxy") {
		t.Errorf("proxy must NOT be forwarded in block mode, got stdout=%q", stdout)
	}
	if !strings.Contains(audit, `"outcome":"blocked"`) {
		t.Errorf("audit should record outcome blocked, got:\n%s", audit)
	}
}

// TestPortForwardDryRunAuditedAsAllowedNotDryRun: port-forward has no
// --dry-run, so on an unprotected context it must be audited as "allowed" —
// not mislabeled "dry-run" — and on a protected context it must still gate.
func TestPortForwardDryRunAuditedAsAllowedNotDryRun(t *testing.T) {
	_, _, code, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=dev-cluster", "port-forward", "--dry-run=client", "svc/api", "8080:80")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if strings.Contains(audit, `"outcome":"dry-run"`) {
		t.Errorf("port-forward has no dry-run; audit must not label it dry-run, got:\n%s", audit)
	}
	if !strings.Contains(audit, `"outcome":"allowed"`) {
		t.Errorf("audit should record outcome allowed, got:\n%s", audit)
	}
}

// TestVerbShiftPortForwardGatedEndToEnd is the end-to-end lock on the S3
// verb-shift bypass: `-v 3` must not hide the port-forward verb from gating.
// Before the fix this exec'd kubectl and opened a tunnel to prod.
func TestVerbShiftPortForwardGatedEndToEnd(t *testing.T) {
	stdout, _, code, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=prod-cluster", "-v", "3", "port-forward", "svc/prod-postgres", "5432:5432")

	if code != 4 {
		t.Fatalf("exit code = %d, want 4 (-v 3 must not bypass gating)", code)
	}
	if strings.Contains(stdout, "port-forward") {
		t.Errorf("verb-shift bypass: port-forward reached kubectl, stdout=%q", stdout)
	}
	if !strings.Contains(audit, `"outcome":"aborted"`) {
		t.Errorf("audit should record outcome aborted, got:\n%s", audit)
	}
}

// TestVerbShiftDeleteGatedEndToEnd: the same global-flag verb shift also hid
// `delete`, the flagship gated verb.
func TestVerbShiftDeleteGatedEndToEnd(t *testing.T) {
	stdout, _, code, _ := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"--context=prod-cluster", "--request-timeout", "30", "delete", "pod", "nginx")

	if code != 4 {
		t.Fatalf("exit code = %d, want 4 (--request-timeout must not bypass gating)", code)
	}
	if strings.Contains(stdout, "delete") {
		t.Errorf("verb-shift bypass: delete reached kubectl, stdout=%q", stdout)
	}
}

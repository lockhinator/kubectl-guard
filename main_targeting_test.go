package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestAuditRecordsImpersonation asserts that --as is captured in the audit log
// as the "impersonate" field, and --token sets "token":true. Runs a real built
// guard against a fake kubectl so the full audit path is exercised.
func TestAuditRecordsImpersonation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\naudit_mode: all\n")
	kubectlDir := writeFakeKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// A read-only command on a protected context is Allowed, so it runs and is
	// audited. Include --as and --token to exercise attribution.
	cmd := exec.CommandContext(ctx, bin,
		"--context=prod-cluster", "--as=system:admin", "--token", "tok", "get", "pods")
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
	if !strings.Contains(s, `"impersonate":"system:admin"`) {
		t.Errorf("audit log should record impersonate=system:admin, got:\n%s", s)
	}
	if !strings.Contains(s, `"token":true`) {
		t.Errorf("audit log should record token=true, got:\n%s", s)
	}
}

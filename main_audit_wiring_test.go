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

// runGuardAudit runs the built guard against a fake kubectl with the given
// config and stdin, returning the exit code and the audit-log contents. Unlike
// runGuardBin it feeds stdin, so the interactive confirmed/aborted outcomes can
// be exercised end to end.
func runGuardAudit(t *testing.T, cfgYAML, stdin string, args ...string) (code int, auditLog string) {
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
	cmd.Stdin = strings.NewReader(stdin)
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
	return code, auditLog
}

// TestAuditWiringPerOutcome asserts that each guard decision writes the correct
// audit outcome, and that audit_mode gates which outcomes are recorded. A
// regression in audit wiring (wrong outcome, missing entry, entry written under
// audit off) fails here. Covers #32.
func TestAuditWiringPerOutcome(t *testing.T) {
	const protectedAll = "protected_contexts:\n  - prod-*\naudit_mode: all\n"

	t.Run("allowed read is audited under audit_mode all", func(t *testing.T) {
		code, audit := runGuardAudit(t, protectedAll, "", "get", "pods")
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if !strings.Contains(audit, `"outcome":"allowed"`) {
			t.Errorf("audit missing allowed outcome:\n%s", audit)
		}
	})

	t.Run("auto-confirmed via --yes is audited", func(t *testing.T) {
		code, audit := runGuardAudit(t, protectedAll, "",
			"--context=prod-cluster", "--yes", "delete", "pod", "nginx")
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (auto-confirmed runs)", code)
		}
		if !strings.Contains(audit, `"outcome":"auto-confirmed"`) {
			t.Errorf("audit missing auto-confirmed outcome:\n%s", audit)
		}
	})

	t.Run("interactive yes is audited as confirmed and runs", func(t *testing.T) {
		code, audit := runGuardAudit(t, protectedAll, "y\n",
			"--context=prod-cluster", "delete", "pod", "nginx")
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (confirmed runs)", code)
		}
		if !strings.Contains(audit, `"outcome":"confirmed"`) {
			t.Errorf("audit missing confirmed outcome:\n%s", audit)
		}
	})

	t.Run("interactive no is audited as aborted and does not run", func(t *testing.T) {
		code, audit := runGuardAudit(t, protectedAll, "n\n",
			"--context=prod-cluster", "delete", "pod", "nginx")
		if code != 4 {
			t.Fatalf("exit = %d, want 4 (aborted)", code)
		}
		if !strings.Contains(audit, `"outcome":"aborted"`) {
			t.Errorf("audit missing aborted outcome:\n%s", audit)
		}
	})

	t.Run("blocked resource is audited", func(t *testing.T) {
		code, audit := runGuardAudit(t,
			"protected_resources:\n  - secret\naudit_mode: all\n", "",
			"get", "secret")
		if code != 2 {
			t.Fatalf("exit = %d, want 2 (blocked)", code)
		}
		if !strings.Contains(audit, `"outcome":"blocked"`) {
			t.Errorf("audit missing blocked outcome:\n%s", audit)
		}
	})

	t.Run("audit_mode gated omits an allowed read but keeps a gated outcome", func(t *testing.T) {
		gated := "protected_contexts:\n  - prod-*\naudit_mode: gated\n"
		// A plain allowed read must NOT be logged under gated.
		_, allowAudit := runGuardAudit(t, gated, "", "get", "pods")
		if strings.Contains(allowAudit, `"outcome":"allowed"`) {
			t.Errorf("audit_mode gated logged an allowed read:\n%s", allowAudit)
		}
		// A gated (auto-confirmed) outcome must still be logged.
		_, gatedAudit := runGuardAudit(t, gated, "",
			"--context=prod-cluster", "--yes", "delete", "pod", "nginx")
		if !strings.Contains(gatedAudit, `"outcome":"auto-confirmed"`) {
			t.Errorf("audit_mode gated dropped a gated outcome:\n%s", gatedAudit)
		}
	})

	t.Run("audit_mode off records nothing", func(t *testing.T) {
		off := "protected_contexts:\n  - prod-*\naudit_mode: off\n"
		_, audit := runGuardAudit(t, off, "", "get", "pods")
		if strings.TrimSpace(audit) != "" {
			t.Errorf("audit_mode off wrote entries:\n%s", audit)
		}
	})
}

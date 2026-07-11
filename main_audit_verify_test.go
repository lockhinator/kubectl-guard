package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuditVerifyCLI exercises `config audit verify` exit codes end to end: an
// intact chain exits 0, a tampered or fully-stripped log exits non-zero. #78.
func TestAuditVerifyCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "audit_mode: all\n")
	kubectlDir := writeFakeKubectl(t)
	auditLog := filepath.Join(home, ".kubectl-guard-audit.log")

	env := []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	run := func(args ...string) (string, int) {
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		var buf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &buf, &buf
		code := 0
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatalf("run: %v", err)
			}
		}
		return buf.String(), code
	}

	// Generate a few audited entries.
	for i := 0; i < 3; i++ {
		run("get", "pods")
	}

	if out, code := run("config", "audit", "verify"); code != 0 || !strings.Contains(out, "INTACT") {
		t.Errorf("intact verify: code=%d out=%q, want 0/INTACT", code, out)
	}

	// Tamper: edit line 2's content -> broken, exit 1.
	lines := strings.Split(strings.TrimRight(readFile(t, auditLog), "\n"), "\n")
	lines[1] = strings.Replace(lines[1], "get pods", "delete node evil", 1)
	if err := os.WriteFile(auditLog, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := run("config", "audit", "verify"); code != 1 || !strings.Contains(out, "BROKEN") {
		t.Errorf("tampered verify: code=%d out=%q, want 1/BROKEN", code, out)
	}

	// Strip ALL hashes (erase history) -> unverifiable, exit non-zero.
	stripped := make([]string, len(lines))
	for i := range lines {
		stripped[i] = `{"time":"x","user":"attacker","command":"delete ns everything","outcome":"allowed"}`
	}
	if err := os.WriteFile(auditLog, []byte(strings.Join(stripped, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := run("config", "audit", "verify"); code == 0 {
		t.Errorf("strip-all verify: code=%d out=%q, want non-zero (unverifiable)", code, out)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigPermWarningIntegration exercises #34 end to end: a group/world-
// writable config warns (non-strict) but still runs; strict mode fails closed;
// a 0600 config loads silently.
func TestConfigPermWarningIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\n")
	writeKubeconfig(t, home, "fake-context", nil)
	path := filepath.Join(home, ".kubectl-guard.yaml")
	kubectlDir := writeFakeKubectl(t)

	run := func(extraEnv ...string) (stderr string, code int) {
		cmd := exec.Command(bin, "get", "pods")
		cmd.Env = append([]string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}, extraEnv...)
		var outBuf, errBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatalf("unexpected error running guard: %v", err)
			}
		}
		return errBuf.String(), code
	}

	// Non-strict, group/world-writable: warns but still runs (unprotected context).
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	stderr, code := run()
	if code != 0 {
		t.Fatalf("non-strict writable config: exit %d, want 0; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "group/world-writable") {
		t.Errorf("expected tamper warning, got stderr=%q", stderr)
	}

	// Strict via env: fails closed (denied, exit 3), nothing runs.
	stderr, code = run("KUBECTL_GUARD_STRICT=1")
	if code != 3 {
		t.Fatalf("strict writable config: exit %d, want 3 (denied); stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "Refusing to run") {
		t.Errorf("strict mode should refuse; stderr=%q", stderr)
	}

	// Restore 0600: loads silently, no warning.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	stderr, code = run()
	if code != 0 {
		t.Fatalf("0600 config: exit %d, want 0", code)
	}
	if strings.Contains(stderr, "group/world-writable") {
		t.Errorf("0600 config must not warn, got stderr=%q", stderr)
	}
}

// TestConfigParentDirTamperIntegration exercises the parent-directory vector end
// to end: a secure 0600 config in a world-writable HOME warns (non-strict) and
// fails closed (strict), because the file can be atomically replaced. #34.
func TestConfigParentDirTamperIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\n") // file is 0600
	writeKubeconfig(t, home, "fake-context", nil)
	path := filepath.Join(home, ".kubectl-guard.yaml")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o777); err != nil { // world-writable parent dir
		t.Fatal(err)
	}
	kubectlDir := writeFakeKubectl(t)

	run := func(extraEnv ...string) (stderr string, code int) {
		cmd := exec.Command(bin, "get", "pods")
		cmd.Env = append([]string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}, extraEnv...)
		var outBuf, errBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatalf("unexpected error running guard: %v", err)
			}
		}
		return errBuf.String(), code
	}

	// Non-strict: warns about the writable directory but still runs.
	stderr, code := run()
	if code != 0 {
		t.Fatalf("non-strict writable parent dir: exit %d, want 0; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "directory") || !strings.Contains(stderr, "writable") {
		t.Errorf("expected a writable-directory warning, got stderr=%q", stderr)
	}

	// Strict: fails closed even though the file itself is 0600.
	stderr, code = run("KUBECTL_GUARD_STRICT=1")
	if code != 3 {
		t.Fatalf("strict writable parent dir: exit %d, want 3 (denied); stderr=%s", code, stderr)
	}
}

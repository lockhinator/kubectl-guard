package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// TestKubectlNotFound asserts that when no kubectl is on PATH, an allowed
// command surfaces a clear, actionable message (not a raw Go exec error) and
// exits non-zero. Regression test for #33.
func TestKubectlNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	// Empty config: no protected contexts, so `get pods` reaches the Allow path
	// and hands off to ExecKubectl even though context resolution can't shell out.
	writeConfig(t, home, "{}\n")
	// A PATH pointing only at an empty dir: no kubectl anywhere. RealKubectlPath
	// walks it, finds nothing, and ExecKubectl fails with exec.ErrNotFound.
	emptyDir := t.TempDir()

	cmd := exec.Command(bin, "get", "pods")
	cmd.Env = []string{"HOME=" + home, "PATH=" + emptyDir}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("unexpected error running guard: %v", err)
		}
		code = ee.ExitCode()
	}

	if code == 0 {
		t.Fatalf("expected non-zero exit when kubectl is missing, got 0 (stderr=%q)", errBuf.String())
	}
	stderr := errBuf.String()
	if !strings.Contains(stderr, "kubectl not found on PATH") {
		t.Errorf("expected friendly not-found message, got stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "kubernetes.io/docs/tasks/tools") {
		t.Errorf("expected install instructions link, got stderr=%q", stderr)
	}
	// The raw Go lookup error must not leak to the user.
	if strings.Contains(stderr, "executable file not found in $PATH") {
		t.Errorf("raw Go exec error leaked to user: %q", stderr)
	}
}

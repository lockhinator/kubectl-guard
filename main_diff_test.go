package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeDiffKubectl installs a fake `kubectl` that answers current-context,
// prints a deterministic diff body for `diff`, and records non-config
// invocations to $KGMARKER. Returns its directory.
func writeDiffKubectl(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "config" ] && [ "$2" = "current-context" ]; then
  echo "prod-cluster"
  exit 0
fi
if [ "$1" = "diff" ]; then
  echo "+ this would be added"
  echo "- this would be removed"
  exit 0
fi
echo "ran: $*" >> "$KGMARKER"
`
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestDiffBeforeConfirmShowsDiff: with diff_before_confirm: true, an apply -f on
// a protected context runs `kubectl diff` and prints its output to stderr
// before prompting. (The prompt then aborts because stdin is empty/no TTY.)
func TestDiffBeforeConfirmShowsDiff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	// prod-cluster is the current context (kubeconfig sets it); protect it.
	writeConfig(t, home, "protected_contexts:\n  - prod-*\ndiff_before_confirm: true\n")
	writeKubeconfig(t, home, "prod-cluster", nil)
	kubectlDir := writeDiffKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "apply", "-f", "deploy.yaml")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	// stdin is empty -> Confirm reads EOF -> aborts (exit 4)
	_ = cmd.Run()
	stderr := errBuf.String()

	if !strings.Contains(stderr, "kubectl diff") {
		t.Errorf("expected a diff preview header on stderr, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "this would be added") {
		t.Errorf("expected the diff body on stderr, got:\n%s", stderr)
	}
}

// TestDiffSkippedForNonDiffable: delete (not diffable) does not run a diff even
// with diff_before_confirm: true.
func TestDiffSkippedForNonDiffable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\ndiff_before_confirm: true\n")
	writeKubeconfig(t, home, "prod-cluster", nil)
	kubectlDir := writeDiffKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "delete", "pod", "nginx")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	_ = cmd.Run()
	stderr := errBuf.String()

	if strings.Contains(stderr, "kubectl diff") {
		t.Errorf("delete must not trigger a diff, got:\n%s", stderr)
	}
}

// TestDiffBeforeConfirmOffByDefault: without diff_before_confirm, no diff runs.
func TestDiffBeforeConfirmOffByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\n")
	writeKubeconfig(t, home, "prod-cluster", nil)
	kubectlDir := writeDiffKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "apply", "-f", "deploy.yaml")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	_ = cmd.Run()
	if strings.Contains(errBuf.String(), "kubectl diff") {
		t.Errorf("diff must not run by default, got:\n%s", errBuf.String())
	}
}

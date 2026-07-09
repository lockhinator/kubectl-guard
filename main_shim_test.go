package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildGuardBinary builds kubectl-guard into dir and returns its path.
func buildGuardBinary(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "kubectl-guard")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// writeFakeRealKubectl writes a fake kubectl that reports a fixed current
// context (so the guard's context resolution succeeds without a real cluster)
// and records every other invocation to $KGMARKER. Returns its path.
func writeFakeRealKubectl(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "kubectl")
	script := `#!/bin/sh
if [ "$1" = "config" ] && [ "$2" = "current-context" ]; then
  echo "test-context"
  exit 0
fi
echo "ran: $*" >> "$KGMARKER"
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestShimInterception exercises the PATH-shadowing install end to end against
// a built guard binary:
//   - forwarding: a safe command run via the shim reaches the REAL kubectl
//     (proving ExecKubectl does not loop into itself), and
//   - blocking: a protected-resource command is intercepted and never reaches
//     the real kubectl, even in a non-interactive subprocess.
func TestShimInterception(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	work := t.TempDir()
	guardBin := buildGuardBinary(t, work)

	shimDir := filepath.Join(work, "shim")
	realDir := filepath.Join(work, "real")
	homeDir := filepath.Join(work, "home")
	for _, d := range []string{shimDir, realDir, homeDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Shim: kubectl -> kubectl-guard (PATH-shadowing install).
	if err := os.Symlink(guardBin, filepath.Join(shimDir, "kubectl")); err != nil {
		t.Fatal(err)
	}
	writeFakeRealKubectl(t, realDir)

	// Minimal config: protect "secret", audit off. Empty protected contexts so
	// "get pods" is allowed and "get secret" is blocked globally.
	if err := os.WriteFile(filepath.Join(homeDir, ".kubectl-guard.yaml"),
		[]byte("protected_resources:\n  - secret\naudit_mode: \"off\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	shimKubectl := filepath.Join(shimDir, "kubectl")
	pathEnv := shimDir + string(os.PathListSeparator) + realDir

	t.Run("forwards safe command to real kubectl (no loop)", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "ran.txt")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, shimKubectl, "get", "pods")
		cmd.Env = []string{
			"PATH=" + pathEnv,
			"HOME=" + homeDir,
			"KGMARKER=" + marker,
		}
		out, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("shim invocation timed out (the guard likely looped into itself)")
		}
		if err != nil {
			t.Fatalf("shim invocation failed: %v\n%s", err, out)
		}
		data, rerr := os.ReadFile(marker)
		if rerr != nil {
			t.Fatalf("real kubectl did not run (no marker written): %v\noutput: %s", rerr, out)
		}
		if !strings.Contains(string(data), "get pods") {
			t.Errorf("marker = %q, want it to record the forwarded 'get pods'", string(data))
		}
	})

	t.Run("intercepts protected resource non-interactively", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "ran.txt")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, shimKubectl, "get", "secret")
		cmd.Env = []string{
			"PATH=" + pathEnv,
			"HOME=" + homeDir,
			"KGMARKER=" + marker,
		}
		out, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("shim invocation timed out (the guard likely looped into itself)")
		}
		if err == nil {
			t.Fatalf("expected get secret to be blocked (non-zero exit), got success\n%s", out)
		}
		if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
			t.Errorf("real kubectl must not run for a blocked command; marker exists: %v\noutput: %s", statErr, out)
		}
		if !strings.Contains(string(out), "Blocked") {
			t.Errorf("expected a 'Blocked' message, got: %s", out)
		}
	})
}

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// installFakeShim builds a guard binary and lays down a PATH-shadowing shim in
// $home/.local/share/kubectl-guard/shims (the DefaultShimDir under a temp HOME):
// a `kubectl` symlink to the guard plus a `kubectl-guard` binary copy, exactly
// like `make install-shim`. It also writes a real kubectl into realDir. It
// returns (guardBin, shimDir, realDir, pathEnv) with the shim first on PATH so
// interception is active before uninstall runs.
func installFakeShim(t *testing.T, home string) (guardBin, shimDir, realDir, pathEnv string) {
	t.Helper()
	work := t.TempDir()
	guardBin = buildGuardBinary(t, work)

	shimDir = filepath.Join(home, ".local", "share", "kubectl-guard", "shims")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// kubectl -> the running guard binary, so Doctor().Intercepted is true (the
	// shim resolves to the same executable as the invoked guard).
	if err := os.Symlink(guardBin, filepath.Join(shimDir, "kubectl")); err != nil {
		t.Fatal(err)
	}
	// The installer also drops a kubectl-guard binary copy into the shim dir.
	if err := os.Symlink(guardBin, filepath.Join(shimDir, "kubectl-guard")); err != nil {
		t.Fatal(err)
	}

	realDir = filepath.Join(work, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeRealKubectl(t, realDir)

	pathEnv = shimDir + string(os.PathListSeparator) + realDir
	return guardBin, shimDir, realDir, pathEnv
}

// runBin runs the guard binary with the given HOME and PATH, returning combined
// output and exit code.
func runBin(t *testing.T, bin, home, pathEnv, stdin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = []string{"HOME=" + home, "PATH=" + pathEnv}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %v: %v\n%s", args, err, out)
		}
	}
	return string(out), code
}

// TestUninstallRemovesShim: uninstall deletes the shim symlink + binary copy,
// reports the PATH line, and a follow-up doctor shows interception INACTIVE. #87.
func TestUninstallRemovesShim(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	guardBin, shimDir, _, pathEnv := installFakeShim(t, home)

	out, code := runBin(t, guardBin, home, pathEnv, "", "uninstall")
	if code != 0 {
		t.Fatalf("uninstall exit %d, want 0:\n%s", code, out)
	}
	if _, err := os.Lstat(filepath.Join(shimDir, "kubectl")); !os.IsNotExist(err) {
		t.Errorf("shim kubectl symlink still present after uninstall (err=%v)", err)
	}
	if _, err := os.Lstat(filepath.Join(shimDir, "kubectl-guard")); !os.IsNotExist(err) {
		t.Errorf("shim kubectl-guard copy still present after uninstall (err=%v)", err)
	}
	for _, want := range []string{"Removed the kubectl-guard shim", "export PATH=", "INACTIVE"} {
		if !strings.Contains(out, want) {
			t.Errorf("uninstall output missing %q:\n%s", want, out)
		}
	}

	// The shim dir is gone from PATH's perspective: a follow-up doctor (same PATH,
	// shim removed) must report interception is no longer active.
	dout, _ := runBin(t, guardBin, home, pathEnv, "", "doctor")
	if !strings.Contains(dout, "interception active") {
		t.Fatalf("doctor did not run its interception check:\n%s", dout)
	}
	if strings.Contains(dout, "kubectl resolves to the guard") {
		t.Errorf("doctor still reports interception active after uninstall:\n%s", dout)
	}
}

// TestUninstallPurge: --purge --yes removes the config + audit log; a plain
// uninstall leaves them in place. #87.
func TestUninstallPurge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	cfgPath := func(home string) string { return filepath.Join(home, ".kubectl-guard.yaml") }
	auditPath := func(home string) string { return filepath.Join(home, ".kubectl-guard-audit.log") }

	// Plain uninstall preserves config + audit.
	t.Run("preserve", func(t *testing.T) {
		home := t.TempDir()
		guardBin, _, _, pathEnv := installFakeShim(t, home)
		writeConfig(t, home, "protected_resources:\n  - secret\n")
		if err := os.WriteFile(auditPath(home), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		out, code := runBin(t, guardBin, home, pathEnv, "", "uninstall")
		if code != 0 {
			t.Fatalf("uninstall exit %d:\n%s", code, out)
		}
		if _, err := os.Stat(cfgPath(home)); err != nil {
			t.Errorf("plain uninstall removed the config: %v", err)
		}
		if _, err := os.Stat(auditPath(home)); err != nil {
			t.Errorf("plain uninstall removed the audit log: %v", err)
		}
	})

	// --purge --yes removes both.
	t.Run("purge", func(t *testing.T) {
		home := t.TempDir()
		guardBin, _, _, pathEnv := installFakeShim(t, home)
		writeConfig(t, home, "protected_resources:\n  - secret\n")
		if err := os.WriteFile(auditPath(home), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		out, code := runBin(t, guardBin, home, pathEnv, "", "uninstall", "--purge", "--yes")
		if code != 0 {
			t.Fatalf("uninstall --purge exit %d:\n%s", code, out)
		}
		if _, err := os.Stat(cfgPath(home)); !os.IsNotExist(err) {
			t.Errorf("--purge did not remove the config (err=%v)", err)
		}
		if _, err := os.Stat(auditPath(home)); !os.IsNotExist(err) {
			t.Errorf("--purge did not remove the audit log (err=%v)", err)
		}
		if !strings.Contains(out, "Removed the files listed above") {
			t.Errorf("--purge did not report removal:\n%s", out)
		}
	})

	// --purge without --yes and a "no" answer aborts, leaving the files.
	t.Run("purge-declined", func(t *testing.T) {
		home := t.TempDir()
		guardBin, _, _, pathEnv := installFakeShim(t, home)
		writeConfig(t, home, "protected_resources:\n  - secret\n")
		if err := os.WriteFile(auditPath(home), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		out, code := runBin(t, guardBin, home, pathEnv, "n\n", "uninstall", "--purge")
		if code != 0 {
			t.Fatalf("uninstall --purge (declined) exit %d:\n%s", code, out)
		}
		if _, err := os.Stat(cfgPath(home)); err != nil {
			t.Errorf("declined purge removed the config: %v", err)
		}
		if !strings.Contains(out, "Purge aborted") {
			t.Errorf("declined purge did not report abort:\n%s", out)
		}
	})
}

// TestUninstallNoop: with nothing installed, uninstall succeeds and reports
// there was nothing to remove (idempotent/safe). #87.
func TestUninstallNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	// A guard binary + real kubectl, but NO shim installed.
	work := t.TempDir()
	guardBin := buildGuardBinary(t, work)
	realDir := filepath.Join(work, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeRealKubectl(t, realDir)

	out, code := runBin(t, guardBin, home, realDir, "", "uninstall")
	if code != 0 {
		t.Fatalf("no-op uninstall exit %d, want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "nothing to remove") {
		t.Errorf("no-op uninstall did not report an empty removal:\n%s", out)
	}
	if !strings.Contains(out, "INACTIVE") {
		t.Errorf("no-op uninstall did not confirm interception inactive:\n%s", out)
	}
}

// TestUninstallCustomShimDirPreservesGuardBinary: a custom --shim-dir (NOT the
// default) holding a real regular-file kubectl-guard binary + kubectl (e.g. a
// mistargeted /usr/local/bin) must delete NEITHER — restoring symmetry with the
// kubectl guarantee. Regression for the security review's Finding A. #87.
func TestUninstallCustomShimDirPreservesGuardBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	work := t.TempDir()
	guardBin := buildGuardBinary(t, work)

	binDir := filepath.Join(work, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	realKubectl := filepath.Join(binDir, "kubectl")
	realGuard := filepath.Join(binDir, "kubectl-guard")
	for _, p := range []string{realKubectl, realGuard} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho real\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	out, code := runBin(t, guardBin, home, binDir, "", "uninstall", "--shim-dir", binDir)
	if code != 0 {
		t.Fatalf("uninstall exit %d:\n%s", code, out)
	}
	if _, err := os.Stat(realKubectl); err != nil {
		t.Errorf("uninstall deleted a real kubectl in a custom --shim-dir: %v", err)
	}
	if _, err := os.Stat(realGuard); err != nil {
		t.Errorf("uninstall deleted a real kubectl-guard binary in a custom --shim-dir: %v", err)
	}
	if !strings.Contains(out, "left untouched") {
		t.Errorf("uninstall did not warn about the untouched binary:\n%s", out)
	}
}

// TestUninstallShimDirRequiresValue: `--shim-dir` with no value (or another flag
// as the value) must error, not silently target the default dir or eat the next
// flag. Regression for the security review's Finding C. #87.
func TestUninstallShimDirRequiresValue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	work := t.TempDir()
	guardBin := buildGuardBinary(t, work)
	realDir := filepath.Join(work, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeRealKubectl(t, realDir)

	for _, args := range [][]string{
		{"uninstall", "--shim-dir"},
		{"uninstall", "--shim-dir", "--purge"},
	} {
		out, code := runBin(t, guardBin, home, realDir, "", args...)
		if code != 1 {
			t.Errorf("%v exit %d, want 1:\n%s", args, code, out)
		}
		if !strings.Contains(out, "requires a directory argument") {
			t.Errorf("%v did not report the missing value:\n%s", args, out)
		}
	}
}

// TestUninstallPurgeRemovesArchives: --purge removes the audit log AND its
// rotated archives (<log>.N) and lock file, not just the live log. Regression for
// the adversarial review's Finding 1. #87.
func TestUninstallPurgeRemovesArchives(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	guardBin, _, _, pathEnv := installFakeShim(t, home)
	writeConfig(t, home, "protected_resources:\n  - secret\n")
	logp := filepath.Join(home, ".kubectl-guard-audit.log")
	archives := []string{logp, logp + ".1", logp + ".2", logp + ".lock"}
	for _, f := range archives {
		if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, code := runBin(t, guardBin, home, pathEnv, "", "uninstall", "--purge", "--yes")
	if code != 0 {
		t.Fatalf("uninstall --purge exit %d:\n%s", code, out)
	}
	for _, f := range archives {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("--purge left %s behind (err=%v)", f, err)
		}
	}
}

// TestUninstallPurgeAuditsToWebhook: --purge writes a final audit record BEFORE
// deleting the local log, so a configured off-box sink still captures that the
// trail was destroyed. Regression for the security review's Finding B. #87.
func TestUninstallPurgeAuditsToWebhook(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	guardBin, _, _, pathEnv := installFakeShim(t, home)

	bodies := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	writeConfig(t, home, "audit_mode: all\naudit_webhook_url: "+srv.URL+"\n")
	if err := os.WriteFile(filepath.Join(home, ".kubectl-guard-audit.log"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := runBin(t, guardBin, home, pathEnv, "", "uninstall", "--purge", "--yes")
	if code != 0 {
		t.Fatalf("uninstall --purge exit %d:\n%s", code, out)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case b := <-bodies:
			if strings.Contains(b, "uninstall --purge") {
				return // the purge was captured off-box before deletion
			}
		case <-deadline:
			t.Fatalf("webhook never received the purge audit record")
		}
	}
}

// TestUninstallSecondGuardShimStillActive: removing one shim while ANOTHER
// kubectl-guard shim is still earlier on PATH must report interception STILL
// ACTIVE, not a false INACTIVE. Regression for the adversarial review's Finding
// 2. #87.
func TestUninstallSecondGuardShimStillActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	work := t.TempDir()
	guardBin := buildGuardBinary(t, work)

	// The default shim (removed by uninstall), invoked via its own symlink so the
	// running binary resolves to guardBin.
	shimDir := filepath.Join(home, ".local", "share", "kubectl-guard", "shims")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kubectl", "kubectl-guard"} {
		if err := os.Symlink(guardBin, filepath.Join(shimDir, name)); err != nil {
			t.Fatal(err)
		}
	}

	// A SEPARATE guard install (its own inode) earlier on PATH.
	other := filepath.Join(work, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(guardBin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "kubectl-guard"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("kubectl-guard", filepath.Join(other, "kubectl")); err != nil {
		t.Fatal(err)
	}

	realDir := filepath.Join(work, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeRealKubectl(t, realDir)

	sep := string(os.PathListSeparator)
	pathEnv := other + sep + shimDir + sep + realDir
	out, code := runBin(t, filepath.Join(shimDir, "kubectl-guard"), home, pathEnv, "", "uninstall")
	if code != 0 {
		t.Fatalf("uninstall exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "STILL ACTIVE") {
		t.Errorf("uninstall falsely reported inactive with a second guard shim on PATH:\n%s", out)
	}
}

// TestUninstallLeavesRealKubectl: a regular-file `kubectl` in the shim dir (not
// our symlink) is never deleted — a mistargeted shim dir cannot wipe a real
// kubectl. #87.
func TestUninstallLeavesRealKubectl(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	work := t.TempDir()
	guardBin := buildGuardBinary(t, work)

	shimDir := filepath.Join(home, ".local", "share", "kubectl-guard", "shims")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A REAL kubectl regular file sitting where the shim would be.
	realKubectl := filepath.Join(shimDir, "kubectl")
	if err := os.WriteFile(realKubectl, []byte("#!/bin/sh\necho real\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	out, code := runBin(t, guardBin, home, shimDir, "", "uninstall")
	if code != 0 {
		t.Fatalf("uninstall exit %d:\n%s", code, out)
	}
	if _, err := os.Stat(realKubectl); err != nil {
		t.Errorf("uninstall deleted a regular-file kubectl it should have left: %v", err)
	}
	if !strings.Contains(out, "regular file") {
		t.Errorf("uninstall did not warn about the untouched regular file:\n%s", out)
	}
}

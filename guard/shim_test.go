package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setPath replaces PATH for the test (and restores it automatically via
// t.Setenv). Tests must control PATH exactly to exercise the shim-skipping
// logic deterministically.
func setPath(t *testing.T, dirs []string) {
	t.Helper()
	t.Setenv("PATH", strings.Join(dirs, string(os.PathListSeparator)))
}

// writeFakeKubectl creates a distinct, non-executable-guard file named kubectl
// in dir and returns its path. RealKubectlPath only stats the candidate, so the
// file need not be runnable for the resolution tests.
func writeFakeKubectl(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "kubectl")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho real\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRealKubectlPathSkipsSelfShim is the core regression test for the
// PATH-shadowing install: when a shim named kubectl (symlinked to the running
// binary) sits EARLIER on PATH than the real kubectl, RealKubectlPath must
// return the real binary, not itself. Reverting ExecKubectl to a plain
// exec.LookPath("kubectl") makes this fail (it would return the shim).
func TestRealKubectlPathSkipsSelfShim(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	shimDir := t.TempDir()
	realDir := t.TempDir()

	// Shim: kubectl -> the running test binary (simulates the guard shim).
	if err := os.Symlink(self, filepath.Join(shimDir, "kubectl")); err != nil {
		t.Fatal(err)
	}
	real := writeFakeKubectl(t, realDir)

	setPath(t, []string{shimDir, realDir})

	got, err := RealKubectlPath()
	if err != nil {
		t.Fatalf("RealKubectlPath: %v", err)
	}
	if got != real {
		t.Errorf("RealKubectlPath = %q, want %q (must skip self shim)", got, real)
	}
}

// TestRealKubectlPathNoShim confirms the common (alias) install still resolves:
// with no self-shadow on PATH, the first kubectl is returned.
func TestRealKubectlPathNoShim(t *testing.T) {
	realDir := t.TempDir()
	real := writeFakeKubectl(t, realDir)

	setPath(t, []string{realDir})

	got, err := RealKubectlPath()
	if err != nil {
		t.Fatalf("RealKubectlPath: %v", err)
	}
	if got != real {
		t.Errorf("RealKubectlPath = %q, want %q", got, real)
	}
}

// TestDoctorDetectsInterception verifies doctor reports ACTIVE interception when
// the shim (self) is first on PATH, and still resolves the real kubectl.
func TestDoctorDetectsInterception(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	shimDir := t.TempDir()
	realDir := t.TempDir()
	if err := os.Symlink(self, filepath.Join(shimDir, "kubectl")); err != nil {
		t.Fatal(err)
	}
	real := writeFakeKubectl(t, realDir)

	setPath(t, []string{shimDir, realDir})

	r := Doctor()
	if !r.Intercepted {
		t.Errorf("Intercepted = false, want true (shim is first on PATH)")
	}
	if r.RealKubectlPath != real {
		t.Errorf("RealKubectlPath = %q, want %q", r.RealKubectlPath, real)
	}
	if len(r.KubectlOnPath) != 2 {
		t.Errorf("KubectlOnPath has %d entries, want 2 (shim + real)", len(r.KubectlOnPath))
	}
}

// TestDoctorNoInterception verifies doctor reports INACTIVE interception when
// the real kubectl is first on PATH (no shim).
func TestDoctorNoInterception(t *testing.T) {
	realDir := t.TempDir()
	real := writeFakeKubectl(t, realDir)

	setPath(t, []string{realDir})

	r := Doctor()
	if r.Intercepted {
		t.Errorf("Intercepted = true, want false (no shim on PATH)")
	}
	if r.RealKubectlPath != real {
		t.Errorf("RealKubectlPath = %q, want %q", r.RealKubectlPath, real)
	}
}

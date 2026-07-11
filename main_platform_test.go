package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestWindowsUnsupportedMessage locks the native-Windows non-goal message (#88):
// it must name WSL2 and say Windows is unsupported, so a user who lands here gets
// actionable guidance rather than a cryptic failure.
func TestWindowsUnsupportedMessage(t *testing.T) {
	for _, want := range []string{"Windows is not supported", "WSL2", "wsl --install"} {
		if !strings.Contains(windowsUnsupportedMessage, want) {
			t.Errorf("windowsUnsupportedMessage missing %q:\n%s", want, windowsUnsupportedMessage)
		}
	}
}

// TestWindowsCrossCompiles guards the Windows non-goal deliverable (#88): the
// binary must still COMPILE for GOOS=windows (so it can print the WSL2 message
// instead of failing to build). It catches a regression where a new unix-only
// syscall is added without a //go:build tag, which would break cross-compilation.
func TestWindowsCrossCompiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-compile test in short mode")
	}
	// Build the main package (not ./...): it imports guard + config, so this still
	// compiles every package for windows and catches a missing build tag there,
	// while producing a single output file.
	out := filepath.Join(t.TempDir(), "kubectl-guard-windows.exe")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("GOOS=windows build failed (a unix-only syscall likely needs a //go:build tag):\n%v\n%s", err, b)
	}
}

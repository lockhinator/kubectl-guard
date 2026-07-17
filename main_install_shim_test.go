//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lockhinator/kubectl-guard/guard"
)

func TestInstallShimRepairsPATHOrderingAndIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	work := t.TempDir()
	bin := buildGuardBinary(t, work)
	realDir := filepath.Join(work, "real")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeFakeRealKubectl(t, realDir)
	rc := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(rc, []byte("export PATH=\""+realDir+":$PATH\"\n"), 0640); err != nil {
		t.Fatal(err)
	}
	pathEnv := realDir + string(os.PathListSeparator) + "/usr/bin:/bin"
	for i := 0; i < 2; i++ {
		out, code := runBin(t, bin, home, pathEnv, "", "install-shim", "--shell-config", rc)
		if code != 0 {
			t.Fatalf("install-shim run %d exit=%d:\n%s", i+1, code, out)
		}
	}
	shimDir, _ := guard.DefaultShimDir()
	data, err := os.ReadFile(rc)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Count(text, shimPathBlockStart) != 1 || !strings.HasSuffix(text, shimPathBlockEnd+"\n") {
		t.Fatalf("managed block is not unique and last:\n%s", text)
	}
	if info, err := os.Stat(rc); err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("shell config mode changed: info=%v err=%v", info, err)
	}
	installed := filepath.Join(shimDir, "kubectl-guard")
	newPath := shimDir + string(os.PathListSeparator) + pathEnv
	out, code := runBin(t, installed, home, newPath, "", "doctor", "--require-interception")
	if code != 0 || !strings.Contains(out, "kubectl resolves to the guard") {
		t.Fatalf("installed ordering does not intercept: exit=%d\n%s", code, out)
	}
}

func TestInstallShimRefusesToReplaceRealKubectl(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	bin := buildGuardBinary(t, t.TempDir())
	shimDir := filepath.Join(t.TempDir(), "shim")
	if err := os.MkdirAll(shimDir, 0755); err != nil {
		t.Fatal(err)
	}
	kubectlPath := filepath.Join(shimDir, "kubectl")
	if err := os.WriteFile(kubectlPath, []byte("real"), 0755); err != nil {
		t.Fatal(err)
	}
	out, code := runBin(t, bin, home, "/usr/bin:/bin", "", "install-shim", "--shim-dir", shimDir, "--shell-config", filepath.Join(home, ".profile"))
	if code == 0 || !strings.Contains(out, "refusing to replace non-symlink") {
		t.Fatalf("real kubectl was not rejected: exit=%d\n%s", code, out)
	}
	if data, err := os.ReadFile(kubectlPath); err != nil || string(data) != "real" {
		t.Fatalf("real kubectl changed: data=%q err=%v", data, err)
	}
}

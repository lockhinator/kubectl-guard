package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildGuardBinaryWithSystem builds the guard with its config.SystemConfigPath
// pinned to sysPath via an -ldflags -X override. This is how integration tests
// point the ENFORCED system-baseline path at a temp file: the var is never
// env-derived (that would defeat enforcement), but a build-time -X is a legitimate
// test seam, mirroring how the config unit tests set config.SystemConfigPath.
func buildGuardBinaryWithSystem(t *testing.T, dir, sysPath string) string {
	t.Helper()
	bin := filepath.Join(dir, "kubectl-guard")
	ld := "-X github.com/lockhinator/kubectl-guard/config.SystemConfigPath=" + sysPath
	out, err := exec.Command("go", "build", "-ldflags", ld, "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// enforcedFixture wires up an isolated HOME with a fake kubectl, a kubeconfig
// whose current context is protected, and a user config, plus a guard binary
// whose system-config path is sysPath. It returns the binary, HOME, the exec
// marker path, and the base env (PATH+HOME).
type enforcedFixture struct {
	bin    string
	home   string
	marker string
	env    []string
}

func newEnforcedFixture(t *testing.T, systemYAML, userYAML string) enforcedFixture {
	t.Helper()
	work := t.TempDir()
	home := filepath.Join(work, "home")
	realDir := filepath.Join(work, "real")
	sysDir := filepath.Join(work, "sys")
	for _, d := range []string{home, realDir, sysDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sysPath := filepath.Join(sysDir, "config.yaml")
	if systemYAML != "" {
		if err := os.WriteFile(sysPath, []byte(systemYAML), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin := buildGuardBinaryWithSystem(t, work, sysPath)

	// Fake kubectl: answers current-context = prod-cluster (protected by prod-*)
	// and records any executed command to $KGMARKER (proving a bypass or forward).
	marker := filepath.Join(work, "ran.txt")
	fake := `#!/bin/sh
if [ "$1" = "config" ] && [ "$2" = "current-context" ]; then
  echo "prod-cluster"
  exit 0
fi
echo "ran: $*" >> "$KGMARKER"
`
	if err := os.WriteFile(filepath.Join(realDir, "kubectl"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	// kubeconfig so clientcmd resolves current-context = prod-cluster.
	writeKubeconfig(t, home, "prod-cluster", nil)
	if userYAML != "" {
		if err := os.WriteFile(filepath.Join(home, ".kubectl-guard.yaml"), []byte(userYAML), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return enforcedFixture{
		bin:    bin,
		home:   home,
		marker: marker,
		env:    []string{"HOME=" + home, "PATH=" + realDir + ":/usr/bin:/bin", "KGMARKER=" + marker},
	}
}

func (f enforcedFixture) run(t *testing.T, extraEnv []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(f.bin, args...)
	cmd.Env = append(append([]string{}, f.env...), extraEnv...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return o.String(), e.String(), code
}

func (f enforcedFixture) ranMarkerExists() bool {
	_, err := os.Stat(f.marker)
	return err == nil
}

const enforcedSystemYAML = "enforced: true\n" +
	"context_mode: block\n" +
	"protected_contexts:\n  - prod-*\n" +
	"audit_mode: all\n"

// TestEnforcedForbidsBypass: KUBECTL_GUARD_BYPASS is ignored under an enforced
// system config; the command is still gated (blocked) and never reaches kubectl.
func TestEnforcedForbidsBypass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	f := newEnforcedFixture(t, enforcedSystemYAML, "")

	_, stderr, code := f.run(t, []string{"KUBECTL_GUARD_BYPASS=1"}, "delete", "pod", "foo")
	if code == 0 {
		t.Fatalf("bypassed delete exited 0; enforced config must still gate it\nstderr: %s", stderr)
	}
	if f.ranMarkerExists() {
		t.Errorf("real kubectl ran under an enforced bypass; it must not\nstderr: %s", stderr)
	}
	if !strings.Contains(stderr, "KUBECTL_GUARD_BYPASS is ignored") {
		t.Errorf("expected the ignored-bypass warning, got: %s", stderr)
	}

	// Regression: with a NON-enforced baseline, bypass works (kubectl runs).
	f2 := newEnforcedFixture(t, "context_mode: block\nprotected_contexts:\n  - prod-*\n", "")
	_, _, code2 := f2.run(t, []string{"KUBECTL_GUARD_BYPASS=1"}, "delete", "pod", "foo")
	if code2 != 0 {
		t.Errorf("non-enforced bypass should run kubectl (exit 0), got %d", code2)
	}
	if !f2.ranMarkerExists() {
		t.Error("non-enforced bypass must reach the real kubectl")
	}
}

// TestEnforcedForbidsAuditRedirect: KUBECTL_GUARD_AUDIT_LOG is ignored under an
// enforced system config that pins audit_log; audit lands at the pinned path.
func TestEnforcedForbidsAuditRedirect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	work := t.TempDir()
	pinned := filepath.Join(work, "pinned-audit.log")
	attacker := filepath.Join(work, "attacker-audit.log")
	sysYAML := enforcedSystemYAML + "audit_log: " + pinned + "\n"
	f := newEnforcedFixture(t, sysYAML, "")

	// A blocked delete is audited (audit_mode all).
	f.run(t, []string{"KUBECTL_GUARD_AUDIT_LOG=" + attacker}, "delete", "pod", "foo")

	if _, err := os.Stat(attacker); err == nil {
		t.Errorf("audit was redirected to the attacker path %s; the enforced pin must ignore the env", attacker)
	}
	data, err := os.ReadFile(pinned)
	if err != nil || len(data) == 0 {
		t.Fatalf("expected audit entries at the pinned path %s: err=%v len=%d", pinned, err, len(data))
	}
}

// TestEnforcedForbidsConfigRedirect: KUBECTL_GUARD_CONFIG cannot drop below the
// system floor under enforcement — the command stays gated.
func TestEnforcedForbidsConfigRedirect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	f := newEnforcedFixture(t, enforcedSystemYAML, "")
	empty := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(empty, []byte("protected_contexts: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := f.run(t, []string{"KUBECTL_GUARD_CONFIG=" + empty}, "delete", "pod", "foo")
	if code == 0 || f.ranMarkerExists() {
		t.Errorf("KUBECTL_GUARD_CONFIG must not drop below the system floor; delete should be gated\nstderr: %s", stderr)
	}
}

// TestEnforcedRemoveContextStillEnforced: removing a system-backed rule from the
// user config succeeds but the rule still applies, and the CLI says so.
func TestEnforcedRemoveContextStillEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	f := newEnforcedFixture(t, enforcedSystemYAML, "protected_contexts:\n  - prod-*\n")

	stdout, stderr, _ := f.run(t, nil, "config", "remove-context", "prod-*")
	out := stdout + stderr
	if !strings.Contains(out, "still enforced by the system baseline") {
		t.Errorf("expected the still-enforced note, got: %s", out)
	}
	// The decision still gates prod-cluster after the user removal.
	_, dstderr, code := f.run(t, nil, "delete", "pod", "foo")
	if code == 0 || f.ranMarkerExists() {
		t.Errorf("prod-* must stay gated by the system baseline after the user removal\nstderr: %s", dstderr)
	}
}

// TestDoctorReportsEnforcedBaseline: doctor surfaces the enforced baseline.
func TestDoctorReportsEnforcedBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	f := newEnforcedFixture(t, enforcedSystemYAML, "")
	stdout, stderr, _ := f.run(t, nil, "doctor")
	out := stdout + stderr
	if !strings.Contains(out, "enforced baseline active") {
		t.Errorf("doctor should report the enforced baseline, got: %s", out)
	}
}

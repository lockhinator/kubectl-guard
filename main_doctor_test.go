package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runDoctorBin runs `doctor <args...>` against the built binary with HOME and a
// fake kubectl on PATH, returning combined output and exit code.
func runDoctorBin(t *testing.T, home, kubectlDir string, args ...string) (string, int) {
	t.Helper()
	bin := buildGuardBin(t)
	cmd := exec.Command(bin, append([]string{"doctor"}, args...)...)
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run doctor: %v", err)
		}
	}
	return buf.String(), code
}

// TestDoctorHealthy: a valid config + resolvable context + writable audit +
// reachable kubectl → all checks pass (exit 0), with posture reported. #37.
func TestDoctorHealthy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	writeKubeconfig(t, home, "fake-context", nil)
	writeConfig(t, home, "protected_contexts:\n  - pattern: prod-*\n    mode: block\ncontext_mode: confirm\nprotected_resources:\n  - secret\n")
	out, code := runDoctorBin(t, home, writeFakeKubectl(t))
	if code != 0 {
		t.Errorf("healthy doctor exit %d, want 0:\n%s", code, out)
	}
	for _, want := range []string{"kubectl reachable", "config valid", "audit log writable", "current context resolvable", "Effective posture", "prod-* (block)"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output missing %q:\n%s", want, out)
		}
	}
}

// TestDoctorInvalidConfig: an invalid config fails the config check (exit 1). #37.
func TestDoctorInvalidConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	writeKubeconfig(t, home, "fake-context", nil)
	writeConfig(t, home, "context_mode: blck\n") // invalid mode
	out, code := runDoctorBin(t, home, writeFakeKubectl(t))
	if code != 1 {
		t.Errorf("invalid-config doctor exit %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "config valid") || !strings.Contains(out, "invalid") {
		t.Errorf("doctor did not flag the invalid config:\n%s", out)
	}
}

// TestDoctorJSON: --json emits a structured report with checks, posture, and a
// healthy flag. #37.
func TestDoctorJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	writeKubeconfig(t, home, "fake-context", nil)
	writeConfig(t, home, "protected_contexts:\n  - prod-*\n")
	out, code := runDoctorBin(t, home, writeFakeKubectl(t), "--json")
	if code != 0 {
		t.Fatalf("json doctor exit %d:\n%s", code, out)
	}
	var report struct {
		Checks  []map[string]string `json:"checks"`
		Posture map[string]string   `json:"posture"`
		Healthy bool                `json:"healthy"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &report); err != nil {
		t.Fatalf("doctor --json is not valid JSON: %v\n%s", err, out)
	}
	if len(report.Checks) == 0 || !report.Healthy {
		t.Errorf("json report: checks=%d healthy=%v, want >0/true", len(report.Checks), report.Healthy)
	}
}

// TestDoctorJSONUnhealthy: --json against an invalid config exits non-zero AND
// still emits valid JSON with healthy:false (the JSON branch has its own exit). #37.
func TestDoctorJSONUnhealthy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	writeKubeconfig(t, home, "fake-context", nil)
	writeConfig(t, home, "context_mode: blck\n") // invalid
	out, code := runDoctorBin(t, home, writeFakeKubectl(t), "--json")
	if code != 1 {
		t.Errorf("unhealthy --json exit %d, want 1", code)
	}
	var report struct {
		Healthy bool `json:"healthy"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &report); err != nil {
		t.Fatalf("unhealthy --json is not valid JSON: %v\n%s", err, out)
	}
	if report.Healthy {
		t.Errorf("healthy=true for an invalid config, want false")
	}
}

// TestDoctorStrictPermsFail: a group/world-writable config under strict mode
// flips the permissions check from warn to fail (exit 1). #37.
func TestDoctorStrictPermsFail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	writeKubeconfig(t, home, "fake-context", nil)
	writeConfig(t, home, "protected_contexts:\n  - prod-*\nstrict_config_perms: true\n")
	if err := os.Chmod(filepath.Join(home, ".kubectl-guard.yaml"), 0o664); err != nil {
		t.Fatal(err)
	}
	out, code := runDoctorBin(t, home, writeFakeKubectl(t))
	if code != 1 {
		t.Errorf("strict + writable config doctor exit %d, want 1:\n%s", code, out)
	}
}

// TestDoctorRequireInterception: without a PATH-shadow shim, --require-interception
// promotes interception from warn to fail (exit 1); default stays healthy. #37.
func TestDoctorRequireInterception(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	writeKubeconfig(t, home, "fake-context", nil)
	writeConfig(t, home, "protected_contexts:\n  - prod-*\n")
	kubectlDir := writeFakeKubectl(t)
	if _, code := runDoctorBin(t, home, kubectlDir); code != 0 {
		t.Errorf("default doctor exit %d, want 0 (interception is only a warn)", code)
	}
	if _, code := runDoctorBin(t, home, kubectlDir, "--require-interception"); code != 1 {
		t.Errorf("--require-interception doctor exit %d, want 1 (no shim)", code)
	}
}

// TestDoctorContextFailClosed: with protected contexts configured but no
// resolvable current context, the context check fails (exit 1) — mirroring the
// runtime fail-closed posture. #37.
func TestDoctorContextFailClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir() // no ~/.kube/config → no current context
	writeConfig(t, home, "protected_contexts:\n  - prod-*\n")
	out, code := runDoctorBin(t, home, writeFakeKubectl(t))
	if code != 1 {
		t.Errorf("unresolvable-context doctor exit %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "current context resolvable") || !strings.Contains(out, "fails closed") {
		t.Errorf("doctor did not flag the fail-closed context:\n%s", out)
	}
}

// TestDoctorAuditNotWritable: an audit log in a read-only directory fails the
// audit-writable check. #37.
func TestDoctorAuditNotWritable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	home := t.TempDir()
	writeKubeconfig(t, home, "fake-context", nil)
	roDir := filepath.Join(home, "readonly")
	if err := os.Mkdir(roDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) }) // let t.TempDir clean up
	writeConfig(t, home, "audit_log: "+filepath.Join(roDir, "audit.log")+"\n")
	out, code := runDoctorBin(t, home, writeFakeKubectl(t))
	if code != 1 {
		t.Errorf("read-only audit doctor exit %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "audit log writable") {
		t.Errorf("doctor did not flag the unwritable audit log:\n%s", out)
	}
}

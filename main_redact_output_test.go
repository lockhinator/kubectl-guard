package main

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// sentinelSecretB64 is base64("SENTINEL"); it is the `data.password` value of the
// canned Secret the fake kubectl emits. The structured redactor blanks it, so its
// PRESENCE in stdout proves the guard left the output untouched (syscall.Exec
// passthrough) and its ABSENCE proves redaction ran.
const sentinelSecretB64 = "U0VOVElORUw="

// cannedSecretYAML is the exact document the fake kubectl prints for any command
// (except its internal config/api-resources answers). It is a valid Secret.
const cannedSecretYAML = `apiVersion: v1
kind: Secret
metadata:
  name: db-creds
  namespace: default
type: Opaque
data:
  password: ` + sentinelSecretB64 + `
`

// writeSecretFakeKubectl installs a fake kubectl that answers the guard's internal
// probes and otherwise prints cannedSecretYAML, then exits with exitCode. This lets
// the redaction path be exercised without a real cluster while asserting exit-code
// propagation.
func writeSecretFakeKubectl(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  config) if [ \"$2\" = \"current-context\" ]; then echo fake-context; fi; exit 0 ;;\n" +
		"  api-resources) exit 0 ;;\n" +
		"esac\n" +
		"cat <<'YAML'\n" +
		cannedSecretYAML +
		"YAML\n" +
		"exit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(dir+"/kubectl", []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// runRedactGuard runs the built guard with a canned-secret fake kubectl in an
// isolated HOME, returning stdout, stderr, and exit code.
func runRedactGuard(t *testing.T, cfgYAML string, exitCode int, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	bin := buildGuardBin(t)
	home := t.TempDir()
	if cfgYAML != "" {
		writeConfig(t, home, cfgYAML)
	}
	writeKubeconfig(t, home, "fake-context", nil)
	kubectlDir := writeSecretFakeKubectl(t, exitCode)

	cmd := exec.Command(bin, args...)
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
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
	return outBuf.String(), errBuf.String(), code
}

// TestRedactOutputStructuredBlanksSecret: structured mode + get secret -o yaml
// blanks the secret value in stdout and preserves the fake kubectl's exit code.
func TestRedactOutputStructuredBlanksSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	stdout, _, code := runRedactGuard(t, "redact_output: structured\n", 0, "get", "secret", "db-creds", "-o", "yaml")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if strings.Contains(stdout, sentinelSecretB64) {
		t.Errorf("secret value survived structured redaction:\n%s", stdout)
	}
	if !strings.Contains(stdout, "***REDACTED (kubectl-guard)***") {
		t.Errorf("expected redaction marker in output:\n%s", stdout)
	}
	// Non-secret fields preserved.
	if !strings.Contains(stdout, "name: db-creds") {
		t.Errorf("metadata was lost:\n%s", stdout)
	}
}

// TestRedactOutputOffByteIdentical: the DEFAULT (off) mode is byte-for-byte
// identical to running the real kubectl directly — the guard still syscall.Exec's
// and never touches the output. This is HARD INVARIANT #1.
func TestRedactOutputOffByteIdentical(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	args := []string{"get", "secret", "db-creds", "-o", "yaml"}

	// off is the default; assert both an empty config and an explicit off.
	for _, cfg := range []string{"{}\n", "redact_output: off\n"} {
		stdout, _, code := runRedactGuard(t, cfg, 0, args...)
		if code != 0 {
			t.Fatalf("cfg %q: exit = %d, want 0", cfg, code)
		}
		if stdout != cannedSecretYAML {
			t.Errorf("cfg %q: off-mode output not byte-identical to raw kubectl:\ngot:\n%q\nwant:\n%q", cfg, stdout, cannedSecretYAML)
		}
		if !strings.Contains(stdout, sentinelSecretB64) {
			t.Errorf("cfg %q: secret value should be present in off mode (no redaction):\n%s", cfg, stdout)
		}
	}
}

// TestRedactOutputExitCodePreserved: on the structured (piped) path, kubectl's
// exit code is authoritative — a fake kubectl exiting 3 makes the guard exit 3.
func TestRedactOutputExitCodePreserved(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	_, _, code := runRedactGuard(t, "redact_output: structured\n", 3, "get", "secret", "-o", "yaml")
	if code != 3 {
		t.Fatalf("exit code = %d, want 3 (kubectl's code must propagate on the piped path)", code)
	}
}

// TestRedactOutputNonQualifyingUsesPassthrough: every command that does NOT match
// the narrow gate keeps the syscall.Exec passthrough (the sentinel survives),
// proving redaction is scoped to non-interactive, non-watch `get -o json|yaml`.
// This is HARD INVARIANT #2.
func TestRedactOutputNonQualifyingUsesPassthrough(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	cases := []struct {
		name string
		args []string
	}{
		{"wide read", []string{"get", "pods", "-o", "wide"}},
		{"jsonpath read", []string{"get", "pods", "-o", "jsonpath={.items}"}},
		{"table read (no -o)", []string{"get", "pods"}},
		{"name read", []string{"get", "pods", "-o", "name"}},
		{"watch json", []string{"get", "pods", "-o", "yaml", "-w"}},
		{"watch long json", []string{"get", "pods", "-o", "json", "--watch"}},
		{"describe", []string{"describe", "pod", "web"}},
		{"logs", []string{"logs", "web"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, code := runRedactGuard(t, "redact_output: structured\n", 0, tc.args...)
			if code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if !strings.Contains(stdout, sentinelSecretB64) {
				t.Errorf("%v was redacted but must use the untouched passthrough:\n%s", tc.args, stdout)
			}
			if strings.Contains(stdout, "***REDACTED") {
				t.Errorf("%v took the redaction path but should not have:\n%s", tc.args, stdout)
			}
		})
	}
}

// TestRedactOutputJSONFormat: structured mode also handles -o json.
func TestRedactOutputJSONFormat(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	// Reuse the YAML fake but request -o json; the fake ignores -o and emits the
	// canned YAML, which is not valid JSON -> the redactor FAILS OPEN (passes it
	// through unredacted) rather than dropping the read. This exercises fail-open
	// end-to-end: the read is not lost.
	stdout, _, code := runRedactGuard(t, "redact_output: structured\n", 0, "get", "secret", "-o", "json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(stdout, sentinelSecretB64) {
		t.Errorf("fail-open should pass the unparseable (non-JSON) read through unredacted:\n%s", stdout)
	}
}

// TestRedactOutputConfigSubcommand: the `config redact-output` setter round-trips
// through the on-disk config and is shown by `config list`.
func TestRedactOutputConfigSubcommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	kubectlDir := writeSecretFakeKubectl(t, 0)
	env := []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}

	run := func(args ...string) (string, int) {
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		code := 0
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatalf("run %v: %v", args, err)
			}
		}
		return out.String(), code
	}

	if out, code := run("config", "redact-output", "structured"); code != 0 {
		t.Fatalf("set failed (%d): %s", code, out)
	}
	data, err := os.ReadFile(home + "/.kubectl-guard.yaml")
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	if !strings.Contains(string(data), "redact_output: structured") {
		t.Errorf("config missing redact_output: structured:\n%s", data)
	}
	if out, code := run("config", "list"); code != 0 || !strings.Contains(out, "Redact output: structured") {
		t.Errorf("config list should show redact output structured (code %d):\n%s", code, out)
	}
	if out, code := run("config", "redact-output", "bogus"); code == 0 {
		t.Errorf("invalid mode should fail, got success:\n%s", out)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// buildGuardBin builds the guard binary into a temp dir and returns its path.
func buildGuardBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "kubectl-guard-test")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

// writeFakeKubectl installs a fake `kubectl` on PATH that answers
// `config current-context` with a stable context and otherwise echoes its args
// to stdout. This makes Allow decisions and arg-forwarding deterministic
// without a real cluster.
func writeFakeKubectl(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "config" ] && [ "$2" = "current-context" ]; then
  echo "fake-context"
else
  echo "$@"
fi
`
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeConfig writes a kubectl-guard config YAML into home.
func writeConfig(t *testing.T, home, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(home, ".kubectl-guard.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeKubeconfig writes a valid kubeconfig to $home/.kube/config so the guard's
// clientcmd-based context/namespace resolution (issue #31) resolves without a
// real cluster. This is the NEW path: clientcmd reads this file directly, so the
// fake kubectl on PATH no longer answers `config current-context`/`config view`
// — it only handles COMMAND EXECUTION (get/delete/etc.).
//
// currentContext becomes the kubeconfig's current-context. The fixture always
// includes the contexts the subprocess tests reference via --context
// (fake-context, dev-cluster, prod-cluster) so explicit --context lookups
// resolve. nsByContext bakes a namespace into the named context — matching what
// `kubectl config view --minify` used to report for tier-2 namespace derivation;
// a context absent from the map carries no namespace (kubectl then defaults to
// "default").
func writeKubeconfig(t *testing.T, home, currentContext string, nsByContext map[string]string) {
	t.Helper()
	kubeDir := filepath.Join(home, ".kube")
	if err := os.MkdirAll(kubeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	names := []string{"fake-context", "dev-cluster", "prod-cluster"}
	if currentContext != "" {
		names = append(names, currentContext)
	}
	for name := range nsByContext {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("apiVersion: v1\n")
	b.WriteString("kind: Config\n")
	b.WriteString("current-context: " + currentContext + "\n")
	b.WriteString("clusters:\n")
	b.WriteString("- cluster:\n    server: https://127.0.0.1:6443\n  name: fake-cluster\n")
	b.WriteString("users:\n")
	b.WriteString("- name: fake-user\n  user: {}\n")
	b.WriteString("contexts:\n")
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		b.WriteString("- context:\n")
		b.WriteString("    cluster: fake-cluster\n")
		b.WriteString("    user: fake-user\n")
		if ns := nsByContext[name]; ns != "" {
			b.WriteString("    namespace: " + ns + "\n")
		}
		b.WriteString("  name: " + name + "\n")
	}

	if err := os.WriteFile(filepath.Join(kubeDir, "config"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// runGuardWithConfig builds the guard, installs a fake kubectl, writes the
// config into a temp HOME, and runs the guard with args. Returns stdout,
// stderr, and exit code.
func runGuardWithConfig(t *testing.T, cfgYAML string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	bin := buildGuardBin(t)
	home := t.TempDir()
	if cfgYAML != "" {
		writeConfig(t, home, cfgYAML)
	}
	writeKubeconfig(t, home, "fake-context", nil)
	kubectlDir := writeFakeKubectl(t)

	cmd := exec.Command(bin, args...)
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error running guard: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), code
}

// TestExitCodesJSON asserts each guard decision exits with the spec'd code and
// emits a structured JSON object on stderr when --json is set.
func TestExitCodesJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("blocked exits 2", func(t *testing.T) {
		stdout, stderr, code := runGuardWithConfig(t,
			"protected_resources:\n  - secret\n",
			"--json", "get", "secret")
		if code != 2 {
			t.Fatalf("exit code = %d, want 2", code)
		}
		if stdout != "" {
			t.Errorf("expected empty stdout in --json mode, got %q", stdout)
		}
		var jr map[string]string
		if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &jr); err != nil {
			t.Fatalf("stderr is not valid JSON: %v\n%s", err, stderr)
		}
		if jr["decision"] != "blocked" {
			t.Errorf("decision = %q, want blocked", jr["decision"])
		}
		if jr["resource"] != "secret" {
			t.Errorf("resource = %q, want secret", jr["resource"])
		}
	})

	t.Run("denied exits 3", func(t *testing.T) {
		// Corrupt config -> fail-closed Deny.
		home := t.TempDir()
		writeConfig(t, home, ":::not valid yaml:::[")
		bin := buildGuardBin(t)
		kubectlDir := writeFakeKubectl(t)

		cmd := exec.Command(bin, "--json", "get", "pods")
		cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
		var errBuf bytes.Buffer
		cmd.Stderr = &errBuf
		err := cmd.Run()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if code != 3 {
			t.Fatalf("exit code = %d, want 3", code)
		}
		var jr map[string]string
		if err := json.Unmarshal([]byte(strings.TrimSpace(errBuf.String())), &jr); err != nil {
			t.Fatalf("stderr is not valid JSON: %v\n%s", err, errBuf.String())
		}
		if jr["decision"] != "denied" {
			t.Errorf("decision = %q, want denied", jr["decision"])
		}
		if jr["reason"] == "" {
			t.Errorf("reason should describe the failure, got empty")
		}
	})

	t.Run("needs-confirmation exits 4 in json mode", func(t *testing.T) {
		// Explicit --context avoids needing a real cluster; prod-* is protected.
		stdout, stderr, code := runGuardWithConfig(t,
			"protected_contexts:\n  - prod-*\n",
			"--json", "--context=prod-cluster", "delete", "pod", "nginx")
		if code != 4 {
			t.Fatalf("exit code = %d, want 4", code)
		}
		if stdout != "" {
			t.Errorf("expected empty stdout in --json mode, got %q", stdout)
		}
		var jr map[string]string
		if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &jr); err != nil {
			t.Fatalf("stderr is not valid JSON: %v\n%s", err, stderr)
		}
		if jr["decision"] != "needs-confirmation" {
			t.Errorf("decision = %q, want needs-confirmation", jr["decision"])
		}
		if jr["context"] != "prod-cluster" {
			t.Errorf("context = %q, want prod-cluster", jr["context"])
		}
	})
}

// TestJSONAllowedClean asserts that an allowed command in --json mode produces
// no extra guard output: kubectl's stdout is clean and --json is not forwarded.
func TestJSONAllowedClean(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	// No protections -> Allow. Fake kubectl echoes the args it receives.
	stdout, stderr, code := runGuardWithConfig(t, "{}\n",
		"--json", "get", "pods")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if stderr != "" {
		t.Errorf("expected empty stderr for allowed command, got %q", stderr)
	}
	if strings.Contains(stdout, "--json") {
		t.Errorf("--json was forwarded to kubectl: %q", stdout)
	}
	if strings.TrimSpace(stdout) != "get pods" {
		t.Errorf("kubectl received unexpected args: %q", stdout)
	}
}

// TestHumanModeUnchanged asserts that without --json the human-facing
// experience is preserved (warnings on stderr, no JSON) while the new exit
// codes still apply.
func TestHumanModeUnchanged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Run("blocked prints warning not JSON, exits 2", func(t *testing.T) {
		stdout, stderr, code := runGuardWithConfig(t,
			"protected_resources:\n  - secret\n",
			"get", "secret")
		if code != 2 {
			t.Fatalf("exit code = %d, want 2", code)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Errorf("expected a human-facing warning on stderr")
		}
		if strings.Contains(stderr, "\"decision\"") {
			t.Errorf("human mode must not emit JSON, got %q", stderr)
		}
		if stdout != "" {
			t.Errorf("expected empty stdout, got %q", stdout)
		}
	})
}

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

// runHeadless builds the guard, installs a fake kubectl on PATH, uses a temp
// HOME with NO config file, and runs the guard with the given extra env and
// args. Returns stdout, stderr, exit code. A timeout guards against the
// interactive wizard ever blocking (a regression would hang and fail the test).
func runHeadless(t *testing.T, extraEnv []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	kubectlDir := writeFakeKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	env := []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	env = append(env, extraEnv...)
	cmd.Env = env
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("guard hung (interactive wizard likely launched): %v", ctx.Err())
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error running guard: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), code
}

// TestHeadlessEnvBootstrapWritesConfig verifies that with
// KUBECTL_GUARD_PROTECTED_CONTEXTS set and no config file, the first run writes
// the config from env and proceeds to run the command (no wizard, no hang).
func TestHeadlessEnvBootstrapWritesConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	kubectlDir := writeFakeKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "get", "pods")
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=" + kubectlDir + ":/usr/bin:/bin",
		"KUBECTL_GUARD_PROTECTED_CONTEXTS=prod-*,prod-cluster",
	}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() != 0 {
			t.Fatalf("exit code = %d, want 0. stderr=%s", ee.ExitCode(), errBuf.String())
		} else if !ok {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	data, rerr := os.ReadFile(filepath.Join(home, ".kubectl-guard.yaml"))
	if rerr != nil {
		t.Fatalf("config was not written from env: %v", rerr)
	}
	s := string(data)
	if !strings.Contains(s, "prod-*") || !strings.Contains(s, "prod-cluster") {
		t.Errorf("config missing env-provided contexts, got:\n%s", s)
	}
}

// TestNoPromptBootstrapEmptyMode asserts that --no-prompt with no config, no env
// config, and the opt-in KUBECTL_GUARD_BOOTSTRAP=empty writes an empty config,
// warns on stderr, and proceeds (no wizard). This was the pre-v0.5.0 default;
// #74 made it opt-in.
func TestNoPromptBootstrapEmptyMode(t *testing.T) {
	stdout, stderr, code := runHeadless(t,
		[]string{"KUBECTL_GUARD_BOOTSTRAP=empty"},
		"--no-prompt", "get", "pods")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "get pods") {
		t.Errorf("expected the command to be forwarded, got stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "empty config") {
		t.Errorf("expected an empty-config warning on stderr, got %q", stderr)
	}
}

// TestNoPromptEnvBootstrapEmptyMode asserts KUBECTL_GUARD_NO_PROMPT behaves like
// the flag, under the opt-in empty bootstrap mode.
func TestNoPromptEnvBootstrapEmptyMode(t *testing.T) {
	stdout, stderr, code := runHeadless(t,
		[]string{"KUBECTL_GUARD_NO_PROMPT=yes", "KUBECTL_GUARD_BOOTSTRAP=empty"},
		"get", "pods")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "get pods") {
		t.Errorf("expected the command to be forwarded, got stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "empty config") {
		t.Errorf("expected an empty-config warning on stderr, got %q", stderr)
	}
}

// TestConfigInitCommand asserts `config init` writes the config non-interactively.
func TestConfigInitCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "config", "init",
		"--protected-contexts", "prod-*,prod-cluster",
		"--protected-resources", "secret",
		"--confirm-mode", "type-name")
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("config init failed (exit %d): stderr=%s", ee.ExitCode(), errBuf.String())
		} else {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	data, rerr := os.ReadFile(filepath.Join(home, ".kubectl-guard.yaml"))
	if rerr != nil {
		t.Fatalf("config was not written by `config init`: %v", rerr)
	}
	s := string(data)
	for _, want := range []string{"prod-*", "prod-cluster", "secret", "type-name"} {
		if !strings.Contains(s, want) {
			t.Errorf("config missing %q, got:\n%s", want, s)
		}
	}
}

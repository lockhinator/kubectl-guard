package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runBootstrap runs the guard against a temp HOME with NO config file, so the
// SetupRequired branch is exercised. It returns stdout, stderr, exit code, and
// whether a config file ended up on disk — the last being the whole point of
// #74: a deny bootstrap must not persist an unprotected config.
func runBootstrap(t *testing.T, extraEnv []string, args ...string) (stdout, stderr string, code int, configWritten bool) {
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
	cmd.Env = append([]string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}, extraEnv...)
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
	if _, serr := os.Stat(filepath.Join(home, ".kubectl-guard.yaml")); serr == nil {
		configWritten = true
	}
	return outBuf.String(), errBuf.String(), code, configWritten
}

// TestBootstrapDenyRefusesStateAltering is the headline #74 criterion: with no
// config and --no-prompt, a state-altering command is refused with an
// actionable message, and NO unprotected config is written.
func TestBootstrapDenyRefusesStateAltering(t *testing.T) {
	stdout, stderr, code, configWritten := runBootstrap(t, nil,
		"--no-prompt", "delete", "pod", "nginx")

	if code != 3 {
		t.Fatalf("exit code = %d, want 3 (denied): stderr=%s", code, stderr)
	}
	if configWritten {
		t.Error("deny bootstrap must NOT persist a config file")
	}
	if strings.Contains(stdout, "delete") {
		t.Errorf("the command must not reach kubectl, got stdout=%q", stdout)
	}
	// The message must tell the operator how to fix it.
	for _, want := range []string{"config init", "KUBECTL_GUARD_BOOTSTRAP"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("message should mention %q, got:\n%s", want, stderr)
		}
	}
}

// TestBootstrapDenyIsTheDefault: deny applies with no KUBECTL_GUARD_BOOTSTRAP
// set at all. This is the behavior change — before #74 this wrote an empty
// config and ran the command.
func TestBootstrapDenyIsTheDefault(t *testing.T) {
	_, _, code, configWritten := runBootstrap(t,
		[]string{"KUBECTL_GUARD_NO_PROMPT=yes"},
		"apply", "-f", "deploy.yaml")

	if code != 3 {
		t.Fatalf("exit code = %d, want 3 (deny is the default)", code)
	}
	if configWritten {
		t.Error("default bootstrap must NOT persist a config file")
	}
}

// TestBootstrapDenyAllowsReads: reads are harmless without a config, so they
// pass through — but still write no config.
func TestBootstrapDenyAllowsReads(t *testing.T) {
	stdout, stderr, code, configWritten := runBootstrap(t, nil,
		"--no-prompt", "get", "pods")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (reads pass under deny): stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "get pods") {
		t.Errorf("expected the read to be forwarded, got stdout=%q", stdout)
	}
	if configWritten {
		t.Error("deny bootstrap must NOT persist a config file, even for reads")
	}
	if !strings.Contains(stderr, "unprotected") {
		t.Errorf("expected an unprotected-run warning, got %q", stderr)
	}
}

// TestBootstrapDenyGatesAccessVerbs: port-forward/proxy are gated verbs (#71),
// so deny must refuse them too — they are the reason "reads pass" is safe.
func TestBootstrapDenyGatesAccessVerbs(t *testing.T) {
	for _, args := range [][]string{
		{"--no-prompt", "port-forward", "svc/prod-db", "5432:5432"},
		{"--no-prompt", "proxy"},
		{"--no-prompt", "exec", "nginx", "--", "sh"},
	} {
		_, _, code, configWritten := runBootstrap(t, nil, args...)
		if code != 3 {
			t.Errorf("%v: exit code = %d, want 3 (denied)", args, code)
		}
		if configWritten {
			t.Errorf("%v: must not persist a config file", args)
		}
	}
}

// TestBootstrapDenyRefusesUnrecognizedMutatingVerbs is the fail-closed
// guarantee for verbs outside the classification map. `certificate approve`
// issues a credential; a classifier gap must not let it run unprotected.
func TestBootstrapDenyRefusesUnrecognizedMutatingVerbs(t *testing.T) {
	for _, args := range [][]string{
		{"--no-prompt", "certificate", "approve", "my-csr"},
		{"--no-prompt", "certificate", "deny", "my-csr"},
		// A verb the guard does not know at all must also fail closed, not be
		// treated as a read and forwarded.
		{"--no-prompt", "some-future-mutating-verb", "prod"},
	} {
		stdout, _, code, configWritten := runBootstrap(t, nil, args...)
		if code != 3 {
			t.Errorf("%v: exit code = %d, want 3 (denied, fail closed)", args, code)
		}
		if configWritten {
			t.Errorf("%v: must not persist a config file", args)
		}
		if strings.Contains(stdout, "approve") || strings.Contains(stdout, "some-future") {
			t.Errorf("%v: command must not reach kubectl, got stdout=%q", args, stdout)
		}
	}
}

// TestBootstrapPromptModeDoesNotHang: `prompt` overrides --no-prompt and
// launches the wizard. With no TTY it must fail fast (cancel), never run the
// command, and never write a config — not block. The 30s harness timeout is the
// backstop against a regression that hangs.
func TestBootstrapPromptModeDoesNotHang(t *testing.T) {
	stdout, stderr, code, configWritten := runBootstrap(t,
		[]string{"KUBECTL_GUARD_BOOTSTRAP=prompt"},
		"--no-prompt", "delete", "pod", "nginx")

	if configWritten {
		t.Error("prompt mode with no TTY must not write a config")
	}
	if strings.Contains(stdout, "delete") {
		t.Errorf("the command must not run, got stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "prompt") {
		t.Errorf("expected a message about the prompt override, got %q", stderr)
	}
	// Exit code is the wizard's (0 on cancel); the point is it terminated.
	_ = code
}

// TestBootstrapEmptyReproducesOldBehavior: `empty` is the opt-in escape hatch
// for intentionally-unprotected CI.
func TestBootstrapEmptyReproducesOldBehavior(t *testing.T) {
	stdout, stderr, code, configWritten := runBootstrap(t,
		[]string{"KUBECTL_GUARD_BOOTSTRAP=empty"},
		"--no-prompt", "delete", "pod", "nginx")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (empty mode proceeds): stderr=%s", code, stderr)
	}
	if !configWritten {
		t.Error("empty mode must write the empty config")
	}
	if !strings.Contains(stdout, "delete") {
		t.Errorf("expected the command to be forwarded, got stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "no protection") {
		t.Errorf("empty mode should warn loudly, got %q", stderr)
	}
}

// TestBootstrapInvalidValueFailsClosed: a typo must not silently produce an
// unprotected guard.
func TestBootstrapInvalidValueFailsClosed(t *testing.T) {
	_, stderr, code, configWritten := runBootstrap(t,
		[]string{"KUBECTL_GUARD_BOOTSTRAP=emtpy"}, // deliberate typo
		"--no-prompt", "delete", "pod", "nginx")

	if code != 3 {
		t.Fatalf("exit code = %d, want 3 (unrecognized mode fails closed)", code)
	}
	if configWritten {
		t.Error("an unrecognized bootstrap mode must NOT persist a config file")
	}
	if !strings.Contains(stderr, "Unrecognized") {
		t.Errorf("expected a warning about the unrecognized value, got %q", stderr)
	}
}

// TestBootstrapDenyJSONDecision: agents parse --json, so the deny must be
// machine-readable rather than only human text.
func TestBootstrapDenyJSONDecision(t *testing.T) {
	_, stderr, code, _ := runBootstrap(t, nil,
		"--json", "--no-prompt", "delete", "pod", "nginx")

	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	line := strings.TrimSpace(stderr)
	if i := strings.LastIndex(line, "\n"); i >= 0 {
		line = line[i+1:]
	}
	var jr struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
		Command  string `json:"command"`
	}
	if err := json.Unmarshal([]byte(line), &jr); err != nil {
		t.Fatalf("stderr is not a JSON decision object: %v\nstderr=%q", err, stderr)
	}
	if jr.Decision != "denied" {
		t.Errorf("decision = %q, want denied", jr.Decision)
	}
	if jr.Reason == "" {
		t.Error("expected a machine-readable reason")
	}
	if strings.Contains(jr.Command, "--json") || strings.Contains(jr.Command, "--no-prompt") {
		t.Errorf("guard-only flags leaked into the command string: %q", jr.Command)
	}
}

// TestBootstrapEnvConfigStillWins: KUBECTL_GUARD_PROTECTED_* config takes
// precedence over the bootstrap mode, so a configured agent is unaffected.
func TestBootstrapEnvConfigStillWins(t *testing.T) {
	_, stderr, code, configWritten := runBootstrap(t,
		[]string{"KUBECTL_GUARD_PROTECTED_CONTEXTS=prod-*"},
		"--no-prompt", "get", "pods")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0: stderr=%s", code, stderr)
	}
	if !configWritten {
		t.Error("env-var bootstrap should still write its config")
	}
}

// TestBootstrapEmptySaveFailureExitsNonZero: if writing the empty config fails,
// the guard must surface a non-zero exit, not a misleading success — the
// command did not run and nothing was written.
func TestBootstrapEmptySaveFailureExitsNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	kubectlDir := writeFakeKubectl(t)

	// A read-only HOME makes config.Save's temp-file create fail. Restore perms
	// afterward so t.TempDir cleanup can remove it.
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(home, 0o700) }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--no-prompt", "get", "pods")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin",
		"KUBECTL_GUARD_BOOTSTRAP=empty"}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("guard hung: %v", ctx.Err())
	}
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if code == 0 {
		t.Errorf("exit code = 0, want non-zero on config-save failure; stderr=%s", errBuf.String())
	}
	if strings.Contains(outBuf.String(), "get pods") {
		t.Errorf("the command must not run when config could not be written, got stdout=%q", outBuf.String())
	}
}

// TestBootstrapExistingConfigUnaffected: #74 only changes the no-config path.
func TestBootstrapExistingConfigUnaffected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\n")
	kubectlDir := writeFakeKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--context=dev-cluster", "delete", "pod", "nginx")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("exit code = %d, want 0 (existing config, unprotected context): stderr=%s", ee.ExitCode(), errBuf.String())
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(outBuf.String(), "delete") {
		t.Errorf("expected the command to be forwarded, got stdout=%q", outBuf.String())
	}
}

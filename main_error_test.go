package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestJSONRequested: --json counts only as a guard flag before the first "--".
func TestJSONRequested(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"--json", "get", "pods"}, true},
		{[]string{"--json=true", "get", "pods"}, true},   // = form, must mirror StripGuardFlags
		{[]string{"--json=false", "get", "pods"}, false}, // explicit off
		{[]string{"get", "pods"}, false},
		{[]string{"get", "pods", "--", "--json"}, false},      // after -- it's a kubectl arg
		{[]string{"get", "pods", "--", "--json=true"}, false}, // after -- too
		{[]string{"--json", "--", "x"}, true},
		{[]string{"delete", "--", "--json"}, false},
		{[]string{}, false},
	}
	for _, c := range cases {
		if got := jsonRequested(c.args); got != c.want {
			t.Errorf("jsonRequested(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

// captureStderr redirects os.Stderr for the duration of fn and returns what was
// written. Not parallel-safe (mutates a global); callers must not t.Parallel.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// TestReportErrorHumanAndJSON: the single sink emits a consistent human line, or
// a structured object when --json was requested. #38.
func TestReportErrorHumanAndJSON(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"kubectl-guard", "config", "list"}
	human := captureStderr(t, func() { reportError(errors.New("something broke")) })
	if !strings.Contains(human, "kubectl-guard: error: something broke") {
		t.Errorf("human error format wrong: %q", human)
	}
	if strings.Contains(human, "{") {
		t.Errorf("human mode should not emit JSON: %q", human)
	}

	os.Args = []string{"kubectl-guard", "--json", "get", "pods"}
	jsonOut := captureStderr(t, func() { reportError(errors.New("boom")) })
	var m map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonOut)), &m); err != nil {
		t.Fatalf("--json error is not valid JSON: %v (%q)", err, jsonOut)
	}
	if m["error"] != "boom" {
		t.Errorf("json error = %q, want boom", m["error"])
	}

	// nil error prints nothing.
	if got := captureStderr(t, func() { reportError(nil) }); got != "" {
		t.Errorf("reportError(nil) printed %q", got)
	}
}

// TestConfigErrorReportingConsistency drives the built binary: a RunE error
// prints the consistent format with NO usage dump; a flag-parse error adds
// usage. #38.
func TestConfigErrorReportingConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\n")

	run := func(args ...string) (stderr string, code int) {
		cmd := exec.Command(bin, args...)
		cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
		var errBuf bytes.Buffer
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatalf("run: %v", err)
			}
		}
		return errBuf.String(), code
	}

	// RunE error: consistent format, no usage dump.
	stderr, code := run("config", "context-mode", "bogus")
	if code == 0 {
		t.Errorf("invalid mode should exit non-zero")
	}
	if !strings.Contains(stderr, "kubectl-guard: error:") {
		t.Errorf("RunE error not in consistent format: %q", stderr)
	}
	if strings.Contains(stderr, "Usage:") || strings.Contains(stderr, "Available Commands:") {
		t.Errorf("RunE error should not dump usage: %q", stderr)
	}

	// Flag-parse error: usage IS shown (plus the consistent message).
	stderr, code = run("config", "add-context", "--bogusflag", "x")
	if code == 0 {
		t.Errorf("unknown flag should exit non-zero")
	}
	if !strings.Contains(stderr, "kubectl-guard: error:") {
		t.Errorf("flag error not in consistent format: %q", stderr)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("flag-parse error should show usage: %q", stderr)
	}
}

// TestJSONErrorEndToEnd: a --json invocation that errors emits a clean JSON
// object on stderr (no interleaved usage text), for both --json and --json=true.
// #38 (regression guard for the jsonRequested/StripGuardFlags parity fix).
func TestJSONErrorEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "{}\n")

	runErr := func(args ...string) string {
		cmd := exec.Command(bin, args...)
		cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
		var errBuf bytes.Buffer
		cmd.Stderr = &errBuf
		_ = cmd.Run()
		return strings.TrimSpace(errBuf.String())
	}

	for _, flag := range []string{"--json", "--json=true"} {
		// `explain <flag>` with no command returns a usage error → JSON object.
		out := runErr("explain", flag)
		var m map[string]string
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Errorf("explain %s error is not clean JSON: %v (%q)", flag, err, out)
			continue
		}
		if m["error"] == "" {
			t.Errorf("explain %s JSON error missing message: %q", flag, out)
		}
	}

	// A cobra FLAG-parse error under --json must emit ONLY the JSON object — the
	// human usage text is suppressed so an agent parsing stderr isn't polluted.
	// (explain's usage error above is a RunE string; this exercises the distinct
	// guardFlagErrorFunc path.)
	flagOut := runErr("config", "add-context", "--json", "foo")
	if strings.Contains(flagOut, "Usage:") || strings.Contains(flagOut, "Flags:") {
		t.Errorf("flag-parse error under --json leaked usage text: %q", flagOut)
	}
	var fm map[string]string
	if err := json.Unmarshal([]byte(flagOut), &fm); err != nil {
		t.Errorf("flag-parse error under --json is not clean JSON: %v (%q)", err, flagOut)
	}
}

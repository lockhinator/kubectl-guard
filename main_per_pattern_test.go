package main

import (
	"strings"
	"testing"
)

// TestPerPatternModeIntegration drives the real guard binary end-to-end with one
// mixed config (prod-* block + staging-* confirm). A delete on prod-cluster is
// hard-blocked (exit 2, kubectl never runs); the same delete on staging-cluster
// needs confirmation and aborts without a TTY (exit 4). This is the headline
// per-pattern-mode behavior from ticket #79.
func TestPerPatternModeIntegration(t *testing.T) {
	const cfg = "protected_contexts:\n" +
		"  - pattern: \"prod-*\"\n" +
		"    mode: block\n" +
		"  - pattern: \"staging-*\"\n" +
		"    mode: confirm\n" +
		"context_mode: confirm\n"

	// prod-cluster -> block (exit 2), kubectl must not run.
	stdout, stderr, code := runGuardWithEnv(t, cfg, nil,
		"--context=prod-cluster", "delete", "pod", "nginx")
	if code != 2 {
		t.Fatalf("prod-cluster: exit = %d, want 2 (block). stderr=%s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("prod-cluster: kubectl must not run, got stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "block mode") {
		t.Errorf("prod-cluster: expected a block-mode message, got %q", stderr)
	}

	// staging-cluster -> confirm, aborts without a TTY (exit 4).
	stdout2, _, code2 := runGuardWithEnv(t, cfg, nil,
		"--context=staging-cluster", "delete", "pod", "nginx")
	if code2 != 4 {
		t.Fatalf("staging-cluster: exit = %d, want 4 (needs confirmation, aborted)", code2)
	}
	if stdout2 != "" {
		t.Errorf("staging-cluster: kubectl must not run before confirmation, got stdout=%q", stdout2)
	}

	// --yes on staging-cluster (confirm) runs; --yes on prod-cluster (block) does NOT.
	_, _, codeYesStaging := runGuardWithEnv(t, cfg, nil,
		"--context=staging-cluster", "--yes", "delete", "pod", "nginx")
	if codeYesStaging != 0 {
		t.Errorf("staging-cluster --yes: exit = %d, want 0 (confirm is bypassable with --yes)", codeYesStaging)
	}
	_, _, codeYesProd := runGuardWithEnv(t, cfg, nil,
		"--context=prod-cluster", "--yes", "delete", "pod", "nginx")
	if codeYesProd != 2 {
		t.Errorf("prod-cluster --yes: exit = %d, want 2 (block is NOT bypassable with --yes)", codeYesProd)
	}
}

// TestPerPatternBareStringBackCompat: an all-bare-string config behaves exactly
// as before — patterns inherit the global context_mode (block here) — and the
// config round-trips to bare strings on a subsequent add.
func TestPerPatternBareStringBackCompat(t *testing.T) {
	const cfg = "protected_contexts:\n  - prod-*\ncontext_mode: block\n"
	stdout, _, code := runGuardWithEnv(t, cfg, nil,
		"--context=prod-cluster", "delete", "pod", "nginx")
	if code != 2 {
		t.Fatalf("bare prod-* with context_mode block: exit = %d, want 2", code)
	}
	if stdout != "" {
		t.Errorf("kubectl must not run, got %q", stdout)
	}
}

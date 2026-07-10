package guard

import "testing"

// TestReadOnlyBlocksStateAltering: with read_only set, state-altering commands
// are Blocked while reads and genuine dry-runs pass. #94.
func TestReadOnlyBlocksStateAltering(t *testing.T) {
	cleanup := writeRawConfig(t, "read_only: true\n")
	defer cleanup()

	if res, _, _, _ := checkWith([]string{"delete", "pod", "x"}, staticContext("dev")); res != Blocked {
		t.Errorf("delete under read_only = %v, want Blocked", res)
	}
	if res, _, _, _ := checkWith([]string{"get", "pods"}, staticContext("dev")); res != Allow {
		t.Errorf("get (read) under read_only = %v, want Allow", res)
	}
	// Native diagnostic reads must stay available during an incident.
	if res, _, _, _ := checkWith([]string{"events"}, staticContext("dev")); res != Allow {
		t.Errorf("events (native read) under read_only = %v, want Allow", res)
	}
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x", "--dry-run=client"}, staticContext("dev")); res != Allow {
		t.Errorf("dry-run delete under read_only = %v, want Allow (changes nothing)", res)
	}

	// Fail-safe: an unknown/plugin verb the guard cannot classify is NOT a
	// known-safe read, so freeze BLOCKS it (a plugin could mutate). A --dry-run
	// token on it buys no pass.
	if res, _, _, _ := checkWith([]string{"node-shell", "node1"}, staticContext("dev")); res != Blocked {
		t.Errorf("unknown plugin verb under read_only = %v, want Blocked (fail-safe)", res)
	}
	if res, _, _, _ := checkWith([]string{"node-shell", "node1", "--dry-run=client"}, staticContext("dev")); res != Blocked {
		t.Errorf("unknown plugin verb + --dry-run under read_only = %v, want Blocked (no pass for unknown verbs)", res)
	}
}

// TestReadOnlyViaEnv: KUBECTL_GUARD_READONLY activates freeze per-invocation even
// with an empty config. #94.
func TestReadOnlyViaEnv(t *testing.T) {
	cleanup := writeRawConfig(t, "{}\n")
	defer cleanup()
	t.Setenv("KUBECTL_GUARD_READONLY", "1")

	if res, _, _, _ := checkWith([]string{"scale", "deploy", "x", "--replicas=3"}, staticContext("dev")); res != Blocked {
		t.Errorf("scale under KUBECTL_GUARD_READONLY = %v, want Blocked", res)
	}
	if res, _, _, _ := checkWith([]string{"get", "pods"}, staticContext("dev")); res != Allow {
		t.Errorf("get under env read-only = %v, want Allow", res)
	}
}

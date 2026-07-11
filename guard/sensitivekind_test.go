package guard

import "testing"

// TestSensitiveKindGatesMutations: state-altering commands on a sensitive kind
// are gated (confirm) on any context; reads pass; non-sensitive kinds pass; a
// genuine dry-run passes. #93.
func TestSensitiveKindGatesMutations(t *testing.T) {
	cleanup := writeRawConfig(t, "sensitive_kinds: [node, namespace]\nsensitive_kind_mode: confirm\n")
	defer cleanup()

	if res, _, _, _ := checkWith([]string{"delete", "node", "x"}, staticContext("dev")); res != RequireConfirmation {
		t.Errorf("delete node = %v, want RequireConfirmation", res)
	}
	if res, _, _, _ := checkWith([]string{"get", "node", "x"}, staticContext("dev")); res != Allow {
		t.Errorf("get node (read) = %v, want Allow", res)
	}
	// Short name ns normalizes to namespace.
	if res, _, _, _ := checkWith([]string{"delete", "ns", "foo"}, staticContext("dev")); res != RequireConfirmation {
		t.Errorf("delete ns = %v, want RequireConfirmation", res)
	}
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x"}, staticContext("dev")); res != Allow {
		t.Errorf("delete pod (non-sensitive kind) = %v, want Allow", res)
	}
	if res, _, _, _ := checkWith([]string{"delete", "node", "x", "--dry-run=client"}, staticContext("dev")); res != Allow {
		t.Errorf("dry-run delete node = %v, want Allow (changes nothing)", res)
	}
}

// TestSensitiveKindImplicitNodeVerbs: cordon/uncordon/drain address a node by
// bare name with no "node" token, so they must be matched against a sensitive
// "node" kind explicitly — otherwise the flagship node-maintenance mutations
// bypass the gate. #93 (security review).
func TestSensitiveKindImplicitNodeVerbs(t *testing.T) {
	cleanup := writeRawConfig(t, "sensitive_kinds: [node]\nsensitive_kind_mode: block\n")
	defer cleanup()
	for _, args := range [][]string{
		{"drain", "worker-1"},
		{"cordon", "worker-1"},
		{"uncordon", "worker-1"},
		{"drain", "-l", "role=worker"},
	} {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != Blocked {
			t.Errorf("%v under sensitive node block = %v, want Blocked (implicit node target)", args, res)
		}
	}
	// A node-verb must NOT gate when node is not a sensitive kind.
	cleanup2 := writeRawConfig(t, "sensitive_kinds: [namespace]\nsensitive_kind_mode: block\n")
	defer cleanup2()
	if res, _, _, _ := checkWith([]string{"drain", "worker-1"}, staticContext("dev")); res != Allow {
		t.Errorf("drain with node NOT sensitive = %v, want Allow", res)
	}
}

// TestSensitiveKindBlockMode: block hard-refuses mutations to the kind; reads
// still pass. #93.
func TestSensitiveKindBlockMode(t *testing.T) {
	cleanup := writeRawConfig(t, "sensitive_kinds: [node]\nsensitive_kind_mode: block\n")
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"delete", "node", "x"}, staticContext("dev")); res != Blocked {
		t.Errorf("delete node block mode = %v, want Blocked", res)
	}
	if res, _, _, _ := checkWith([]string{"get", "node", "x"}, staticContext("dev")); res != Allow {
		t.Errorf("get node block mode = %v, want Allow (reads pass)", res)
	}
}

// TestSensitiveKindOffDoesNothing: mode off leaves mutations ungated. #93.
func TestSensitiveKindOffDoesNothing(t *testing.T) {
	cleanup := writeRawConfig(t, "sensitive_kinds: [node]\nsensitive_kind_mode: off\n")
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"delete", "node", "x"}, staticContext("dev")); res != Allow {
		t.Errorf("delete node with mode off = %v, want Allow", res)
	}
}

// TestSensitiveKindResistsSafeOverride: a command_overrides.safe downgrade of the
// verb must NOT bypass a sensitive-kind BLOCK (block is un-bypassable). #93.
func TestSensitiveKindResistsSafeOverride(t *testing.T) {
	cleanup := writeRawConfig(t, "sensitive_kinds: [node]\nsensitive_kind_mode: block\ncommand_overrides:\n  safe: [delete]\n")
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"delete", "node", "x"}, staticContext("dev")); res != Blocked {
		t.Errorf("delete node (delete marked safe) under sensitive-kind block = %v, want Blocked", res)
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSensitiveKindIntegration exercises #93 end to end via the built binary:
// mutations to a sensitive kind are gated (confirm) or Blocked, reads pass, the
// -f manifest kind is matched, --yes cannot override block, and block is audited.
func TestSensitiveKindIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Confirm mode: a mutation to node is gated; with no stdin the prompt declines
	// (exit 4). A read of node passes.
	if _, _, code, _ := runGuardBin(t, "sensitive_kinds: [node]\nsensitive_kind_mode: confirm\n", "delete", "node", "n1"); code != 4 {
		t.Errorf("delete node (confirm) exit %d, want 4 (declined)", code)
	}
	if _, _, code, _ := runGuardBin(t, "sensitive_kinds: [node]\nsensitive_kind_mode: confirm\n", "get", "node", "n1"); code != 0 {
		t.Errorf("get node (read) exit %d, want 0", code)
	}

	// Block mode: --yes cannot override; audited as sensitive-kind-block.
	_, _, code, audit := runGuardBin(t, "sensitive_kinds: [node]\nsensitive_kind_mode: block\naudit_mode: all\n", "--yes", "delete", "node", "n1")
	if code != 2 {
		t.Errorf("delete node --yes (block) exit %d, want 2 (no override)", code)
	}
	if !strings.Contains(audit, "sensitive-kind-block") {
		t.Errorf("audit missing sensitive-kind-block reason:\n%s", audit)
	}

	// Manifest kind: apply -f node.yaml (kind Node) is matched and Blocked.
	manifest := filepath.Join(t.TempDir(), "node.yaml")
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\nkind: Node\nmetadata:\n  name: n1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code, _ := runGuardBin(t, "sensitive_kinds: [node]\nsensitive_kind_mode: block\n", "apply", "-f", manifest); code != 2 {
		t.Errorf("apply -f node.yaml (manifest kind) exit %d, want 2 (blocked)", code)
	}
}

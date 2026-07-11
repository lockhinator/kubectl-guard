package config

import "testing"

// TestSensitiveKindConfig covers the config layer: mode default/validation,
// normalized matching (singular/plural/short-name), add/remove, and weakening
// classification. #93.
func TestSensitiveKindConfig(t *testing.T) {
	c := &Config{}
	if c.SensitiveKindMode() != SensitiveKindOff {
		t.Errorf("default mode = %q, want off", c.SensitiveKindMode())
	}
	if !c.AddSensitiveKind("node") {
		t.Fatal("AddSensitiveKind(node) returned false")
	}
	if c.AddSensitiveKind("nodes") {
		t.Error("adding 'nodes' should be a no-op (equivalent to 'node')")
	}
	for _, form := range []string{"node", "nodes", "no"} {
		if !c.IsSensitiveKind(form) {
			t.Errorf("IsSensitiveKind(%q) = false, want true (normalized)", form)
		}
	}
	if c.IsSensitiveKind("pod") {
		t.Error("pod should not be sensitive")
	}
	if !c.SetSensitiveKindMode(SensitiveKindBlock) || c.SensitiveKindMode() != SensitiveKindBlock {
		t.Error("SetSensitiveKindMode(block) failed")
	}
	if c.SetSensitiveKindMode("bogus") {
		t.Error("SetSensitiveKindMode should reject an invalid mode")
	}
	// Removal by an equivalent short name works.
	if !c.RemoveSensitiveKind("no") {
		t.Error("RemoveSensitiveKind(no) should remove the equivalent 'node'")
	}
	if c.HasSensitiveKinds() {
		t.Error("HasSensitiveKinds should be false after removal")
	}

	// Invalid mode is a validation problem (fail-closed).
	if len(([]string)((&Config{SensitiveKind: "bogus"}).Validate())) == 0 {
		t.Error("an invalid sensitive_kind_mode should be a Validate problem")
	}
}

// TestSensitiveKindWeakening: removing a sensitive kind or weakening its mode is
// a protection-weakening change. #93.
func TestSensitiveKindWeakening(t *testing.T) {
	oldC := &Config{SensitiveKinds: []string{"node"}, SensitiveKind: SensitiveKindBlock}
	// Removed kind.
	if w := WeakensProtection(oldC, &Config{SensitiveKind: SensitiveKindBlock}); len(w) == 0 {
		t.Error("removing a sensitive kind should be weakening")
	}
	// Weakened mode (block -> confirm).
	if w := WeakensProtection(oldC, &Config{SensitiveKinds: []string{"node"}, SensitiveKind: SensitiveKindConfirm}); len(w) == 0 {
		t.Error("block -> confirm should be weakening")
	}
}

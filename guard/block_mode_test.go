package guard

import (
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// TestContextBlockModeBlocks: with context_mode: block, a state-altering
// command on a protected context is hard-blocked (Blocked, not RequireConfirmation).
func TestContextBlockModeBlocks(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		ContextMode:       config.ContextModeBlock,
	})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"--context=prod-cluster", "delete", "pod", "nginx"}, staticContext("prod-cluster"))
	if res != Blocked {
		t.Errorf("result = %v, want Blocked (block mode)", res)
	}
}

// TestContextConfirmModeUnchanged: with context_mode: confirm (default), a
// state-altering command on a protected context still requires confirmation.
func TestContextConfirmModeUnchanged(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		ContextMode:       config.ContextModeConfirm,
	})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"--context=prod-cluster", "delete", "pod", "nginx"}, staticContext("prod-cluster"))
	if res != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation (confirm mode)", res)
	}
}

// TestContextBlockModeReadOnlyAllowed: block mode only affects state-altering
// commands; reads on a protected context still pass.
func TestContextBlockModeReadOnlyAllowed(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		ContextMode:       config.ContextModeBlock,
	})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"--context=prod-cluster", "get", "pods"}, staticContext("prod-cluster"))
	if res != Allow {
		t.Errorf("result = %v, want Allow (read-only)", res)
	}
}

// TestNamespaceBlockModeBlocks: namespace_mode: block hard-blocks state-altering
// commands on a protected namespace.
func TestNamespaceBlockModeBlocks(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedNamespaces: config.Patterns("kube-system"),
		NamespaceMode:       config.NamespaceModeBlock,
	})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"delete", "pod", "nginx", "-n", "kube-system"}, staticContext("dev"))
	if res != Blocked {
		t.Errorf("result = %v, want Blocked (namespace block mode)", res)
	}
}

// TestBlockWinsWhenEitherModeBlock: if context is confirm but namespace is
// block (or vice versa), block wins (most restrictive).
func TestBlockWinsWhenEitherModeBlock(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts:   config.Patterns("prod-*"),
		ContextMode:         config.ContextModeConfirm,
		ProtectedNamespaces: config.Patterns("kube-system"),
		NamespaceMode:       config.NamespaceModeBlock,
	})
	defer cleanup()
	// Protected context (confirm) AND protected namespace (block) -> block wins.
	res, _, _, _ := checkWith([]string{"--context=prod-cluster", "delete", "pod", "nginx", "-n", "kube-system"}, staticContext("prod-cluster"))
	if res != Blocked {
		t.Errorf("result = %v, want Blocked (block wins)", res)
	}
}

// TestBlockModeAppliesToAllNamespaces: -A on a block-mode namespace config blocks.
func TestBlockModeAppliesToAllNamespaces(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedNamespaces: config.Patterns("kube-system"),
		NamespaceMode:       config.NamespaceModeBlock,
	})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"delete", "pods", "--all-namespaces"}, staticContext("dev"))
	if res != Blocked {
		t.Errorf("result = %v, want Blocked", res)
	}
}

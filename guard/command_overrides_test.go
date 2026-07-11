package guard

import (
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// TestCommandOverrideStateAltering: a custom verb marked state_altering is gated
// on a protected context; without the override it passes (unknown verb).
func TestCommandOverrideStateAltering(t *testing.T) {
	cleanupOff := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	// Unknown custom verb with no override → not state-altering → passes.
	if res, _, _, _ := checkWith([]string{"my-plugin", "sync"}, staticContext("prod-1")); res != Allow {
		t.Errorf("custom verb with no override = %v, want Allow", res)
	}
	cleanupOff()

	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		CommandOverrides:  config.CommandOverrides{StateAltering: []string{"my-plugin"}},
	})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"my-plugin", "sync"}, staticContext("prod-1")); res != RequireConfirmation {
		t.Errorf("custom verb marked state_altering on protected context = %v, want RequireConfirmation", res)
	}
	// Unprotected context: not gated.
	if res, _, _, _ := checkWith([]string{"my-plugin", "sync"}, staticContext("dev")); res != Allow {
		t.Errorf("custom state_altering verb on unprotected context = %v, want Allow", res)
	}
}

// TestCommandOverrideUnsafeSafe: moving a default-safe verb (logs) to unsafe_safe
// makes it require confirmation on a protected context.
func TestCommandOverrideUnsafeSafe(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		CommandOverrides:  config.CommandOverrides{UnsafeSafe: []string{"logs"}},
	})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"logs", "mypod"}, staticContext("prod-1")); res != RequireConfirmation {
		t.Errorf("logs moved to unsafe_safe on protected context = %v, want RequireConfirmation", res)
	}
	// Without the override, logs is a safe read → passes.
	cleanup2 := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup2()
	if res, _, _, _ := checkWith([]string{"logs", "mypod"}, staticContext("prod-1")); res != Allow {
		t.Errorf("logs with no override on protected context = %v, want Allow (default safe)", res)
	}
}

// TestCommandOverrideSafeDowngrade: a built-in state-altering verb marked safe
// passes through (a deliberate, documented downgrade).
func TestCommandOverrideSafeDowngrade(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		CommandOverrides:  config.CommandOverrides{Safe: []string{"scale"}},
	})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"scale", "deploy/web", "--replicas=3"}, staticContext("prod-1")); res != Allow {
		t.Errorf("scale marked safe on protected context = %v, want Allow (downgrade)", res)
	}
}

// TestCommandOverrideSafeDoesNotBypassOrthogonalBlocks: a `safe` override
// downgrades the context/namespace axis, but must NOT turn off the orthogonal
// blast-radius / sensitive-access BLOCK policies — those compose most-restrictive
// and are un-bypassable in block mode.
func TestCommandOverrideSafeDoesNotBypassOrthogonalBlocks(t *testing.T) {
	// safe: [delete] + blast_radius: block — a single delete passes (downgrade),
	// but a wide `delete --all` is still Blocked by blast-radius.
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		BlastRadius:       config.BlastRadiusBlock,
		CommandOverrides:  config.CommandOverrides{Safe: []string{"delete"}},
	})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x"}, staticContext("prod-1")); res != Allow {
		t.Errorf("single delete marked safe = %v, want Allow (context axis downgraded)", res)
	}
	if res, _, _, _ := checkWith([]string{"delete", "pods", "--all"}, staticContext("prod-1")); res != Blocked {
		t.Errorf("wide `delete --all` marked safe under blast_radius:block = %v, want Blocked (orthogonal block not bypassable)", res)
	}

	// safe: [exec] + sensitive_access: block — exec is still Blocked.
	cleanup2 := withTempHome(t, &config.Config{
		SensitiveAccess:  config.SensitiveAccessBlock,
		CommandOverrides: config.CommandOverrides{Safe: []string{"exec"}},
	})
	defer cleanup2()
	if res, _, _, _ := checkWith([]string{"exec", "pod", "--", "sh"}, staticContext("dev")); res != Blocked {
		t.Errorf("exec marked safe under sensitive_access:block = %v, want Blocked", res)
	}
}

// TestCommandOverrideBuiltinsUnchanged: with no overrides, built-in classification
// is unchanged.
func TestCommandOverrideBuiltinsUnchanged(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x"}, staticContext("prod-1")); res != RequireConfirmation {
		t.Errorf("delete with no overrides = %v, want RequireConfirmation", res)
	}
	if res, _, _, _ := checkWith([]string{"get", "pods"}, staticContext("prod-1")); res != Allow {
		t.Errorf("get with no overrides = %v, want Allow", res)
	}
}

// TestIsStateAlteringWithOverride pins the classifier helpers directly, including
// the case-insensitive match and the safe/state-altering complementarity.
func TestIsStateAlteringWithOverride(t *testing.T) {
	cfg := &config.Config{CommandOverrides: config.CommandOverrides{
		StateAltering: []string{"My-Plugin"}, // mixed case
		Safe:          []string{"weird-read"},
	}}
	if !IsStateAlteringWith(cfg, []string{"my-plugin", "x"}) {
		t.Error("my-plugin should be state-altering (case-insensitive)")
	}
	if IsSafeCommandWith(cfg, []string{"my-plugin", "x"}) {
		t.Error("my-plugin must not be safe when marked state-altering")
	}
	if !IsSafeCommandWith(cfg, []string{"weird-read"}) {
		t.Error("weird-read should be safe")
	}
	if IsStateAlteringWith(cfg, []string{"weird-read"}) {
		t.Error("weird-read must not be state-altering when marked safe")
	}
	// nil cfg falls back to built-ins.
	if IsStateAlteringWith(nil, []string{"my-plugin"}) {
		t.Error("nil cfg: unknown verb is not state-altering")
	}
	if !IsStateAlteringWith(nil, []string{"delete", "pod"}) {
		t.Error("nil cfg: delete is state-altering (built-in)")
	}
}

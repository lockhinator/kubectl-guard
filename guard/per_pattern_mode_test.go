package guard

import (
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// TestPerPatternContextModeMixed: one config with prod-* block + staging-*
// confirm. delete on prod-cluster is Blocked; on staging-cluster it needs
// confirmation. context_mode (global) is confirm, so prod-*'s block comes purely
// from its per-pattern mode.
func TestPerPatternContextModeMixed(t *testing.T) {
	cfg := &config.Config{
		ProtectedContexts: []config.ProtectedPattern{
			{Pattern: "prod-*", Mode: config.ContextModeBlock},
			{Pattern: "staging-*", Mode: config.ContextModeConfirm},
		},
		ContextMode: config.ContextModeConfirm,
	}
	cleanup := withTempHome(t, cfg)
	defer cleanup()

	if res, _, _, _ := checkWith([]string{"--context=prod-cluster", "delete", "pod", "nginx"}, staticContext("prod-cluster")); res != Blocked {
		t.Errorf("prod-cluster: result = %v, want Blocked (per-pattern block)", res)
	}
	if res, _, _, _ := checkWith([]string{"--context=staging-cluster", "delete", "pod", "nginx"}, staticContext("staging-cluster")); res != RequireConfirmation {
		t.Errorf("staging-cluster: result = %v, want RequireConfirmation (per-pattern confirm)", res)
	}
}

// TestPerPatternInheritsGlobal: a bare pattern (no explicit mode) inherits the
// global context_mode. With context_mode: block, a bare prod-* blocks.
func TestPerPatternInheritsGlobal(t *testing.T) {
	cfg := &config.Config{
		ProtectedContexts: config.Patterns("prod-*"), // bare, inherit
		ContextMode:       config.ContextModeBlock,
	}
	cleanup := withTempHome(t, cfg)
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"--context=prod-cluster", "delete", "pod", "x"}, staticContext("prod-cluster")); res != Blocked {
		t.Errorf("bare pattern should inherit block, got %v", res)
	}
}

// TestPerPatternMostRestrictiveBothAxes: a context matches a CONFIRM pattern and
// the target namespace matches a BLOCK pattern -> block wins (most restrictive).
func TestPerPatternMostRestrictiveBothAxes(t *testing.T) {
	cfg := &config.Config{
		ProtectedContexts:   []config.ProtectedPattern{{Pattern: "prod-*", Mode: config.ContextModeConfirm}},
		ProtectedNamespaces: []config.ProtectedPattern{{Pattern: "kube-system", Mode: config.NamespaceModeBlock}},
		ContextMode:         config.ContextModeConfirm,
		NamespaceMode:       config.NamespaceModeConfirm,
	}
	cleanup := withTempHome(t, cfg)
	defer cleanup()
	res, _, _, _ := checkWith([]string{"--context=prod-cluster", "delete", "pod", "x", "-n", "kube-system"}, staticContext("prod-cluster"))
	if res != Blocked {
		t.Errorf("context confirm + namespace block should Block, got %v", res)
	}
}

// TestPerPatternNamespaceNameTargetBlock: a per-pattern BLOCK namespace reached by
// NAME (`delete namespace kube-system`) blocks even though the run-in namespace
// ("default") is unprotected and the global namespace_mode is confirm. This guards
// against a downgrade of a block pattern via the namespace-object route.
func TestPerPatternNamespaceNameTargetBlock(t *testing.T) {
	cfg := &config.Config{
		ProtectedNamespaces: []config.ProtectedPattern{{Pattern: "kube-system", Mode: config.NamespaceModeBlock}},
		NamespaceMode:       config.NamespaceModeConfirm,
	}
	cleanup := withTempHome(t, cfg)
	defer cleanup()
	res, _, _, _ := checkWith([]string{"delete", "namespace", "kube-system"}, staticContext("dev"))
	if res != Blocked {
		t.Errorf("delete namespace kube-system (block pattern) should Block, got %v", res)
	}
}

// TestPerPatternAllNamespacesBlock: --all-namespaces touches every namespace, so a
// single block namespace pattern blocks it even with global confirm.
func TestPerPatternAllNamespacesBlock(t *testing.T) {
	cfg := &config.Config{
		ProtectedNamespaces: []config.ProtectedPattern{
			{Pattern: "team-*", Mode: config.NamespaceModeConfirm},
			{Pattern: "kube-system", Mode: config.NamespaceModeBlock},
		},
		NamespaceMode: config.NamespaceModeConfirm,
	}
	cleanup := withTempHome(t, cfg)
	defer cleanup()
	res, _, _, _ := checkWith([]string{"delete", "pods", "--all-namespaces"}, staticContext("dev"))
	if res != Blocked {
		t.Errorf("--all-namespaces with a block namespace pattern should Block, got %v", res)
	}
}

// TestPerPatternConfirmPatternStaysConfirm: a confirm namespace pattern gates
// (does not block) even when another, non-matching pattern is block.
func TestPerPatternConfirmPatternStaysConfirm(t *testing.T) {
	cfg := &config.Config{
		ProtectedNamespaces: []config.ProtectedPattern{
			{Pattern: "team-*", Mode: config.NamespaceModeConfirm},
			{Pattern: "kube-system", Mode: config.NamespaceModeBlock},
		},
		NamespaceMode: config.NamespaceModeConfirm,
	}
	cleanup := withTempHome(t, cfg)
	defer cleanup()
	res, _, _, _ := checkWith([]string{"delete", "pod", "x", "-n", "team-a"}, staticContext("dev"))
	if res != RequireConfirmation {
		t.Errorf("team-a (confirm pattern) should RequireConfirmation, got %v", res)
	}
}

// TestPerPatternActorTightensOnTop: an actor policy still tightens a per-pattern
// confirm to block for a matching actor, on top of the per-pattern base.
func TestPerPatternActorTightensOnTop(t *testing.T) {
	cfg := &config.Config{
		ProtectedContexts: []config.ProtectedPattern{{Pattern: "prod-*", Mode: config.ContextModeConfirm}},
		ContextMode:       config.ContextModeConfirm,
		ActorPolicies:     []config.ActorPolicy{{Actor: "agent-ci", ContextMode: config.ContextModeBlock}},
	}
	cleanup := withTempHome(t, cfg)
	defer cleanup()

	t.Setenv("KUBECTL_GUARD_ACTOR", "agent-ci")
	if res, _, _, _ := checkWith([]string{"--context=prod-cluster", "delete", "pod", "x"}, staticContext("prod-cluster")); res != Blocked {
		t.Errorf("actor policy should tighten per-pattern confirm to block, got %v", res)
	}
	t.Setenv("KUBECTL_GUARD_ACTOR", "human-bob")
	if res, _, _, _ := checkWith([]string{"--context=prod-cluster", "delete", "pod", "x"}, staticContext("prod-cluster")); res != RequireConfirmation {
		t.Errorf("unmatched actor should keep per-pattern confirm, got %v", res)
	}
}

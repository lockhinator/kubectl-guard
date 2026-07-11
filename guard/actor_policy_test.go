package guard

import (
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// TestActorPolicyBlocksMatchedActor: an actor policy `claude-code → block` blocks
// that actor on a protected context (no prompt), while an unmatched actor follows
// the global mode (confirm).
func TestActorPolicyBlocksMatchedActor(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		ContextMode:       config.ContextModeConfirm,
		ActorPolicies: []config.ActorPolicy{
			{Actor: "claude-code", ContextMode: config.ContextModeBlock},
		},
	})
	defer cleanup()

	// Matched actor -> Blocked.
	t.Setenv(ActorEnvVar, "claude-code")
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x"}, staticContext("prod-1")); res != Blocked {
		t.Errorf("claude-code delete on protected context = %v, want Blocked", res)
	}
	// Reads are never gated, even for a block-mode actor.
	if res, _, _, _ := checkWith([]string{"get", "pods"}, staticContext("prod-1")); res != Allow {
		t.Errorf("claude-code read = %v, want Allow", res)
	}

	// Unmatched actor -> global confirm.
	t.Setenv(ActorEnvVar, "alice")
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x"}, staticContext("prod-1")); res != RequireConfirmation {
		t.Errorf("unmatched actor delete = %v, want RequireConfirmation (global mode)", res)
	}
}

// TestActorPolicyGlobMatch: a glob actor pattern (`ci-*`) matches.
func TestActorPolicyGlobMatch(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		ActorPolicies: []config.ActorPolicy{
			{Actor: "ci-*", ContextMode: config.ContextModeBlock},
		},
	})
	defer cleanup()
	t.Setenv(ActorEnvVar, "ci-deploy")
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x"}, staticContext("prod-1")); res != Blocked {
		t.Errorf("ci-deploy (glob ci-*) delete = %v, want Blocked", res)
	}
	t.Setenv(ActorEnvVar, "ci")
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x"}, staticContext("prod-1")); res != RequireConfirmation {
		t.Errorf("actor 'ci' should not match 'ci-*' = %v, want RequireConfirmation", res)
	}
}

// TestActorPolicyNamespaceMode: an actor policy can upgrade namespace_mode too.
func TestActorPolicyNamespaceMode(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedNamespaces: config.Patterns("kube-system"),
		NamespaceMode:       config.NamespaceModeConfirm,
		ActorPolicies: []config.ActorPolicy{
			{Actor: "claude-code", NamespaceMode: config.NamespaceModeBlock},
		},
	})
	defer cleanup()
	t.Setenv(ActorEnvVar, "claude-code")
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x", "-n", "kube-system"}, staticContext("dev")); res != Blocked {
		t.Errorf("claude-code delete in protected namespace = %v, want Blocked", res)
	}
	t.Setenv(ActorEnvVar, "alice")
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x", "-n", "kube-system"}, staticContext("dev")); res != RequireConfirmation {
		t.Errorf("unmatched actor in protected namespace = %v, want RequireConfirmation", res)
	}
}

// TestActorPolicyCannotWeaken: an actor policy may only tighten a mode. A global
// block stays block even when a matching policy sets confirm — a self-asserted
// actor must never relax protection below the global posture.
func TestActorPolicyCannotWeaken(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		ContextMode:       config.ContextModeBlock,
		ActorPolicies: []config.ActorPolicy{
			{Actor: "human-*", ContextMode: config.ContextModeConfirm},
		},
	})
	defer cleanup()
	t.Setenv(ActorEnvVar, "human-bob")
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x"}, staticContext("prod-1")); res != Blocked {
		t.Errorf("global block + actor confirm = %v, want Blocked (a policy cannot weaken)", res)
	}
}

// TestActorPolicyUnsetUnchanged: no actor policies -> unchanged global behavior.
func TestActorPolicyUnsetUnchanged(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		ContextMode:       config.ContextModeConfirm,
	})
	defer cleanup()
	t.Setenv(ActorEnvVar, "claude-code")
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x"}, staticContext("prod-1")); res != RequireConfirmation {
		t.Errorf("no actor policies = %v, want RequireConfirmation (global mode)", res)
	}
}

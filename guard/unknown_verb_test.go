package guard

import (
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// TestIsUnknownCommand: the tri-state classifier returns unknown only for a verb
// the guard cannot classify, honoring command_overrides.
func TestIsUnknownCommand(t *testing.T) {
	if !IsUnknownCommand(nil, []string{"my-plugin", "sync"}) {
		t.Error("a made-up verb should be unknown")
	}
	if IsUnknownCommand(nil, []string{"get", "pods"}) {
		t.Error("get is a known safe verb, not unknown")
	}
	if IsUnknownCommand(nil, []string{"delete", "pod", "x"}) {
		t.Error("delete is a known state-altering verb, not unknown")
	}
	if IsUnknownCommand(nil, nil) {
		t.Error("empty args (no verb) is not unknown")
	}
	// A command_override makes an otherwise-unknown verb known.
	cfg := &config.Config{CommandOverrides: config.CommandOverrides{StateAltering: []string{"my-plugin"}}}
	if IsUnknownCommand(cfg, []string{"my-plugin", "sync"}) {
		t.Error("a classified verb is no longer unknown")
	}
}

// TestUnknownVerbNotLaunderedByArgVerb is the regression for the confirmed
// bypass: a plugin verb whose ARGUMENTS contain a recognized read verb
// (`my-plugin get pods`) must NOT be laundered into "known-safe" by
// ExtractCommand's verb-shift fallback — the leading (invoked) verb is still
// unknown and must be gated/denied on a protected target.
func TestUnknownVerbNotLaunderedByArgVerb(t *testing.T) {
	// The classifier keys off the leading verb, not a later recognized token.
	for _, args := range [][]string{
		{"my-plugin", "get", "pods"},
		{"my-plugin", "version"},
		{"my-plugin", "--", "get", "pods"}, // even across the "--" separator
	} {
		if !IsUnknownCommand(nil, args) {
			t.Errorf("IsUnknownCommand(%v) = false, want true (leading verb is the plugin, not a later token)", args)
		}
	}
	// End-to-end: denied on a protected context.
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		UnknownVerb:       config.UnknownVerbDeny,
	})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"my-plugin", "get", "pods"}, staticContext("prod-1")); res != Deny {
		t.Errorf("`my-plugin get pods` on protected context, deny = %v, want Deny (not laundered by the get token)", res)
	}
	// A recognized verb with an unrecognized SUBcommand is NOT unknown (its leading
	// verb is recognized); it is gated as state-altering, not denied-as-unknown.
	if IsUnknownCommand(nil, []string{"config", "frobnicate"}) {
		t.Error("`config frobnicate` leading verb is recognized; not unknown")
	}
	if IsUnknownCommand(nil, []string{"rollout", "bogus"}) {
		t.Error("`rollout bogus` leading verb is recognized; not unknown")
	}
}

// TestUnknownVerbInClusterComposition pins the intended (by-design) composition
// of unknown_verb with in_cluster: unknown_verb rides the context/namespace
// protection axis, so `in_cluster: allow` (a documented full passthrough of that
// axis) lets an unknown verb through even under unknown_verb: deny — exactly as a
// known state-altering verb passes there — while `in_cluster: namespace` (the
// default) still gates it by the serviceaccount namespace. (sensitive_access and
// blast_radius are every-context axes and are NOT bypassed by in_cluster: allow;
// those are pinned in their own tests.)
func TestUnknownVerbInClusterComposition(t *testing.T) {
	// in_cluster: allow — unknown verb passes (allow opts out of the axis).
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"), // so the in-cluster branch is entered
		InCluster:         config.InClusterAllow,
		UnknownVerb:       config.UnknownVerbDeny,
	})
	res, _, _, _ := checkWithResolvers([]string{"my-plugin", "sync"},
		unresolvableContext, noContextNamespace, noShortNames, inClusterAs("kube-system"), noServerForContext)
	cleanup()
	if res != Allow {
		t.Errorf("unknown verb in-cluster under in_cluster=allow = %v, want Allow (allow opts out of the protected-target axis)", res)
	}

	// in_cluster: namespace (default) — unknown verb in a protected SA namespace
	// is still denied. protected_contexts must be set for the in-cluster branch to
	// be entered at all (the in-cluster policy is scoped to protected contexts,
	// per #83); the SA namespace is then the gating target.
	cleanup2 := withTempHome(t, &config.Config{
		ProtectedContexts:   config.Patterns("prod-*"),
		ProtectedNamespaces: config.Patterns("kube-system"),
		InCluster:           config.InClusterNamespace,
		UnknownVerb:         config.UnknownVerbDeny,
	})
	defer cleanup2()
	res, _, _, _ = checkWithResolvers([]string{"my-plugin", "sync"},
		unresolvableContext, noContextNamespace, noShortNames, inClusterAs("kube-system"), noServerForContext)
	if res != Deny {
		t.Errorf("unknown verb in-cluster (namespace mode) in a protected SA namespace = %v, want Deny", res)
	}
}

// TestUnknownVerbGate: with unknown_verb: gate, an unrecognized verb requires
// confirmation on a protected context but passes on an unprotected one.
func TestUnknownVerbGate(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		UnknownVerb:       config.UnknownVerbGate,
	})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"my-plugin", "sync"}, staticContext("prod-1")); res != RequireConfirmation {
		t.Errorf("unknown verb on protected context, gate = %v, want RequireConfirmation", res)
	}
	if res, _, _, _ := checkWith([]string{"my-plugin", "sync"}, staticContext("dev")); res != Allow {
		t.Errorf("unknown verb on UNPROTECTED context, gate = %v, want Allow", res)
	}
	// Known verbs are unaffected.
	if res, _, _, _ := checkWith([]string{"get", "pods"}, staticContext("prod-1")); res != Allow {
		t.Errorf("known read on protected context = %v, want Allow", res)
	}
}

// TestUnknownVerbDeny: with unknown_verb: deny, an unrecognized verb is refused
// on a protected context (fail-closed) but passes on an unprotected one.
func TestUnknownVerbDeny(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		UnknownVerb:       config.UnknownVerbDeny,
	})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"my-plugin", "sync"}, staticContext("prod-1")); res != Deny {
		t.Errorf("unknown verb on protected context, deny = %v, want Deny", res)
	}
	if res, _, _, _ := checkWith([]string{"my-plugin", "sync"}, staticContext("dev")); res != Allow {
		t.Errorf("unknown verb on UNPROTECTED context, deny = %v, want Allow", res)
	}
}

// TestUnknownVerbAllowUnchanged: the default (allow) passes unknown verbs even on
// protected contexts (backward compatible).
func TestUnknownVerbAllowUnchanged(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"my-plugin", "sync"}, staticContext("prod-1")); res != Allow {
		t.Errorf("unknown verb with default allow = %v, want Allow (unchanged)", res)
	}
}

// TestUnknownVerbGateNamespace: an unknown verb targeting a protected namespace
// (by -n) is gated even on an unprotected context.
func TestUnknownVerbGateNamespace(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedNamespaces: config.Patterns("kube-system"),
		UnknownVerb:         config.UnknownVerbDeny,
	})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"my-plugin", "sync", "-n", "kube-system"}, staticContext("dev")); res != Deny {
		t.Errorf("unknown verb targeting protected namespace, deny = %v, want Deny", res)
	}
	// A different namespace is not protected → passes.
	if res, _, _, _ := checkWith([]string{"my-plugin", "sync", "-n", "team-a"}, staticContext("dev")); res != Allow {
		t.Errorf("unknown verb in unprotected namespace = %v, want Allow", res)
	}
}

// TestUnknownVerbBlockModeContext: an unknown verb under gate on a protected
// context in BLOCK mode is Blocked (inherits the context mode).
func TestUnknownVerbBlockModeContext(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		ContextMode:       config.ContextModeBlock,
		UnknownVerb:       config.UnknownVerbGate,
	})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"my-plugin", "sync"}, staticContext("prod-1")); res != Blocked {
		t.Errorf("unknown verb, gate, on a block-mode protected context = %v, want Blocked", res)
	}
}

// TestUnknownVerbRespectsOverride: a verb classified via command_overrides is no
// longer unknown, so unknown_verb: deny does not apply to it.
func TestUnknownVerbRespectsOverride(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		UnknownVerb:       config.UnknownVerbDeny,
		CommandOverrides:  config.CommandOverrides{Safe: []string{"my-plugin"}},
	})
	defer cleanup()
	// Marked safe → known → passes (not denied as unknown).
	if res, _, _, _ := checkWith([]string{"my-plugin", "sync"}, staticContext("prod-1")); res != Allow {
		t.Errorf("override-safe verb under unknown_verb:deny = %v, want Allow (no longer unknown)", res)
	}
}

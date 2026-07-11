package guard

import (
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// TestSensitiveAccessGate: with sensitive_access: gate, the sensitive verbs are
// gated on an UNPROTECTED context, while read verbs pass.
func TestSensitiveAccessGate(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		SensitiveAccess:   config.SensitiveAccessGate,
	})
	defer cleanup()

	gated := [][]string{
		{"exec", "pod", "--", "cat", "/etc/passwd"},
		{"cp", "pod:/etc/secret", "./secret"},
		{"attach", "mypod"},
		{"port-forward", "pod", "8080:80"},
	}
	for _, args := range gated {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != RequireConfirmation {
			t.Errorf("%v on unprotected context = %v, want RequireConfirmation", args, res)
		}
	}
	// Read verbs are unaffected.
	for _, args := range [][]string{{"get", "pods"}, {"logs", "mypod"}, {"describe", "pod", "x"}} {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != Allow {
			t.Errorf("read %v = %v, want Allow (sensitive-access must not gate reads)", args, res)
		}
	}
}

// TestSensitiveAccessBlock: with sensitive_access: block, a sensitive verb is
// refused on any context, and --yes cannot bypass it.
func TestSensitiveAccessBlock(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{SensitiveAccess: config.SensitiveAccessBlock})
	defer cleanup()

	if res, _, _, _ := checkWith([]string{"exec", "pod", "--", "sh"}, staticContext("dev")); res != Blocked {
		t.Errorf("exec under sensitive_access: block = %v, want Blocked", res)
	}
	// Block is a distinct result from RequireConfirmation, so the main-loop --yes
	// auto-confirm (which only acts on RequireConfirmation) cannot bypass it.
}

// TestSensitiveAccessOffUnchanged: with the default (off), the sensitive verbs
// behave exactly as before — gated only on a protected context/namespace.
func TestSensitiveAccessOffUnchanged(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()

	// exec on an UNPROTECTED context passes (old behavior).
	if res, _, _, _ := checkWith([]string{"exec", "pod", "--", "sh"}, staticContext("dev")); res != Allow {
		t.Errorf("exec on unprotected context with sensitive_access off = %v, want Allow", res)
	}
	// exec on a PROTECTED context still gates (unchanged: exec is state-altering).
	if res, _, _, _ := checkWith([]string{"exec", "pod", "--", "sh"}, staticContext("prod-1")); res != RequireConfirmation {
		t.Errorf("exec on protected context = %v, want RequireConfirmation", res)
	}
}

// TestSensitiveAccessComposesMostRestrictive: sensitive-access composes with
// context protection; a block anywhere wins.
func TestSensitiveAccessComposesMostRestrictive(t *testing.T) {
	// sensitive gate + context block: the context block wins (Blocked).
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		ContextMode:       config.ContextModeBlock,
		SensitiveAccess:   config.SensitiveAccessGate,
	})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"exec", "pod", "--", "sh"}, staticContext("prod-1")); res != Blocked {
		t.Errorf("exec on a block-mode protected context = %v, want Blocked (context block wins)", res)
	}

	// sensitive block + unprotected context: sensitive block wins (Blocked).
	cleanup2 := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		SensitiveAccess:   config.SensitiveAccessBlock,
	})
	defer cleanup2()
	if res, _, _, _ := checkWith([]string{"exec", "pod", "--", "sh"}, staticContext("dev")); res != Blocked {
		t.Errorf("exec on unprotected context under sensitive block = %v, want Blocked", res)
	}
}

// TestSensitiveVerbsOverride: a custom sensitive_verbs list is honored, including
// marking an otherwise read-only verb (logs) sensitive.
func TestSensitiveVerbsOverride(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		SensitiveAccess: config.SensitiveAccessGate,
		SensitiveVerbs:  []string{"logs"},
	})
	defer cleanup()

	// logs is now sensitive -> gated even on an unprotected context.
	if res, _, _, _ := checkWith([]string{"logs", "mypod"}, staticContext("dev")); res != RequireConfirmation {
		t.Errorf("logs with sensitive_verbs=[logs] = %v, want RequireConfirmation", res)
	}
	// exec is NOT in the override -> not sensitive -> passes on unprotected.
	if res, _, _, _ := checkWith([]string{"exec", "pod", "--", "sh"}, staticContext("dev")); res != Allow {
		t.Errorf("exec not in sensitive_verbs override = %v, want Allow", res)
	}
}

// TestResourceProtectionStillBlocksUnderSensitive: resource protection is global
// and independent; it still blocks even when sensitive_access is off, and a
// sensitive verb targeting a protected resource is blocked as a resource, not
// merely gated.
func TestResourceProtectionUnaffectedBySensitive(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedResources: []string{"secret"},
		SensitiveAccess:    config.SensitiveAccessGate,
	})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"get", "secret", "x"}, staticContext("dev")); res != Blocked {
		t.Errorf("get secret = %v, want Blocked (resource protection unaffected)", res)
	}
}

// TestSensitiveAccessDebugAndProxyDefault: debug and proxy are in the DEFAULT
// sensitive set (a debug ephemeral container / node root shell reads secrets;
// proxy exposes the API server), so they gate on an unprotected context.
func TestSensitiveAccessDebugAndProxyDefault(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{SensitiveAccess: config.SensitiveAccessBlock})
	defer cleanup()
	for _, args := range [][]string{
		{"debug", "node/n1", "-it", "--image=busybox"},
		{"debug", "pod", "-it", "--image=busybox"},
		{"proxy"},
	} {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != Blocked {
			t.Errorf("%v under sensitive_access: block = %v, want Blocked", args, res)
		}
	}
}

// TestSensitiveAccessNotBypassedByDryRun is the regression for the confirmed
// dry-run bypass: a sensitive verb that supports --dry-run must STILL gate under
// sensitive_access, because a dry-run still reads/reaches (e.g.
// `create secret --dry-run=client -o yaml` echoes the secret with no cluster
// write).
func TestSensitiveAccessNotBypassedByDryRun(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		SensitiveAccess: config.SensitiveAccessBlock,
		SensitiveVerbs:  []string{"create"}, // create supports --dry-run
	})
	defer cleanup()

	// Without dry-run: blocked.
	if res, _, _, _ := checkWith([]string{"create", "pod", "x"}, staticContext("dev")); res != Blocked {
		t.Errorf("create (sensitive, block) = %v, want Blocked", res)
	}
	// WITH dry-run: must still be blocked (dry-run does not stop the read/reach).
	for _, args := range [][]string{
		{"create", "pod", "x", "--dry-run=client"},
		{"create", "pod", "x", "--dry-run=server"},
	} {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != Blocked {
			t.Errorf("%v = %v, want Blocked (dry-run must not bypass sensitive-access)", args, res)
		}
	}
	// A NON-sensitive verb still gets the dry-run skip on a protected context.
	cleanup2 := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		SensitiveAccess:   config.SensitiveAccessBlock,
		SensitiveVerbs:    []string{"create"},
	})
	defer cleanup2()
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x", "--dry-run=client"}, staticContext("prod-1")); res != Allow {
		t.Errorf("non-sensitive delete --dry-run on protected context = %v, want Allow (dry-run skip unaffected)", res)
	}
}

// TestSensitiveVerbsWhitespaceTolerant: a whitespace-padded sensitive_verbs entry
// still matches (it would otherwise pass validation but silently never match).
func TestSensitiveVerbsWhitespaceTolerant(t *testing.T) {
	cfg := &config.Config{SensitiveAccess: config.SensitiveAccessGate, SensitiveVerbs: []string{" exec ", "CP"}}
	if !cfg.IsSensitiveVerb("exec") {
		t.Error("a padded ' exec ' entry must still match exec")
	}
	if !cfg.IsSensitiveVerb("cp") {
		t.Error("case-insensitive: CP must match cp")
	}
}

// TestSensitiveAccessNotBypassedByInClusterAllow is the regression for the
// confirmed in-cluster fail-open: sensitive-access is orthogonal to context
// protection (it gates on what the verb can read/reach, not WHERE it runs), so
// `in_cluster: allow` must NOT let a sensitive verb through. A CI/operator pod
// using `exec`/`cp` to read Secrets is exactly the exfiltration path this control
// exists to stop.
func TestSensitiveAccessNotBypassedByInClusterAllow(t *testing.T) {
	// block: exec in-cluster under in_cluster=allow must still be Blocked.
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"), // so the in-cluster branch is entered
		InCluster:         config.InClusterAllow,
		SensitiveAccess:   config.SensitiveAccessBlock,
	})
	defer cleanup()
	res, _, _, _ := checkWithResolvers([]string{"exec", "pod", "--", "cat", "/etc/secret"},
		unresolvableContext, noContextNamespace, noShortNames, inClusterAs("team-a"))
	if res != Blocked {
		t.Errorf("exec in-cluster, in_cluster=allow, sensitive=block = %v, want Blocked", res)
	}

	// gate: same setup, gate mode -> RequireConfirmation, not Allow.
	cleanup2 := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		InCluster:         config.InClusterAllow,
		SensitiveAccess:   config.SensitiveAccessGate,
	})
	defer cleanup2()
	res, _, _, _ = checkWithResolvers([]string{"exec", "pod", "--", "sh"},
		unresolvableContext, noContextNamespace, noShortNames, inClusterAs("team-a"))
	if res != RequireConfirmation {
		t.Errorf("exec in-cluster, in_cluster=allow, sensitive=gate = %v, want RequireConfirmation", res)
	}

	// A NON-sensitive command still gets the in_cluster=allow blanket pass.
	cleanup3 := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		InCluster:         config.InClusterAllow,
		SensitiveAccess:   config.SensitiveAccessBlock,
	})
	defer cleanup3()
	res, _, _, _ = checkWithResolvers([]string{"delete", "pod", "x"},
		unresolvableContext, noContextNamespace, noShortNames, inClusterAs("team-a"))
	if res != Allow {
		t.Errorf("non-sensitive delete in-cluster, in_cluster=allow = %v, want Allow (blanket pass unaffected)", res)
	}
}

func TestIsSensitiveAccessHelper(t *testing.T) {
	off := &config.Config{}
	if IsSensitiveAccess(off, []string{"exec", "pod"}) {
		t.Error("sensitive_access off must report false")
	}
	on := &config.Config{SensitiveAccess: config.SensitiveAccessGate}
	if !IsSensitiveAccess(on, []string{"exec", "pod"}) {
		t.Error("exec under gate mode must report true")
	}
	if IsSensitiveAccess(on, []string{"get", "pods"}) {
		t.Error("get is not a sensitive verb")
	}
	if IsSensitiveAccess(nil, []string{"exec"}) {
		t.Error("nil config must report false")
	}
}

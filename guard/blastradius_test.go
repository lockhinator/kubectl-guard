package guard

import (
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// TestBlastRadiusClassifier checks the pure classifier: which commands are wide.
func TestBlastRadiusClassifier(t *testing.T) {
	wide := [][]string{
		{"delete", "pods", "--all"},
		{"delete", "pods", "-l", "app=nginx"},
		{"delete", "pods", "--selector", "app=nginx"},
		{"delete", "pods", "--field-selector", "status.phase=Running"},
		{"delete", "pods", "--all-namespaces", "--all"},
		{"delete", "pod", "x", "--force"},
		{"delete", "pod", "x", "--grace-period=0"},
		{"delete", "pod", "x", "--grace-period", "0"},
		{"apply", "--prune", "-f", "m.yaml"},
		{"apply", "--force", "-f", "m.yaml"},
		{"replace", "--force", "-f", "m.yaml"},
		{"label", "pods", "--all", "team=x"},
		{"annotate", "pods", "-l", "app=x", "k=v"},
		{"rollout", "restart", "deployment", "-l", "app=nginx"}, // mass restart
		{"rollout", "restart", "deployment", "--all"},
	}
	for _, args := range wide {
		if w, reason := BlastRadius(args); !w || reason == "" {
			t.Errorf("BlastRadius(%v) = (%v, %q), want wide with a reason", args, w, reason)
		}
	}

	notWide := [][]string{
		{"delete", "pod", "x"},                        // single object
		{"delete", "pod", "x", "--grace-period=30"},   // graceful, not force
		{"delete", "pod", "x", "--all=false"},         // explicitly not --all
		{"delete", "pod", "x", "--force=false"},       // explicitly not force
		{"get", "pods", "--all-namespaces"},           // read-only
		{"get", "pods", "--all"},                      // read-only
		{"describe", "pods", "-l", "app=x"},           // read-only
		{"apply", "-f", "m.yaml"},                     // ordinary apply
		{"apply", "-f", "m.yaml", "-l", "app=nginx"},  // -l NARROWS the apply (a subset), not a bulk delete
		{"apply", "-f", "m.yaml", "--selector=app=x"}, // same
		{"apply", "-f", "m.yaml", "--all"},            // --all here scopes the manifest, not live objects
		{"replace", "-f", "m.yaml"},                   // manifest replace of one object
		{"patch", "pods", "--all"},                    // patch takes no --all/-l (kubectl rejects); not a live fan-out
		{"exec", "pod", "--all"},                      // access verb, not a bulk mutation
		{"scale", "deploy/web", "--replicas=3"},       // single target, no wide flag
		{"rollout", "status", "deploy", "-l", "x=y"},  // read-only subcommand
		{"rollout", "history", "deploy"},              // read-only subcommand
		// expose/run: -l/--selector label the NEW object, they do not fan out over
		// existing objects, so a selector there is a single-object create.
		{"expose", "deployment", "nginx", "--port=80", "-l", "app=nginx"},
		{"expose", "deployment", "nginx", "--port=80", "--selector=app=nginx"},
		{"run", "web", "--image=nginx", "-l", "tier=frontend"},
	}
	for _, args := range notWide {
		if w, _ := BlastRadius(args); w {
			t.Errorf("BlastRadius(%v) = wide, want not wide", args)
		}
	}
}

// TestBlastRadiusGate: with blast_radius: gate, a wide mutation requires
// confirmation on an UNPROTECTED context; a single-object mutation and reads pass.
func TestBlastRadiusGate(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{BlastRadius: config.BlastRadiusGate})
	defer cleanup()

	for _, args := range [][]string{
		{"delete", "pods", "--all"},
		{"delete", "pods", "-l", "app=x"},
		{"apply", "--prune", "-f", "m.yaml"},
		{"delete", "pod", "x", "--force"},
	} {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != RequireConfirmation {
			t.Errorf("%v under blast_radius: gate = %v, want RequireConfirmation", args, res)
		}
	}
	// Single-object mutation and reads are unaffected.
	for _, args := range [][]string{{"delete", "pod", "x"}, {"get", "pods", "--all-namespaces"}} {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != Allow {
			t.Errorf("%v under blast_radius: gate = %v, want Allow", args, res)
		}
	}
}

// TestBlastRadiusBlock: with blast_radius: block, a wide mutation is refused on
// any context, and --yes cannot bypass it (Blocked is distinct from confirm).
func TestBlastRadiusBlock(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{BlastRadius: config.BlastRadiusBlock})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"delete", "pods", "--all"}, staticContext("dev")); res != Blocked {
		t.Errorf("delete --all under blast_radius: block = %v, want Blocked", res)
	}
}

// TestBlastRadiusOffUnchanged: with the default (off), a wide mutation behaves as
// before — gated only on a protected context, not on an unprotected one.
func TestBlastRadiusOffUnchanged(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"delete", "pods", "--all"}, staticContext("dev")); res != Allow {
		t.Errorf("delete --all on unprotected context with blast_radius off = %v, want Allow", res)
	}
	if res, _, _, _ := checkWith([]string{"delete", "pods", "--all"}, staticContext("prod-1")); res != RequireConfirmation {
		t.Errorf("delete --all on protected context = %v, want RequireConfirmation", res)
	}
}

// TestBlastRadiusNotGatedByDryRun: a genuine --dry-run of a wide mutation changes
// nothing, so it passes even under blast_radius: block (unlike sensitive-access).
func TestBlastRadiusNotGatedByDryRun(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{BlastRadius: config.BlastRadiusBlock})
	defer cleanup()
	for _, args := range [][]string{
		{"delete", "pods", "--all", "--dry-run=client"},
		{"apply", "--prune", "-f", "m.yaml", "--dry-run=server"},
	} {
		if res, _, _, _ := checkWith(args, staticContext("dev")); res != Allow {
			t.Errorf("%v = %v, want Allow (a dry-run wide mutation changes nothing)", args, res)
		}
	}
	// But a dry-run=none (a REAL mutation) still gates.
	if res, _, _, _ := checkWith([]string{"delete", "pods", "--all", "--dry-run=none"}, staticContext("dev")); res != Blocked {
		t.Errorf("delete --all --dry-run=none = %v, want Blocked (not a dry-run)", res)
	}
}

// TestBlastRadiusComposesMostRestrictive: blast-radius composes with context
// protection; a block anywhere wins.
func TestBlastRadiusComposesMostRestrictive(t *testing.T) {
	// blast gate + context block: context block wins (Blocked).
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: []string{"prod-*"},
		ContextMode:       config.ContextModeBlock,
		BlastRadius:       config.BlastRadiusGate,
	})
	defer cleanup()
	if res, _, _, _ := checkWith([]string{"delete", "pods", "--all"}, staticContext("prod-1")); res != Blocked {
		t.Errorf("delete --all on a block-mode protected context = %v, want Blocked", res)
	}

	// blast block + unprotected context: blast block wins (Blocked).
	cleanup2 := withTempHome(t, &config.Config{
		ProtectedContexts: []string{"prod-*"},
		BlastRadius:       config.BlastRadiusBlock,
	})
	defer cleanup2()
	if res, _, _, _ := checkWith([]string{"delete", "pods", "--all"}, staticContext("dev")); res != Blocked {
		t.Errorf("delete --all on unprotected context under blast block = %v, want Blocked", res)
	}
}

// TestBlastRadiusNotBypassedByInClusterAllow is the regression for the confirmed
// in-cluster fail-open: blast-radius is orthogonal to context protection (it
// gates on how much a command destroys, not WHERE it runs), so `in_cluster:
// allow` must NOT let a wide/bulk mutation through. A CI/operator pod firing
// `delete pods --all` is exactly the mass-destruction the policy exists to stop.
func TestBlastRadiusNotBypassedByInClusterAllow(t *testing.T) {
	// block: delete --all in-cluster under in_cluster=allow must still be Blocked.
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: []string{"prod-*"}, // so the in-cluster branch is entered
		InCluster:         config.InClusterAllow,
		BlastRadius:       config.BlastRadiusBlock,
	})
	defer cleanup()
	res, _, _, _ := checkWithResolvers([]string{"delete", "pods", "--all"},
		unresolvableContext, noContextNamespace, noShortNames, inClusterAs("team-a"))
	if res != Blocked {
		t.Errorf("delete --all in-cluster, in_cluster=allow, blast=block = %v, want Blocked", res)
	}

	// gate: same setup, gate mode -> RequireConfirmation, not Allow.
	cleanup2 := withTempHome(t, &config.Config{
		ProtectedContexts: []string{"prod-*"},
		InCluster:         config.InClusterAllow,
		BlastRadius:       config.BlastRadiusGate,
	})
	defer cleanup2()
	res, _, _, _ = checkWithResolvers([]string{"apply", "--prune", "-f", "m.yaml"},
		unresolvableContext, noContextNamespace, noShortNames, inClusterAs("team-a"))
	if res != RequireConfirmation {
		t.Errorf("apply --prune in-cluster, in_cluster=allow, blast=gate = %v, want RequireConfirmation", res)
	}

	// A NON-wide command still gets the in_cluster=allow blanket pass.
	cleanup3 := withTempHome(t, &config.Config{
		ProtectedContexts: []string{"prod-*"},
		InCluster:         config.InClusterAllow,
		BlastRadius:       config.BlastRadiusBlock,
	})
	defer cleanup3()
	res, _, _, _ = checkWithResolvers([]string{"delete", "pod", "x"},
		unresolvableContext, noContextNamespace, noShortNames, inClusterAs("team-a"))
	if res != Allow {
		t.Errorf("single-object delete in-cluster, in_cluster=allow = %v, want Allow (blanket pass unaffected)", res)
	}
}

// TestIsBlastRadiusActive covers the cfg-aware predicate used by messaging.
func TestIsBlastRadiusActive(t *testing.T) {
	off := &config.Config{}
	if IsBlastRadiusActive(off, []string{"delete", "pods", "--all"}) {
		t.Error("blast_radius off must report false")
	}
	on := &config.Config{BlastRadius: config.BlastRadiusGate}
	if !IsBlastRadiusActive(on, []string{"delete", "pods", "--all"}) {
		t.Error("delete --all under gate must report true")
	}
	if IsBlastRadiusActive(on, []string{"delete", "pod", "x"}) {
		t.Error("single-object delete is not wide")
	}
	if IsBlastRadiusActive(nil, []string{"delete", "pods", "--all"}) {
		t.Error("nil config must report false")
	}
}

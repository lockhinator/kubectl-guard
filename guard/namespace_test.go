package guard

import (
	"errors"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// --- ParseArgs namespace capture ---

func TestParseArgsNamespaceLong(t *testing.T) {
	p := ParseArgs([]string{"get", "pods", "--namespace", "kube-system"})
	if !p.HasNamespace || p.Namespace != "kube-system" {
		t.Errorf("namespace = %q (has=%v)", p.Namespace, p.HasNamespace)
	}
}

func TestParseArgsNamespaceInline(t *testing.T) {
	p := ParseArgs([]string{"get", "pods", "--namespace=kube-system"})
	if p.Namespace != "kube-system" {
		t.Errorf("namespace = %q", p.Namespace)
	}
}

func TestParseArgsNamespaceShort(t *testing.T) {
	p := ParseArgs([]string{"get", "pods", "-n", "kube-system"})
	if !p.HasNamespace || p.Namespace != "kube-system" {
		t.Errorf("namespace = %q (has=%v)", p.Namespace, p.HasNamespace)
	}
}

func TestParseArgsNamespaceShortAttached(t *testing.T) {
	p := ParseArgs([]string{"get", "pods", "-nkube-system"})
	if p.Namespace != "kube-system" {
		t.Errorf("namespace = %q", p.Namespace)
	}
}

func TestParseArgsAllNamespaces(t *testing.T) {
	p := ParseArgs([]string{"get", "pods", "--all-namespaces"})
	if !p.AllNamespaces {
		t.Error("AllNamespaces = false, want true")
	}
	p2 := ParseArgs([]string{"get", "pods", "-A"})
	if !p2.AllNamespaces {
		t.Error("-A did not set AllNamespaces")
	}
}

// TestParseArgsAllNamespacesFalse: --all-namespaces=false must NOT set
// AllNamespaces (matches kubectl); otherwise a scoped command would be gated as
// if it spanned every namespace, including protected ones.
func TestParseArgsAllNamespacesFalse(t *testing.T) {
	if ParseArgs([]string{"delete", "pods", "--all-namespaces=false"}).AllNamespaces {
		t.Error("--all-namespaces=false set AllNamespaces = true, want false")
	}
	if !ParseArgs([]string{"delete", "pods", "--all-namespaces=true"}).AllNamespaces {
		t.Error("--all-namespaces=true did not set AllNamespaces")
	}
}

// TestAllNamespacesFalseNotGated: --all-namespaces=false on a scoped delete must
// not be gated by namespace protection just because a namespace is protected.
func TestAllNamespacesFalseNotGated(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"delete", "pod", "x", "-n", "default", "--all-namespaces=false"}, staticContext("dev"))
	if res != Allow {
		t.Errorf("result = %v, want Allow (--all-namespaces=false, target ns unprotected)", res)
	}
}

func TestResolvedNamespaceDefault(t *testing.T) {
	p := ParseArgs([]string{"get", "pods"})
	if got := p.ResolvedNamespace(); got != "default" {
		t.Errorf("ResolvedNamespace = %q, want default", got)
	}
}

// --- checkWith namespace gating ---

// TestNamespaceGatedPrompts: state-altering command targeting a protected
// namespace requires confirmation, even on an unprotected context.
func TestNamespaceGatedPrompts(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"delete", "pod", "nginx", "-n", "kube-system"}, staticContext("dev"))
	if res != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation", res)
	}
}

// TestNamespaceUnprotectedPassesThrough: same command on an unprotected
// namespace is allowed.
func TestNamespaceUnprotectedPassesThrough(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"delete", "pod", "nginx", "-n", "default"}, staticContext("dev"))
	if res != Allow {
		t.Errorf("result = %v, want Allow", res)
	}
}

// TestNamespaceGlobMatch: protected namespace patterns use glob matching.
func TestNamespaceGlobMatch(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"prod-*"}})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"delete", "pod", "nginx", "-n", "prod-us-east-1"}, staticContext("dev"))
	if res != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation (glob match)", res)
	}
}

// TestAllNamespacesGated: --all-namespaces on a state-altering command gates
// when any namespace is protected (it spans protected namespaces).
func TestAllNamespacesGated(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"delete", "pods", "--all-namespaces"}, staticContext("dev"))
	if res != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation", res)
	}
}

// TestAllNamespacesNoProtection: with no protected namespaces, -A is allowed.
func TestAllNamespacesNoProtection(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"delete", "pods", "--all-namespaces"}, staticContext("dev"))
	if res != Allow {
		t.Errorf("result = %v, want Allow", res)
	}
}

// TestNamespaceAndContextCompose: namespace protection works even when context
// protection is also configured; either triggers gating.
func TestNamespaceAndContextCompose(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts:   []string{"prod-*"},
		ProtectedNamespaces: []string{"kube-system"},
	})
	defer cleanup()
	// Unprotected context, protected namespace -> gated by namespace.
	res, _, _, _ := checkWith([]string{"delete", "pod", "nginx", "-n", "kube-system"}, staticContext("dev"))
	if res != RequireConfirmation {
		t.Errorf("namespace-gated result = %v, want RequireConfirmation", res)
	}
	// Protected context, unprotected namespace -> gated by context.
	res2, _, _, _ := checkWith([]string{"delete", "pod", "nginx", "-n", "default"}, staticContext("prod-cluster"))
	if res2 != RequireConfirmation {
		t.Errorf("context-gated result = %v, want RequireConfirmation", res2)
	}
}

// TestNamespaceReadOnlyPasses: read-only commands on a protected namespace pass.
func TestNamespaceReadOnlyPasses(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"get", "pods", "-n", "kube-system"}, staticContext("dev"))
	if res != Allow {
		t.Errorf("result = %v, want Allow (read-only)", res)
	}
}

// --- tier-2: namespace baked into the resolved context (issue #19) ---

// fakeContextNamespace returns a NamespaceForContextFunc that always reports ns.
func fakeContextNamespace(ns string) NamespaceForContextFunc {
	return func(_, _ string) (string, error) { return ns, nil }
}

// TestNamespaceFromContextGated: with no -n flag, the namespace baked into the
// resolved context is consulted; a protected one gates the command.
func TestNamespaceFromContextGated(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()
	res, _, _, _ := checkWithResolvers(
		[]string{"delete", "pod", "nginx"},
		staticContext("dev"),
		fakeContextNamespace("kube-system"),
		noShortNames,
	)
	if res != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation (context namespace protected)", res)
	}
}

// TestNamespaceFromContextUnprotected: a context whose namespace is unprotected
// passes through.
func TestNamespaceFromContextUnprotected(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()
	res, _, _, _ := checkWithResolvers(
		[]string{"delete", "pod", "nginx"},
		staticContext("dev"),
		fakeContextNamespace("team-a"),
		noShortNames,
	)
	if res != Allow {
		t.Errorf("result = %v, want Allow (context namespace unprotected)", res)
	}
}

// TestNamespaceFlagOverridesContextNamespace: an explicit -n wins over the
// context's baked-in namespace (tier 1 beats tier 2).
func TestNamespaceFlagOverridesContextNamespace(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()
	// -n default overrides a context pinned to the protected kube-system.
	res, _, _, _ := checkWithResolvers(
		[]string{"delete", "pod", "nginx", "-n", "default"},
		staticContext("dev"),
		fakeContextNamespace("kube-system"),
		noShortNames,
	)
	if res != Allow {
		t.Errorf("result = %v, want Allow (-n default overrides context namespace)", res)
	}
	// -n kube-system gates even when the context namespace is unprotected.
	res2, _, _, _ := checkWithResolvers(
		[]string{"delete", "pod", "nginx", "-n", "kube-system"},
		staticContext("dev"),
		fakeContextNamespace("default"),
		noShortNames,
	)
	if res2 != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation (-n kube-system)", res2)
	}
}

// TestNamespaceFromContextBlockMode: block mode applies to a context-derived
// protected namespace, not just an explicit -n.
func TestNamespaceFromContextBlockMode(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedNamespaces: []string{"kube-system"},
		NamespaceMode:       config.NamespaceModeBlock,
	})
	defer cleanup()
	res, _, _, _ := checkWithResolvers(
		[]string{"delete", "pod", "nginx"},
		staticContext("dev"),
		fakeContextNamespace("kube-system"),
		noShortNames,
	)
	if res != Blocked {
		t.Errorf("result = %v, want Blocked (context namespace, block mode)", res)
	}
}

// TestNamespaceFromContextLookupErrorFallsBack: a lookup error falls back to
// "default" (best-effort) rather than failing closed on every command.
func TestNamespaceFromContextLookupErrorFallsBack(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()
	errResolver := func(_, _ string) (string, error) { return "", errors.New("kubectl not found") }
	res, _, _, _ := checkWithResolvers(
		[]string{"delete", "pod", "nginx"},
		staticContext("dev"),
		errResolver,
		noShortNames,
	)
	if res != Allow {
		t.Errorf("result = %v, want Allow (lookup error falls back to default, which is unprotected)", res)
	}
}

// TestNamespaceFromContextNotConsultedWithoutProtection: the context-namespace
// resolver is not invoked when no namespace protection is configured.
func TestNamespaceFromContextNotConsultedWithoutProtection(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
	defer cleanup()
	called := false
	spy := func(_, _ string) (string, error) { called = true; return "kube-system", nil }
	_, _, _, _ = checkWithResolvers(
		[]string{"delete", "pod", "nginx"},
		staticContext("dev"),
		spy,
		noShortNames,
	)
	if called {
		t.Error("context-namespace resolver was called with no namespace protection configured")
	}
}

// TestReadOnlyDoesNotResolveContextNamespace: a read-only command must NOT
// invoke the (shelling-out) context-namespace resolver, even when namespace
// protection is configured. Gating only applies to state-altering commands, so
// resolving the namespace for a "get"/"describe" is wasted work (a subprocess
// on the hot read path).
func TestReadOnlyDoesNotResolveContextNamespace(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: []string{"kube-system"}})
	defer cleanup()
	called := false
	spy := func(_, _ string) (string, error) { called = true; return "kube-system", nil }
	res, _, _, _ := checkWithResolvers([]string{"get", "pods"}, staticContext("dev"), spy, noShortNames)
	if called {
		t.Error("read-only 'get pods' invoked the context-namespace resolver")
	}
	if res != Allow {
		t.Errorf("res = %v, want Allow", res)
	}
}

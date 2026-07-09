package guard

import (
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
		ProtectedContexts:  []string{"prod-*"},
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

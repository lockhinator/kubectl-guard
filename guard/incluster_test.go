package guard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// TestDefaultInCluster exercises the real detection: KUBERNETES_SERVICE_HOST +
// the serviceaccount namespace file.
func TestDefaultInCluster(t *testing.T) {
	// Not in-cluster when the env var is unset.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, in := defaultInCluster(); in {
		t.Error("no KUBERNETES_SERVICE_HOST must report not-in-cluster")
	}

	// In-cluster with a readable namespace file.
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	nsFile := filepath.Join(t.TempDir(), "namespace")
	if err := os.WriteFile(nsFile, []byte("prod-app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := saNamespacePath
	saNamespacePath = nsFile
	defer func() { saNamespacePath = orig }()

	ns, in := defaultInCluster()
	if !in {
		t.Error("KUBERNETES_SERVICE_HOST set must report in-cluster")
	}
	if ns != "prod-app" {
		t.Errorf("SA namespace = %q, want prod-app (trimmed)", ns)
	}

	// KUBERNETES_SERVICE_HOST set but the namespace file is MISSING: not a genuine
	// pod (a spoofed env var, or a pod with the SA mount disabled). Must report
	// NOT in-cluster, so the caller fails closed rather than relaxes protection.
	saNamespacePath = filepath.Join(t.TempDir(), "does-not-exist")
	if ns, in := defaultInCluster(); in || ns != "" {
		t.Errorf("missing SA file with KSH set = (%q, %v), want (\"\", false)", ns, in)
	}
	// An empty namespace file is likewise not-in-cluster.
	emptyFile := filepath.Join(t.TempDir(), "namespace")
	if err := os.WriteFile(emptyFile, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saNamespacePath = emptyFile
	if _, in := defaultInCluster(); in {
		t.Error("empty SA namespace file must report not-in-cluster")
	}
}

// TestInClusterSpoofedEnvVarDoesNotDowngrade is the regression for the confirmed
// bypass: an out-of-cluster caller exporting KUBERNETES_SERVICE_HOST (with no SA
// namespace file present) must NOT enter the relaxed in-cluster policy. Using the
// real defaultInCluster, a missing SA file means not-in-cluster, so the guard
// stays on the fail-closed path.
func TestInClusterSpoofedEnvVarDoesNotDowngrade(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	orig := saNamespacePath
	saNamespacePath = filepath.Join(t.TempDir(), "no-such-file")
	defer func() { saNamespacePath = orig }()

	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: []string{"prod-*"},
		InCluster:         config.InClusterAllow, // even the most permissive policy must not apply
	})
	defer cleanup()

	// Use the REAL defaultInCluster (not the seam), so the spoofed env var is
	// evaluated as production would.
	res, _, _, _ := checkWithResolvers([]string{"delete", "pod", "x"}, unresolvableContext, noContextNamespace, noShortNames, defaultInCluster)
	if res != Deny {
		t.Errorf("spoofed KUBERNETES_SERVICE_HOST (no SA file) = %v, want Deny (must not enter in-cluster mode)", res)
	}
}

// unresolvableContext simulates in-cluster context resolution: there is no named
// current-context, so the lookup errors (as `kubectl config current-context`
// does in a pod).
func unresolvableContext(string) (string, error) {
	return "", errors.New("current-context is not set")
}

// inClusterAs returns an InClusterFunc reporting in-cluster with the given SA
// namespace.
func inClusterAs(ns string) InClusterFunc {
	return func() (string, bool) { return ns, true }
}

// checkInCluster runs the decision core with an unresolvable context and the
// given in-cluster resolver (which carries the serviceaccount namespace).
func checkInCluster(t *testing.T, args []string, inCluster InClusterFunc) Result {
	t.Helper()
	res, _, _, _ := checkWithResolvers(args, unresolvableContext, noContextNamespace, noShortNames, inCluster)
	return res
}

// TestInClusterNamespaceGates is the headline case: in-cluster with the default
// (namespace) policy, a state-altering command in a PROTECTED serviceaccount
// namespace is gated — not blanket-denied — even though the context is
// unresolvable and protected_contexts is configured.
func TestInClusterNamespaceGates(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts:   []string{"prod-*"}, // configured, but unevaluable in-cluster
		ProtectedNamespaces: []string{"kube-system"},
	})
	defer cleanup()

	// Pod runs in kube-system (protected): a state-altering command gates.
	if res := checkInCluster(t, []string{"delete", "pod", "nginx"}, inClusterAs("kube-system")); res != RequireConfirmation {
		t.Errorf("delete in protected SA namespace = %v, want RequireConfirmation", res)
	}
	// Pod runs in an unprotected namespace: passes through.
	if res := checkInCluster(t, []string{"delete", "pod", "nginx"}, inClusterAs("team-a")); res != Allow {
		t.Errorf("delete in unprotected SA namespace = %v, want Allow", res)
	}
	// An explicit -n overrides the SA namespace.
	if res := checkInCluster(t, []string{"delete", "pod", "nginx", "-n", "kube-system"}, inClusterAs("team-a")); res != RequireConfirmation {
		t.Errorf("-n kube-system in-cluster = %v, want RequireConfirmation", res)
	}
	if res := checkInCluster(t, []string{"delete", "pod", "nginx", "-n", "team-a"}, inClusterAs("team-a")); res != Allow {
		t.Errorf("-n team-a overriding a protected SA namespace = %v, want Allow", res)
	}
}

// TestInClusterNamespaceNoProtection: in-cluster with no namespace protection
// configured passes through (criterion: "in-cluster with no protection passes").
func TestInClusterNamespaceNoProtection(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
	defer cleanup()

	if res := checkInCluster(t, []string{"delete", "pod", "nginx"}, inClusterAs("kube-system")); res != Allow {
		t.Errorf("in-cluster with no namespace protection = %v, want Allow", res)
	}
}

// TestInClusterDeny reproduces the previous fail-closed behavior.
func TestInClusterDeny(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: []string{"prod-*"},
		InCluster:         config.InClusterDeny,
	})
	defer cleanup()

	// Even a read is denied under in_cluster: deny (matches the old blanket deny).
	if res := checkInCluster(t, []string{"get", "pods"}, inClusterAs("team-a")); res != Deny {
		t.Errorf("in_cluster=deny read = %v, want Deny", res)
	}
	if res := checkInCluster(t, []string{"delete", "pod", "x"}, inClusterAs("team-a")); res != Deny {
		t.Errorf("in_cluster=deny state-altering = %v, want Deny", res)
	}
}

// TestInClusterAllow passes commands through in-cluster with no gating — even a
// state-altering command in a PROTECTED serviceaccount namespace, which pins that
// "allow" is a full passthrough (namespace protection does NOT apply, unlike
// "namespace" mode).
func TestInClusterAllow(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts:   []string{"prod-*"},
		ProtectedNamespaces: []string{"kube-system"}, // protected, yet allow passes it
		InCluster:           config.InClusterAllow,
	})
	defer cleanup()

	if res := checkInCluster(t, []string{"delete", "pod", "x"}, inClusterAs("kube-system")); res != Allow {
		t.Errorf("in_cluster=allow in a protected SA namespace = %v, want Allow (full passthrough)", res)
	}
}

// TestOutOfClusterUnchanged: the fail-closed behavior for an unresolvable context
// is UNCHANGED when NOT in-cluster (criterion 4). notInCluster reports false, so
// the guard denies as before, regardless of the in_cluster policy.
func TestOutOfClusterUnchanged(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: []string{"prod-*"},
		InCluster:         config.InClusterAllow, // must NOT apply out-of-cluster
	})
	defer cleanup()

	if res := checkInCluster(t, []string{"delete", "pod", "x"}, notInCluster); res != Deny {
		t.Errorf("out-of-cluster unresolvable context = %v, want Deny (unchanged)", res)
	}
}

// TestInClusterBlockMode: namespace_mode: block hard-refuses in-cluster too.
func TestInClusterBlockMode(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts:   []string{"prod-*"},
		ProtectedNamespaces: []string{"kube-system"},
		NamespaceMode:       config.NamespaceModeBlock,
	})
	defer cleanup()

	if res := checkInCluster(t, []string{"delete", "pod", "x"}, inClusterAs("kube-system")); res != Blocked {
		t.Errorf("in-cluster protected SA namespace under block mode = %v, want Blocked", res)
	}
}

// TestInClusterResolvableContextUnaffected: if a context IS resolvable in-cluster
// (e.g. a mounted kubeconfig with a current-context), normal context protection
// applies and the in-cluster policy is not consulted.
func TestInClusterResolvableContextUnaffected(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
	defer cleanup()

	// staticContext resolves "prod-1" (protected) -> gate, regardless of in-cluster.
	res, _, _, _ := checkWithResolvers([]string{"delete", "pod", "x"}, staticContext("prod-1"), noContextNamespace, noShortNames, inClusterAs("kube-system"))
	if res != RequireConfirmation {
		t.Errorf("resolvable protected context in-cluster = %v, want RequireConfirmation", res)
	}
}

// TestInClusterEmptySANamespaceFailsClosed: if an InClusterFunc reports in-cluster
// but with an unknowable (empty) serviceaccount namespace, the guard cannot
// evaluate namespace protection, so it fails CLOSED. The production
// defaultInCluster never reports in-cluster with an empty namespace (it requires
// a readable SA namespace file), so this exercises the defensive guard in
// checkWithResolvers against any other InClusterFunc.
func TestInClusterEmptySANamespaceFailsClosed(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts:   []string{"prod-*"},
		ProtectedNamespaces: []string{"kube-system"},
	})
	defer cleanup()

	if res := checkInCluster(t, []string{"delete", "pod", "x"}, inClusterAs("")); res != Deny {
		t.Errorf("in-cluster with empty SA namespace = %v, want Deny (namespace unknowable, fail closed)", res)
	}
}

// TestClusterOverrideRefused pins the fix for the --cluster retarget bypass:
// --cluster overrides the API server independently of the context name, so
// `--context=dev --cluster=prod` would gate on the unprotected "dev" while hitting
// prod. It is refused whenever protected contexts are configured, like --server.
func TestClusterOverrideRefused(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
	defer cleanup()

	// Resolvable but unprotected context + --cluster retarget: must Deny.
	res, _, _, _ := checkWithResolvers([]string{"--cluster=prod-cluster", "delete", "pod", "x"}, staticContext("dev"), noContextNamespace, noShortNames, notInCluster)
	if res != Deny {
		t.Errorf("--cluster on an unprotected context = %v, want Deny", res)
	}
	// Separate-value form.
	res, _, _, _ = checkWithResolvers([]string{"--cluster", "prod-cluster", "delete", "pod", "x"}, staticContext("dev"), noContextNamespace, noShortNames, notInCluster)
	if res != Deny {
		t.Errorf("--cluster (separate value) = %v, want Deny", res)
	}
	// Without --cluster on the same unprotected context, it still passes.
	res, _, _, _ = checkWithResolvers([]string{"delete", "pod", "x"}, staticContext("dev"), noContextNamespace, noShortNames, notInCluster)
	if res != Allow {
		t.Errorf("no --cluster on unprotected context = %v, want Allow", res)
	}
}

// TestClusterOverrideNotDeniedWithoutProtectedContexts: --cluster is only refused
// when protected contexts are configured.
func TestClusterOverrideNotDeniedWithoutProtectedContexts(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedResources: []string{"secret"}})
	defer cleanup()
	res, _, _, _ := checkWithResolvers([]string{"--cluster=x", "get", "pods"}, staticContext("dev"), noContextNamespace, noShortNames, notInCluster)
	if res != Allow {
		t.Errorf("--cluster with no protected contexts = %v, want Allow", res)
	}
}

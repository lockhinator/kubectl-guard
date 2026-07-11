package guard

import (
	"errors"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// fakeServerFor builds a ServerForContextFunc that maps a context name to a
// server URL, so cluster-identity protection can be exercised without a real
// kubeconfig. An unmapped context resolves to "" (no server).
func fakeServerFor(byContext map[string]string) ServerForContextFunc {
	return func(_ /*kubeconfig*/, context string) (string, error) {
		if s, ok := byContext[context]; ok {
			return s, nil
		}
		return "", nil
	}
}

// fakeServerForKubeconfig keys on kubeconfig+context, modeling a crafted
// --kubeconfig that points an innocent-looking context at a protected server.
func fakeServerForKubeconfig(byKey map[string]string) ServerForContextFunc {
	return func(kubeconfig, context string) (string, error) {
		if s, ok := byKey[kubeconfig+"\x00"+context]; ok {
			return s, nil
		}
		return "", nil
	}
}

// TestClusterIdentityAliasedContextGated: an innocent-looking context NAME that
// is NOT in protected_contexts still gates a state-altering command when the
// resolved API server matches protected_clusters. A read still passes.
func TestClusterIdentityAliasedContextGated(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedClusters: []config.ProtectedCluster{{Server: "https://prod.eks.amazonaws.com"}},
	})
	defer cleanup()

	serverFor := fakeServerFor(map[string]string{"innocent": "https://prod.eks.amazonaws.com"})

	// State-altering on the aliased (server-protected) context: RequireConfirmation.
	res, _, _, _ := checkWithResolvers([]string{"delete", "pod", "x"},
		staticContext("innocent"), noContextNamespace, noShortNames, notInCluster, serverFor)
	if res != RequireConfirmation {
		t.Errorf("delete on aliased protected cluster = %v, want RequireConfirmation", res)
	}

	// A read passes (cluster protection gates state-altering, like context protection).
	res, _, _, _ = checkWithResolvers([]string{"get", "pods"},
		staticContext("innocent"), noContextNamespace, noShortNames, notInCluster, serverFor)
	if res != Allow {
		t.Errorf("read on aliased protected cluster = %v, want Allow", res)
	}
}

// TestClusterIdentityCraftedKubeconfig: a crafted --kubeconfig whose "dev"
// context resolves to the protected server is gated, keyed on kubeconfig+context.
func TestClusterIdentityCraftedKubeconfig(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedClusters: []config.ProtectedCluster{{ServerPattern: "*.prod.example.com"}},
	})
	defer cleanup()

	serverFor := fakeServerForKubeconfig(map[string]string{
		"/tmp/evil.kubeconfig\x00dev": "https://api.prod.example.com:443",
	})
	res, _, _, _ := checkWithResolvers(
		[]string{"--kubeconfig=/tmp/evil.kubeconfig", "--context=dev", "scale", "deploy/x", "--replicas=0"},
		staticContext("dev"), noContextNamespace, noShortNames, notInCluster, serverFor)
	if res != RequireConfirmation {
		t.Errorf("crafted --kubeconfig to protected server = %v, want RequireConfirmation", res)
	}
}

// TestClusterIdentityNameOnlyUnaffected: with NO protected_clusters, the server
// resolver is never consulted and behavior is byte-identical to before the
// feature (regression guard for the additive invariant).
func TestClusterIdentityNameOnlyUnaffected(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()

	called := false
	spy := ServerForContextFunc(func(_, _ string) (string, error) { called = true; return "https://prod", nil })

	// Unprotected name, no cluster protection: Allow, and the resolver is untouched.
	res, _, _, _ := checkWithResolvers([]string{"delete", "pod", "x"},
		staticContext("dev"), noContextNamespace, noShortNames, notInCluster, spy)
	if res != Allow {
		t.Errorf("unprotected name, no cluster protection = %v, want Allow", res)
	}
	if called {
		t.Error("server resolver was consulted with no protected_clusters configured")
	}

	// Name-protected context still gates exactly as before.
	res, _, _, _ = checkWithResolvers([]string{"delete", "pod", "x"},
		staticContext("prod-1"), noContextNamespace, noShortNames, notInCluster, spy)
	if res != RequireConfirmation {
		t.Errorf("name-protected context = %v, want RequireConfirmation", res)
	}
	if called {
		t.Error("server resolver was consulted with no protected_clusters configured (name path)")
	}
}

// TestClusterIdentityBlockMode: a server_pattern entry in block mode hard-blocks;
// confirm/inherit gates. Block is a distinct result from RequireConfirmation, so
// --yes (which only auto-confirms RequireConfirmation in main) cannot bypass it.
func TestClusterIdentityBlockMode(t *testing.T) {
	serverFor := fakeServerFor(map[string]string{"innocent": "https://api.prod.example.com"})

	// Per-entry block while the global context_mode is the default confirm.
	blockCleanup := withTempHome(t, &config.Config{
		ProtectedClusters: []config.ProtectedCluster{{ServerPattern: "*.prod.example.com", Mode: config.ContextModeBlock}},
	})
	res, _, _, _ := checkWithResolvers([]string{"delete", "pod", "x"},
		staticContext("innocent"), noContextNamespace, noShortNames, notInCluster, serverFor)
	blockCleanup()
	if res != Blocked {
		t.Errorf("cluster block mode = %v, want Blocked", res)
	}

	// Inherit (global confirm) → RequireConfirmation.
	confirmCleanup := withTempHome(t, &config.Config{
		ProtectedClusters: []config.ProtectedCluster{{ServerPattern: "*.prod.example.com"}},
	})
	res, _, _, _ = checkWithResolvers([]string{"delete", "pod", "x"},
		staticContext("innocent"), noContextNamespace, noShortNames, notInCluster, serverFor)
	confirmCleanup()
	if res != RequireConfirmation {
		t.Errorf("cluster confirm mode = %v, want RequireConfirmation", res)
	}

	// Global context_mode: block with an inherit entry also blocks.
	globalBlockCleanup := withTempHome(t, &config.Config{
		ContextMode:       config.ContextModeBlock,
		ProtectedClusters: []config.ProtectedCluster{{ServerPattern: "*.prod.example.com"}},
	})
	res, _, _, _ = checkWithResolvers([]string{"delete", "pod", "x"},
		staticContext("innocent"), noContextNamespace, noShortNames, notInCluster, serverFor)
	globalBlockCleanup()
	if res != Blocked {
		t.Errorf("global block mode with cluster match = %v, want Blocked", res)
	}

	// A per-entry mode: confirm on a CLUSTER-ONLY match (name NOT protected) must
	// survive a global context_mode: block — the entry's own confirm wins, so the
	// command needs confirmation, NOT a hard block. Regression: the name-derived
	// ctxMode falls back to the global block for an unprotected name, and folding
	// it into the cluster arm used to escalate this confirm entry to Blocked.
	confirmOverrideCleanup := withTempHome(t, &config.Config{
		ContextMode:       config.ContextModeBlock,
		ProtectedClusters: []config.ProtectedCluster{{ServerPattern: "*.prod.example.com", Mode: config.ContextModeConfirm}},
	})
	res, _, _, _ = checkWithResolvers([]string{"delete", "pod", "x"},
		staticContext("innocent"), noContextNamespace, noShortNames, notInCluster, serverFor)
	confirmOverrideCleanup()
	if res != RequireConfirmation {
		t.Errorf("cluster mode:confirm under global block = %v, want RequireConfirmation (entry confirm wins)", res)
	}
}

// TestClusterIdentityServerClusterDenied: --server and --cluster are refused when
// only protected_clusters is configured (no protected_contexts), matching the
// fail-closed parity the two overrides already have for protected contexts.
func TestClusterIdentityServerClusterDenied(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedClusters: []config.ProtectedCluster{{Server: "https://prod"}},
	})
	defer cleanup()
	serverFor := fakeServerFor(nil)

	res, _, _, _ := checkWithResolvers([]string{"--server=https://anything", "delete", "pod", "x"},
		staticContext("dev"), noContextNamespace, noShortNames, notInCluster, serverFor)
	if res != Deny {
		t.Errorf("--server with only protected_clusters = %v, want Deny", res)
	}
	res, _, _, _ = checkWithResolvers([]string{"--cluster=prod-cluster", "delete", "pod", "x"},
		staticContext("dev"), noContextNamespace, noShortNames, notInCluster, serverFor)
	if res != Deny {
		t.Errorf("--cluster with only protected_clusters = %v, want Deny", res)
	}
}

// TestClusterIdentityResolveErrorIsAdditive: when the server resolver errors,
// cluster protection simply does not apply — a name-protected context is still
// gated exactly as before (a cluster-resolution failure never weakens an existing
// decision).
func TestClusterIdentityResolveErrorIsAdditive(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		ProtectedClusters: []config.ProtectedCluster{{Server: "https://prod"}},
	})
	defer cleanup()

	errResolver := ServerForContextFunc(func(_, _ string) (string, error) {
		return "", errors.New("kubeconfig unreadable")
	})

	// Name-protected context: still RequireConfirmation despite the resolver error.
	res, _, _, _ := checkWithResolvers([]string{"delete", "pod", "x"},
		staticContext("prod-1"), noContextNamespace, noShortNames, notInCluster, errResolver)
	if res != RequireConfirmation {
		t.Errorf("name-protected with cluster resolve error = %v, want RequireConfirmation", res)
	}

	// Unprotected name + resolver error: cluster protection cannot apply, so Allow
	// (the resolver failure did not fabricate a gate).
	res, _, _, _ = checkWithResolvers([]string{"delete", "pod", "x"},
		staticContext("dev"), noContextNamespace, noShortNames, notInCluster, errResolver)
	if res != Allow {
		t.Errorf("unprotected name with cluster resolve error = %v, want Allow", res)
	}
}

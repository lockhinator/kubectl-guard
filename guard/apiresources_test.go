package guard

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lockhinator/kubectl-guard/config"
)

func TestParseAPIResources(t *testing.T) {
	// Real-shaped `kubectl api-resources --no-headers` output, including rows with
	// NO short name (secrets, pushsecrets) and multi-column short names.
	out := []byte(`configmaps                          cm                                  v1                                        true         ConfigMap
secrets                                                                 v1                                        true         Secret
externalsecrets                     es                                  external-secrets.io/v1beta1               true         ExternalSecret
clusterexternalsecrets              ces                                 external-secrets.io/v1beta1               false        ClusterExternalSecret
secretstores                        ss                                  external-secrets.io/v1beta1               true         SecretStore
pushsecrets                                                             external-secrets.io/v1alpha1              true         PushSecret
horizontalpodautoscalers            hpa                                 autoscaling/v2                            true         HorizontalPodAutoscaler
`)
	got := parseAPIResources(out)
	want := map[string]string{
		// short names
		"cm": "configmap", "es": "externalsecret",
		"ces": "clusterexternalsecret", "ss": "secretstore",
		"hpa": "horizontalpodautoscaler",
		// plural NAMEs (so a CRD protected by kind is also matched by its typed
		// plural, including irregular plurals). A row with no short name still
		// contributes its plural name.
		"configmaps": "configmap", "secrets": "secret",
		"externalsecrets": "externalsecret", "clusterexternalsecrets": "clusterexternalsecret",
		"secretstores": "secretstore", "pushsecrets": "pushsecret",
		"horizontalpodautoscalers": "horizontalpodautoscaler",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseAPIResources = %#v,\nwant %#v", got, want)
	}
}

// TestParseAPIResourcesIrregularPlural: a CRD with a y->ies plural must map its
// typed plural to the canonical kind, so protecting the kind catches
// `get <plural>` even when NormalizeResource cannot singularize it.
func TestParseAPIResourcesIrregularPlural(t *testing.T) {
	out := []byte("ciliumnetworkpolicies               cnp                                 cilium.io/v2                              true         CiliumNetworkPolicy\n")
	got := parseAPIResources(out)
	if got["ciliumnetworkpolicies"] != "ciliumnetworkpolicy" {
		t.Errorf("plural ciliumnetworkpolicies = %q, want ciliumnetworkpolicy", got["ciliumnetworkpolicies"])
	}
	if got["cnp"] != "ciliumnetworkpolicy" {
		t.Errorf("short cnp = %q, want ciliumnetworkpolicy", got["cnp"])
	}
}

func TestParseAPIResourcesMultipleShortNames(t *testing.T) {
	// Some resources list several comma-separated short names.
	out := []byte(`poddisruptionbudgets                pdb                                 policy/v1                                 true         PodDisruptionBudget
things                              t,thing,th                          example.com/v1                            true         Thing
`)
	got := parseAPIResources(out)
	for _, short := range []string{"t", "thing", "th"} {
		if got[short] != "thing" {
			t.Errorf("short name %q = %q, want thing", short, got[short])
		}
	}
}

func TestParseAPIResourcesGarbage(t *testing.T) {
	// Blank lines, warnings, and too-short lines are skipped without panicking.
	out := []byte("\nsomewarning\n   \nconfigmaps cm v1 true ConfigMap\nbad line two\n")
	got := parseAPIResources(out)
	if got["cm"] != "configmap" || got["configmaps"] != "configmap" {
		t.Errorf("valid line must still parse (short + plural): %#v", got)
	}
	// "bad line two" is 3 fields -> too short (<4) -> skipped. Only the one valid
	// line contributes: its short name and its plural name.
	if len(got) != 2 {
		t.Errorf("only the one valid line should parse (short + plural), got %#v", got)
	}
}

func TestShortNameCacheRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	m := map[string]string{"ss": "secretstore"}
	writeShortNameCache("key-A", m, 1000)

	// Fresh + same key -> hit.
	if got, ok := readShortNameCache("key-A", 1000+60); !ok || !reflect.DeepEqual(got, m) {
		t.Errorf("fresh same-key read = (%v, %v), want (%v, true)", got, ok, m)
	}
	// Different cluster key -> miss (must not reuse another cluster's map).
	if _, ok := readShortNameCache("key-B", 1000+60); ok {
		t.Error("a different cluster key must miss the cache")
	}
	// Expired (beyond TTL) -> miss.
	expired := 1000 + int64(shortNameCacheTTL.Seconds()) + 1
	if _, ok := readShortNameCache("key-A", expired); ok {
		t.Error("an expired cache entry must miss")
	}
	// Within TTL boundary -> hit.
	atEdge := 1000 + int64(shortNameCacheTTL.Seconds())
	if _, ok := readShortNameCache("key-A", atEdge); !ok {
		t.Error("a cache entry exactly at the TTL edge must still hit")
	}
}

func TestShortNameCacheMissingFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if _, ok := readShortNameCache("key", 0); ok {
		t.Error("a missing cache file must miss, not error")
	}
}

func TestCacheKeyDistinguishesClusters(t *testing.T) {
	if cacheKey("", "prod") == cacheKey("", "dev") {
		t.Error("different contexts must produce different cache keys")
	}
	if cacheKey("/a", "prod") == cacheKey("/b", "prod") {
		t.Error("different kubeconfigs must produce different cache keys")
	}
	a, b := cacheKey("", "prod"), cacheKey("", "prod")
	if a != b {
		t.Error("the same target must produce a stable key")
	}
}

// TestDiscoverShortNamesDisabled: with discover_short_names: false, no discovery
// happens (returns nil) even with a warm cache.
func TestDiscoverShortNamesDisabled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeShortNameCache(cacheKey("", ""), map[string]string{"ss": "secretstore"}, timeNow())

	off := false
	cfg := &config.Config{DiscoverShortNames: &off}
	if m := DiscoverShortNames(cfg, []string{"get", "ss"}); m != nil {
		t.Errorf("discovery disabled must return nil, got %v", m)
	}
}

// TestDiscoverShortNamesUsesCache: a fresh cache is returned without running
// kubectl. We prove kubectl is not invoked by putting NO kubectl on PATH — if
// discovery shelled out it would error and fall back to nil; instead it must
// return the cached map.
func TestDiscoverShortNamesUsesCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "") // no kubectl anywhere: a shell-out would fail

	want := map[string]string{"ss": "secretstore"}
	// The command has no --context/--kubeconfig, so the key is cacheKey("","").
	writeShortNameCache(cacheKey("", ""), want, timeNow())

	got := DiscoverShortNames(&config.Config{}, []string{"get", "ss"})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DiscoverShortNames = %v, want the cached %v (must not shell out)", got, want)
	}
}

// TestDiscoverShortNamesCacheKeyedToTarget: a cache gathered for one context is
// not reused for a command targeting a different context.
func TestDiscoverShortNamesCacheKeyedToTarget(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "") // no kubectl: a miss falls back to nil, not a shell-out

	writeShortNameCache(cacheKey("", "prod"), map[string]string{"ss": "secretstore"}, timeNow())

	// A command targeting --context=dev must NOT get prod's cache.
	if m := DiscoverShortNames(&config.Config{}, []string{"--context=dev", "get", "ss"}); m != nil {
		t.Errorf("dev command must not reuse prod's cache; got %v", m)
	}
	// The prod command does get it.
	if m := DiscoverShortNames(&config.Config{}, []string{"--context=prod", "get", "ss"}); m["ss"] != "secretstore" {
		t.Errorf("prod command must reuse prod's cache; got %v", m)
	}
}

func TestDiscoverShortNamesNilConfig(t *testing.T) {
	if DiscoverShortNames(nil, []string{"get", "ss"}) != nil {
		t.Error("nil config must return nil")
	}
}

// TestGuardBlocksDiscoveredShortName is the end-to-end decision test through the
// guard core with an injected discoverer: protecting a CRD by kind blocks its
// discovered short name.
func TestGuardBlocksDiscoveredShortName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := &config.Config{ProtectedResources: []string{"secretstore"}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}

	discover := func(*config.Config, []string) map[string]string {
		return map[string]string{"ss": "secretstore"}
	}

	// `get ss` is blocked via discovery.
	res, _, _, _ := checkWithResolvers([]string{"get", "ss"}, staticContext("dev"), noContextNamespace, discover)
	if res != Blocked {
		t.Errorf("get ss = %v, want Blocked (discovered short name)", res)
	}
	// `get pods` is allowed.
	res, _, _, _ = checkWithResolvers([]string{"get", "pods"}, staticContext("dev"), noContextNamespace, discover)
	if res != Allow {
		t.Errorf("get pods = %v, want Allow", res)
	}
	// If discovery yields nothing (offline/RBAC), the built-in behavior stands:
	// the full name still blocks, the short name does not (no regression, no
	// crash).
	res, _, _, _ = checkWithResolvers([]string{"get", "secretstore"}, staticContext("dev"), noContextNamespace, noShortNames)
	if res != Blocked {
		t.Errorf("get secretstore with no discovery = %v, want Blocked (full name always works)", res)
	}
	res, _, _, _ = checkWithResolvers([]string{"get", "ss"}, staticContext("dev"), noContextNamespace, noShortNames)
	if res != Allow {
		t.Errorf("get ss with no discovery = %v, want Allow (fallback to built-ins, no crash)", res)
	}
}

// TestDiscoveryNotRunWithoutProtection: discovery must not shell out when no
// resource protection is configured (nothing to enrich).
func TestDiscoveryNotRunWithoutProtection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := config.Save(&config.Config{ProtectedContexts: []string{"prod-*"}}); err != nil {
		t.Fatal(err)
	}
	called := false
	spy := func(*config.Config, []string) map[string]string { called = true; return nil }
	_, _, _, _ = checkWithResolvers([]string{"get", "pods"}, staticContext("dev"), noContextNamespace, spy)
	if called {
		t.Error("discovery was invoked with no resource protection configured")
	}
}

// TestDiscoverShortNamesTimeout: a hung `kubectl api-resources` must not block
// the guard. With a fake kubectl that sleeps far longer than the (shrunk)
// timeout, DiscoverShortNames returns nil (fall back to built-ins) promptly.
func TestDiscoverShortNamesTimeout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// A fake kubectl that sleeps 30s in the foreground, with a trailing no-op so
	// the shell cannot tail-exec the sleep. That guarantees `sleep` runs as a
	// CHILD of the shell (a grandchild of the guard) holding the stdout pipe: the
	// context deadline SIGKILLs the shell, but the surviving sleep keeps the pipe
	// open, so cmd.Output() would block ~30s UNLESS WaitDelay force-closes it.
	// Reverting the WaitDelay in runAPIResources makes this hang to the Fatal.
	bin := t.TempDir()
	// Use an absolute path to sleep: PATH is set to just `bin` below, so a bare
	// `sleep` would not be found and the fake would exit immediately (testing
	// nothing). The trailing `true` stops the shell tail-exec'ing sleep.
	script := "#!/bin/sh\n/bin/sleep 30\ntrue\n"
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	// Shrink the deadline for the test and restore it after.
	orig := apiResourcesTimeout
	apiResourcesTimeout = 200 * time.Millisecond
	defer func() { apiResourcesTimeout = orig }()

	done := make(chan map[string]string, 1)
	start := time.Now()
	go func() { done <- DiscoverShortNames(&config.Config{}, []string{"get", "ss"}) }()

	select {
	case m := <-done:
		if m != nil {
			t.Errorf("a hung api-resources must yield nil (built-ins), got %v", m)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("discovery took %v; the timeout did not bound the hung subprocess", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("DiscoverShortNames did not return; the subprocess timeout did not fire")
	}
}

// TestCacheIgnoredWhenGroupWorldWritable: a cache file another user could have
// written (group/world-writable) is ignored, so it cannot even over-block.
func TestCacheIgnoredWhenGroupWorldWritable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	key := cacheKey("", "")
	writeShortNameCache(key, map[string]string{"ss": "secretstore"}, timeNow())
	path, _ := apiResourcesCachePath()

	// Sanity: a 0600 cache is honored.
	if _, ok := readShortNameCache(key, timeNow()); !ok {
		t.Fatal("a normally-written (0600) cache should be read")
	}
	// Make it world-writable; it must now be ignored.
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, ok := readShortNameCache(key, timeNow()); ok {
		t.Error("a group/world-writable cache must be ignored")
	}
}

// Ensure the discovery cache never lands where a stray file would break other
// tests: it writes under HOME.
func TestCachePathUnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	p, err := apiResourcesCachePath()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p) != home {
		t.Errorf("cache path %q not under HOME %q", p, home)
	}
	if _, err := os.Stat(home); err != nil {
		t.Fatal(err)
	}
}

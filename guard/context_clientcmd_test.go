package guard

import (
	"os"
	"path/filepath"
	"testing"
)

const fixtureKubeconfig = `apiVersion: v1
kind: Config
current-context: dev-ctx
clusters:
- name: dev-cluster
  cluster:
    server: https://dev.example.com
- name: prod-cluster
  cluster:
    server: https://prod.example.com
contexts:
- name: dev-ctx
  context:
    cluster: dev-cluster
    user: dev-user
    namespace: dev-ns
- name: prod-ctx
  context:
    cluster: prod-cluster
    user: prod-user
users:
- name: dev-user
- name: prod-user
`

func writeFixtureKubeconfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestClientcmdCurrentContext: the current context resolves by parsing the
// kubeconfig directly, with NO kubectl on PATH (proving no shell-out). #31.
func TestClientcmdCurrentContext(t *testing.T) {
	path := writeFixtureKubeconfig(t, fixtureKubeconfig)
	t.Setenv("PATH", "") // no kubectl anywhere
	t.Setenv("KUBECONFIG", path)
	got, err := defaultCurrentContext("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "dev-ctx" {
		t.Errorf("current context = %q, want dev-ctx", got)
	}
}

// TestClientcmdExplicitKubeconfig: an explicit --kubeconfig path is honored and
// wins over $KUBECONFIG. #31.
func TestClientcmdExplicitKubeconfig(t *testing.T) {
	path := writeFixtureKubeconfig(t, fixtureKubeconfig)
	t.Setenv("KUBECONFIG", "/nonexistent/should-be-ignored")
	got, err := defaultCurrentContext(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "dev-ctx" {
		t.Errorf("explicit --kubeconfig current context = %q, want dev-ctx", got)
	}
}

// TestClientcmdContextNamespace: the namespace baked into a context is read from
// the kubeconfig; a context with none yields "". #31.
func TestClientcmdContextNamespace(t *testing.T) {
	path := writeFixtureKubeconfig(t, fixtureKubeconfig)
	t.Setenv("KUBECONFIG", path)
	if ns, err := lookupContextNamespace("", ""); err != nil || ns != "dev-ns" {
		t.Errorf("current-context ns = %q (err %v), want dev-ns", ns, err)
	}
	if ns, err := lookupContextNamespace("", "prod-ctx"); err != nil || ns != "" {
		t.Errorf("prod-ctx ns = %q (err %v), want empty", ns, err)
	}
}

// TestClientcmdGetAllContexts: all contexts are listed (name-sorted) with their
// cluster/namespace/current flag, parsed directly. #31.
func TestClientcmdGetAllContexts(t *testing.T) {
	path := writeFixtureKubeconfig(t, fixtureKubeconfig)
	t.Setenv("PATH", "")
	t.Setenv("KUBECONFIG", path)
	ctxs, err := GetAllContexts()
	if err != nil {
		t.Fatal(err)
	}
	if len(ctxs) != 2 {
		t.Fatalf("got %d contexts, want 2: %+v", len(ctxs), ctxs)
	}
	if ctxs[0].Name != "dev-ctx" || ctxs[1].Name != "prod-ctx" {
		t.Errorf("contexts not name-sorted: %q, %q", ctxs[0].Name, ctxs[1].Name)
	}
	if !ctxs[0].Current {
		t.Errorf("dev-ctx should be marked current")
	}
	if ctxs[0].Cluster != "dev-cluster" || ctxs[0].Namespace != "dev-ns" {
		t.Errorf("dev-ctx fields = %+v", ctxs[0])
	}
}

// TestClientcmdMultiPathKubeconfig: a colon-separated $KUBECONFIG merges the
// contexts from every file; the current-context comes from the first that sets
// one. #31.
func TestClientcmdMultiPathKubeconfig(t *testing.T) {
	p1 := writeFixtureKubeconfig(t, fixtureKubeconfig)
	p2 := writeFixtureKubeconfig(t, `apiVersion: v1
kind: Config
clusters:
- name: staging-cluster
  cluster:
    server: https://staging.example.com
contexts:
- name: staging-ctx
  context:
    cluster: staging-cluster
    user: staging-user
    namespace: staging-ns
users:
- name: staging-user
`)
	t.Setenv("KUBECONFIG", p1+string(os.PathListSeparator)+p2)

	ctxs, err := GetAllContexts()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range ctxs {
		names[c.Name] = true
	}
	for _, want := range []string{"dev-ctx", "prod-ctx", "staging-ctx"} {
		if !names[want] {
			t.Errorf("merged $KUBECONFIG missing context %q; got %v", want, names)
		}
	}
	if got, _ := defaultCurrentContext(""); got != "dev-ctx" {
		t.Errorf("multi-path current-context = %q, want dev-ctx (from the first file)", got)
	}
	if ns, _ := lookupContextNamespace("", "staging-ctx"); ns != "staging-ns" {
		t.Errorf("staging-ctx ns from second file = %q, want staging-ns", ns)
	}
}

// TestEmptyContextNilErrFailsClosed locks the load-bearing fail-closed invariant
// that #31 depends on: clientcmd returns ("", nil) for an unset current-context
// (no error, unlike the old shell-out), so the guard's "cannot resolve context ⇒
// Deny" guarantee now rests on the `ctx == ""` disjunct in checkWithResolvers, not
// on a non-nil error. A refactor reverting that to `ctxErr != nil` alone would
// silently reopen a critical fail-open; this test would catch it. #31.
func TestEmptyContextNilErrFailsClosed(t *testing.T) {
	cleanup := writeRawConfig(t, "protected_contexts: [prod-*]\n")
	defer cleanup()
	emptyCtx := func(string) (string, error) { return "", nil } // clientcmd's empty-no-error shape
	for _, args := range [][]string{{"get", "pods"}, {"delete", "pod", "x"}} {
		res, _, _, err := checkWith(args, emptyCtx)
		if res != Deny {
			t.Errorf("checkWith(%v) with empty-context/nil-error = %v (err %v), want Deny (fail-closed)", args, res, err)
		}
	}
}

// TestLegacyContextFallback: KUBECTL_GUARD_LEGACY_CONTEXT=1 restores the shell-out
// path (via a fake kubectl on PATH). #31.
func TestLegacyContextFallback(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "kubectl")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho legacy-ctx\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("KUBECONFIG", "")
	t.Setenv(EnvLegacyContext, "1")
	got, err := defaultCurrentContext("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "legacy-ctx" {
		t.Errorf("legacy fallback current-context = %q, want legacy-ctx", got)
	}
}

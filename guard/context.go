// Package guard implements the core protection logic for kubectl-guard.
package guard

import (
	"bufio"
	"bytes"
	"os"
	"sort"
	"strings"
	"sync"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// EnvLegacyContext, when truthy, makes context/namespace resolution shell out to
// kubectl (the pre-v1.0 behavior) instead of parsing the kubeconfig directly via
// client-go's clientcmd. A safety hatch in case clientcmd ever diverges from a
// user's kubectl version.
const EnvLegacyContext = "KUBECTL_GUARD_LEGACY_CONTEXT"

func useLegacyContext() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvLegacyContext))) {
	case "1", "t", "true", "yes", "y":
		return true
	}
	return false
}

// loadKubeconfig parses the kubeconfig directly — no kubectl subprocess — using
// the same loading rules kubectl itself uses: an explicit --kubeconfig path wins,
// otherwise the $KUBECONFIG precedence list (colon-separated) is merged, else
// ~/.kube/config. This is the client-go equivalent of what kubectl does to
// resolve the current context, so it stays faithful to kubectl's own view.
func loadKubeconfig(kubeconfig string) (*clientcmdapi.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	return rules.Load()
}

// KubectlContext represents a kubectl context.
type KubectlContext struct {
	Name      string
	Cluster   string
	AuthInfo  string
	Namespace string
	Current   bool
}

// GetCurrentContext returns the current kubectl context name, honoring the
// KUBECONFIG environment variable.
func GetCurrentContext() (string, error) {
	return ResolveContext(nil)
}

// GetAllContexts returns all available kubectl contexts by parsing the kubeconfig
// directly (client-go), so it works without kubectl on PATH and spawns no
// subprocess. Contexts are returned in name order for deterministic output. Set
// KUBECTL_GUARD_LEGACY_CONTEXT=1 to fall back to shelling out to kubectl.
func GetAllContexts() ([]KubectlContext, error) {
	if useLegacyContext() {
		return legacyGetAllContexts()
	}
	cfg, err := loadKubeconfig("")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cfg.Contexts))
	for name := range cfg.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	contexts := make([]KubectlContext, 0, len(names))
	for _, name := range names {
		c := cfg.Contexts[name]
		contexts = append(contexts, KubectlContext{
			Name:      name,
			Cluster:   c.Cluster,
			AuthInfo:  c.AuthInfo,
			Namespace: c.Namespace,
			Current:   name == cfg.CurrentContext,
		})
	}
	return contexts, nil
}

// legacyGetAllContexts is the pre-v1.0 shell-out implementation, kept behind
// KUBECTL_GUARD_LEGACY_CONTEXT. It targets the REAL kubectl (via RealKubectlPath)
// so a PATH-shadowing shim cannot make the guard recurse into itself.
func legacyGetAllContexts() ([]KubectlContext, error) {
	cmd, err := kubectlCommand("config", "get-contexts", "--no-headers")
	if err != nil {
		return nil, err
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var contexts []KubectlContext
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		ctx := parseContextLine(line)
		if ctx.Name != "" {
			contexts = append(contexts, ctx)
		}
	}

	return contexts, scanner.Err()
}

// ResolveContextFromArgs inspects args for --context and --kubeconfig flags
// via the shared ParseArgs tokenizer. Because ParseArgs stops interpreting
// flags at "--", a trailing "-- --context=dev" can no longer spoof context
// resolution (the S1 bypass). Pure and easily tested.
func ResolveContextFromArgs(args []string) (ctx, kubeconfig string, explicit bool) {
	p := ParseArgs(args)
	return p.Context, p.Kubeconfig, p.ExplicitContext
}

// CurrentContextFunc returns the current kubectl context for a given
// kubeconfig path ("" = default lookup). The default implementation shells
// out to kubectl; tests inject a fake so the protection logic can be exercised
// without kubectl on PATH.
type CurrentContextFunc func(kubeconfig string) (string, error)

// ResolveContext determines the context a command will actually target, using
// the default (shelling-out) current-context lookup.
func ResolveContext(args []string) (string, error) {
	return resolveContextWith(args, defaultCurrentContext)
}

// resolveContextWith is the testable core: it honors an explicit --context
// only when it appears before "--" (ParseArgs enforces this), otherwise it
// falls back to the current-context lookup. This is the seam that makes the
// S1 ("--" bypass) and S2 (fail-closed) guarantees unit-testable.
func resolveContextWith(args []string, current CurrentContextFunc) (string, error) {
	p := ParseArgs(args)
	if p.ExplicitContext && p.Context != "" {
		return p.Context, nil
	}
	return current(p.Kubeconfig)
}

// defaultCurrentContext resolves the current context by parsing the kubeconfig
// directly (client-go), honoring an explicit --kubeconfig path. No kubectl
// subprocess. An unset current-context yields "" (the guard then fails closed on
// an empty context exactly as before). Set KUBECTL_GUARD_LEGACY_CONTEXT=1 to shell
// out to kubectl instead.
func defaultCurrentContext(kubeconfig string) (string, error) {
	if useLegacyContext() {
		return legacyCurrentContext(kubeconfig)
	}
	cfg, err := loadKubeconfig(kubeconfig)
	if err != nil {
		return "", err
	}
	return cfg.CurrentContext, nil
}

// legacyCurrentContext is the pre-v1.0 shell-out to `kubectl config
// current-context`, kept behind KUBECTL_GUARD_LEGACY_CONTEXT. It targets the REAL
// kubectl so a PATH-shadowing shim cannot make the guard recurse into itself.
func legacyCurrentContext(kubeconfig string) (string, error) {
	base := []string{"config", "current-context"}
	if kubeconfig != "" {
		base = append([]string{"--kubeconfig=" + kubeconfig}, base...)
	}
	cmd, err := kubectlCommand(base...)
	if err != nil {
		return "", err
	}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// NamespaceForContextFunc returns the namespace baked into the given context
// in kubeconfig, or "" when the context sets none. kubeconfig "" uses the
// default lookup; context "" means the current context. The default
// implementation shells out to kubectl; tests inject a fake so namespace
// resolution can be exercised without kubectl on PATH.
type NamespaceForContextFunc func(kubeconfig, context string) (string, error)

// noContextNamespace is the resolver used by checkWith (the test seam): it
// reports no context namespace, so resolution falls back to "default" and no
// kubectl subprocess is spawned during unit tests that don't opt in.
func noContextNamespace(_, _ string) (string, error) { return "", nil }

// InClusterFunc reports whether the guard is running in-cluster (inside a pod on
// the serviceaccount config, or CI with an in-cluster kubeconfig) and, if so, the
// serviceaccount namespace it runs in. It is injected so the in-cluster decision
// can be exercised without a real pod.
type InClusterFunc func() (namespace string, inCluster bool)

// notInCluster is the InClusterFunc used by checkWith (the test seam): it reports
// not-in-cluster, preserving the out-of-cluster fail-closed behavior for tests
// that do not opt in.
func notInCluster() (string, bool) { return "", false }

// saNamespacePath is the standard in-pod location of the serviceaccount
// namespace. It is a var so tests can point it at a fixture.
var saNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// defaultInCluster detects in-cluster execution and resolves the serviceaccount
// namespace. It reports in-cluster ONLY when BOTH signals of a real pod are
// present: KUBERNETES_SERVICE_HOST (injected by the kubelet) AND a readable,
// non-empty serviceaccount namespace file (projected into the pod alongside the
// token).
//
// Requiring the namespace file — not just the env var — is a security boundary.
// KUBERNETES_SERVICE_HOST is an ordinary, user-settable env var; if it alone
// entered in-cluster mode, an out-of-cluster caller could export it to flip the
// guard's fail-closed "unresolvable context ⇒ deny" into the relaxed in-cluster
// policy and slip a command past. The projected SA namespace file cannot be
// fabricated under /var/run/secrets by an ordinary caller, so gating detection on
// it keeps the relaxation to genuine pods. A pod that disables the SA mount
// (automountServiceAccountToken: false) is likewise treated as not-in-cluster and
// falls through to fail-closed — the conservative default; such a pod can opt in
// with in_cluster: allow.
func defaultInCluster() (string, bool) {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return "", false
	}
	data, err := os.ReadFile(saNamespacePath)
	if err != nil {
		return "", false
	}
	ns := strings.TrimSpace(string(data))
	if ns == "" {
		return "", false
	}
	return ns, true
}

// ctxNamespaceMemo caches context-namespace lookups for the lifetime of the
// process. A kubectl invocation resolves at most one (kubeconfig, context)
// pair, but the decision path and the message path both look it up; memoizing
// makes the second lookup a cache hit instead of a second `kubectl config view`
// subprocess, and — more importantly — guarantees the message names the same
// namespace the gating decision used (they cannot disagree). The kubeconfig
// cannot change within a single short-lived CLI invocation, so caching is
// always correct here; a fresh process starts with an empty cache.
var (
	ctxNamespaceMu   sync.Mutex
	ctxNamespaceMemo = map[string]ctxNamespaceResult{}
)

type ctxNamespaceResult struct {
	ns  string
	err error
}

// defaultContextNamespace is the memoized entry point used as the production
// NamespaceForContextFunc. It reads through ctxNamespaceMemo so repeated
// lookups of the same context within one invocation share a single subprocess
// and a single result (including a single error outcome).
func defaultContextNamespace(kubeconfig, context string) (string, error) {
	key := kubeconfig + "\x00" + context
	ctxNamespaceMu.Lock()
	if r, ok := ctxNamespaceMemo[key]; ok {
		ctxNamespaceMu.Unlock()
		return r.ns, r.err
	}
	ctxNamespaceMu.Unlock()

	ns, err := lookupContextNamespace(kubeconfig, context)

	ctxNamespaceMu.Lock()
	ctxNamespaceMemo[key] = ctxNamespaceResult{ns: ns, err: err}
	ctxNamespaceMu.Unlock()
	return ns, err
}

// lookupContextNamespace reads the namespace baked into a context by parsing the
// kubeconfig directly (client-go), honoring an explicit --kubeconfig/--context.
// context "" means the current context. An empty result means the context sets no
// namespace (kubectl then defaults to "default"). No kubectl subprocess. Set
// KUBECTL_GUARD_LEGACY_CONTEXT=1 to shell out to kubectl instead.
func lookupContextNamespace(kubeconfig, context string) (string, error) {
	if useLegacyContext() {
		return legacyLookupContextNamespace(kubeconfig, context)
	}
	cfg, err := loadKubeconfig(kubeconfig)
	if err != nil {
		return "", err
	}
	if context == "" {
		context = cfg.CurrentContext
	}
	if c, ok := cfg.Contexts[context]; ok {
		return c.Namespace, nil
	}
	return "", nil
}

// legacyLookupContextNamespace is the pre-v1.0 shell-out to
// `kubectl config view --minify`, kept behind KUBECTL_GUARD_LEGACY_CONTEXT. It
// targets the REAL kubectl so a PATH-shadowing shim cannot make the guard recurse
// into itself.
func legacyLookupContextNamespace(kubeconfig, context string) (string, error) {
	var args []string
	if kubeconfig != "" {
		args = append(args, "--kubeconfig="+kubeconfig)
	}
	if context != "" {
		args = append(args, "--context="+context)
	}
	args = append(args, "config", "view", "--minify", "-o", "jsonpath={.contexts[0].context.namespace}")
	cmd, err := kubectlCommand(args...)
	if err != nil {
		return "", err
	}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// parseContextLine parses a line from `kubectl config get-contexts --no-headers`.
// Format: CURRENT   NAME   CLUSTER   AUTHINFO   NAMESPACE
// CURRENT is * or empty.
func parseContextLine(line string) KubectlContext {
	var ctx KubectlContext

	// Check if this is the current context (starts with *)
	if strings.HasPrefix(line, "*") {
		ctx.Current = true
		line = strings.TrimPrefix(line, "*")
	}

	fields := strings.Fields(line)
	if len(fields) >= 1 {
		ctx.Name = fields[0]
	}
	if len(fields) >= 2 {
		ctx.Cluster = fields[1]
	}
	if len(fields) >= 3 {
		ctx.AuthInfo = fields[2]
	}
	if len(fields) >= 4 {
		ctx.Namespace = fields[3]
	}

	return ctx
}

// Package guard implements the core protection logic for kubectl-guard.
package guard

import (
	"bufio"
	"bytes"
	"strings"
	"sync"
)

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

// GetAllContexts returns all available kubectl contexts. It targets the REAL
// kubectl (via RealKubectlPath) so a PATH-shadowing shim cannot make the guard
// recurse into itself.
func GetAllContexts() ([]KubectlContext, error) {
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

// defaultCurrentContext shells out to `kubectl config current-context`,
// honoring an explicit --kubeconfig path. It targets the REAL kubectl so a
// PATH-shadowing shim cannot make the guard recurse into itself.
func defaultCurrentContext(kubeconfig string) (string, error) {
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

// lookupContextNamespace reads the namespace baked into a context via
// `kubectl config view --minify`, honoring an explicit --kubeconfig/--context.
// It targets the REAL kubectl so a PATH-shadowing shim cannot make the guard
// recurse into itself. An empty result means the context sets no namespace
// (kubectl then defaults to "default").
func lookupContextNamespace(kubeconfig, context string) (string, error) {
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

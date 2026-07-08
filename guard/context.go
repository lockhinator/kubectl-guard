// Package guard implements the core protection logic for kubectl-guard.
package guard

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"
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

// GetAllContexts returns all available kubectl contexts.
func GetAllContexts() ([]KubectlContext, error) {
	cmd := exec.Command("kubectl", "config", "get-contexts", "--no-headers")
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
// honoring an explicit --kubeconfig path.
func defaultCurrentContext(kubeconfig string) (string, error) {
	base := []string{"config", "current-context"}
	if kubeconfig != "" {
		base = append([]string{"--kubeconfig=" + kubeconfig}, base...)
	}
	out, err := exec.Command("kubectl", base...).Output()
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

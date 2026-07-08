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

// ResolveContext determines the context a command will actually target.
//
// It honors an explicit --context flag first (closing the bypass where
// "kubectl --context=prod delete ..." would otherwise skip the guard), then a
// --kubeconfig flag, and finally falls back to the current context (which
// itself honors KUBECONFIG).
func ResolveContext(args []string) (string, error) {
	ctx, kubeconfig, explicit := ResolveContextFromArgs(args)
	if explicit && ctx != "" {
		return ctx, nil
	}

	base := []string{}
	if kubeconfig != "" {
		base = append(base, "--kubeconfig="+kubeconfig)
	}
	base = append(base, "config", "current-context")

	cmd := exec.Command("kubectl", base...)
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

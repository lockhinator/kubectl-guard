// Package guard implements the core protection logic for kubectl-guard.
package guard

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/cameronlockhart/kubectl-guard/config"
)

// Result represents the outcome of checking a command.
type Result int

const (
	// Allow means the command should be forwarded to kubectl.
	Allow Result = iota
	// RequireConfirmation means the command needs user confirmation.
	RequireConfirmation
	// Blocked means the command targets a protected resource and is refused.
	Blocked
	// SetupRequired means the config doesn't exist and setup is needed.
	SetupRequired
	// Deny means the guard could not verify the command is safe (e.g. the
	// config is unreadable or the current context cannot be resolved while
	// protected contexts are configured). The guard fails closed: it refuses
	// to run the command rather than pass it through unprotected.
	Deny
)

// Check evaluates whether a command should be allowed, require confirmation,
// be blocked, be denied (fail-closed), or trigger setup. It returns the
// loaded config (non-nil for Allow/Blocked/RequireConfirmation) so callers do
// not need to re-read the file.
func Check(args []string) (Result, string, *config.Config, error) {
	return checkWith(args, defaultCurrentContext)
}

// checkWith is the testable core of Check: the current-context lookup is
// injected so the protection decision can be exercised without kubectl.
func checkWith(args []string, current CurrentContextFunc) (Result, string, *config.Config, error) {
	// Config must be readable; if we cannot tell what is protected we refuse.
	exists, err := config.Exists()
	if err != nil {
		return Deny, "", nil, fmt.Errorf("cannot read config status: %w", err)
	}
	if !exists {
		return SetupRequired, "", nil, nil
	}

	cfg, err := config.Load()
	if err != nil {
		return Deny, "", nil, fmt.Errorf("cannot load config: %w", err)
	}
	cfg.ApplyDefaults()

	// Best-effort context for messaging; failures are handled below.
	ctx, ctxErr := resolveContextWith(args, current)

	// Protected resources are blocked globally, regardless of context or verb.
	if MatchesProtectedResource(cfg, args) {
		return Blocked, ctx, cfg, nil
	}

	// If we cannot resolve the context, we cannot confirm it is unprotected.
	// When protected contexts exist, fail closed; otherwise there is nothing
	// to enforce beyond resources.
	if ctxErr != nil || ctx == "" {
		if len(cfg.ProtectedContexts) > 0 {
			if ctxErr != nil {
				return Deny, "", cfg, fmt.Errorf("cannot resolve current context: %w", ctxErr)
			}
			return Deny, "", cfg, fmt.Errorf("cannot resolve current context")
		}
		return Allow, "", cfg, nil
	}

	if cfg.IsContextProtected(ctx) && IsStateAltering(args) {
		return RequireConfirmation, ctx, cfg, nil
	}

	return Allow, ctx, cfg, nil
}

// ExecKubectl replaces the current process with kubectl.
func ExecKubectl(args []string) error {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		return err
	}

	// Prepend "kubectl" to args for proper argv[0]
	fullArgs := append([]string{"kubectl"}, args...)

	return syscall.Exec(kubectl, fullArgs, os.Environ())
}

// RunKubectl runs kubectl and returns its output.
func RunKubectl(args ...string) ([]byte, error) {
	cmd := exec.Command("kubectl", args...)
	return cmd.Output()
}

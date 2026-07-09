// Package guard implements the core protection logic for kubectl-guard.
package guard

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/lockhinator/kubectl-guard/config"
)

// Exit codes for guard decisions. kubectl itself uses 0 (success) and 1
// (error); guard decisions use higher codes so an agent framework can
// distinguish a guard intervention from an ordinary kubectl failure. When the
// guard allows a command it replaces its own process with kubectl via
// syscall.Exec, so kubectl's real exit code is preserved (ExitSuccess/ExitKubectlError).
const (
	ExitSuccess      = 0 // allowed / ran successfully (kubectl's own code is preserved)
	ExitKubectlError = 1 // kubectl itself errored (passthrough)
	ExitBlocked      = 2 // blocked: command targets a protected resource
	ExitDenied       = 3 // denied: fail-closed (config/context could not be verified)
	ExitNeedsConfirm = 4 // needs confirmation but aborted (no TTY / agent / declined)
)

// JSONResult is the structured decision object emitted on stderr when the
// guard runs with --json and the decision is not Allow. Agent frameworks
// parse this instead of scraping human-facing warning text.
type JSONResult struct {
	Decision string `json:"decision"`           // blocked | denied | needs-confirmation
	Reason   string `json:"reason,omitempty"`   // machine-readable reason
	Context  string `json:"context,omitempty"`  // resolved or declared context
	Command  string `json:"command"`            // the kubectl command string
	Resource string `json:"resource,omitempty"` // protected resource token (Blocked)
}

// JSONForResult builds the structured decision object for a non-Allow result.
// commandStr is the joined kubectl argument string; args is the raw arg list
// (used to best-effort surface the protected resource token for Blocked).
// denyErr is the error returned by Check for a Deny result.
func JSONForResult(result Result, ctx, commandStr string, args []string, denyErr error) JSONResult {
	jr := JSONResult{Context: ctx, Command: commandStr}
	switch result {
	case Blocked:
		jr.Decision = "blocked"
		jr.Reason = "protected-resource"
		if cands := ExtractResourceCandidates(args); len(cands) > 0 {
			jr.Resource = cands[0]
		}
	case Deny:
		jr.Decision = "denied"
		if denyErr != nil {
			jr.Reason = denyErr.Error()
		} else {
			jr.Reason = "fail-closed"
		}
	case RequireConfirmation:
		jr.Decision = "needs-confirmation"
		jr.Reason = "aborted"
	}
	return jr
}

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

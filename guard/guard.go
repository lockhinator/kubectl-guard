// Package guard implements the core protection logic for kubectl-guard.
package guard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	// Prompt is the human-readable approval request, set in agent-relay mode so
	// an agent framework can show it to its own human before re-running with --yes.
	Prompt string `json:"prompt,omitempty"`
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
	return checkWithResolvers(args, defaultCurrentContext, defaultContextNamespace, DiscoverShortNames)
}

// ShortNameDiscoverer returns discovered CRD short names for the command's
// target cluster (or nil to fall back to built-ins). Injected so the decision
// core can be tested without shelling out to `kubectl api-resources`.
type ShortNameDiscoverer func(cfg *config.Config, args []string) map[string]string

// noShortNames is the discoverer used by checkWith: it discovers nothing, so
// existing tests never spawn a kubectl api-resources subprocess.
func noShortNames(*config.Config, []string) map[string]string { return nil }

// checkWith is the test seam for the current-context lookup. It uses the no-op
// context-namespace resolver AND the no-op short-name discoverer so existing
// tests never spawn a kubectl subprocess; tier-2 namespace resolution and CRD
// short-name discovery are exercised via checkWithResolvers with injected fakes.
func checkWith(args []string, current CurrentContextFunc) (Result, string, *config.Config, error) {
	return checkWithResolvers(args, current, noContextNamespace, noShortNames)
}

// checkWithResolvers is the testable core of Check: the current-context lookup,
// the context-namespace lookup, and the CRD short-name discovery are all injected
// so the protection decision can be exercised without kubectl.
func checkWithResolvers(args []string, current CurrentContextFunc, nsFor NamespaceForContextFunc, discover ShortNameDiscoverer) (Result, string, *config.Config, error) {
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

	// A config with an invalid known-field value silently downgrades protection:
	// e.g. context_mode: "blck" is not "block", so the runtime falls back to
	// confirm (bypassable with --yes) while the user believes they set block. For
	// a security tool that is the wrong default, so an invalid config fails
	// CLOSED: refuse every command until it is fixed, rather than run with
	// protection weaker than configured. `kubectl-guard config validate` lists the
	// problems, and the config-mutation subcommands still work so it can be fixed.
	if problems := cfg.Validate(); len(problems) > 0 {
		return Deny, "", cfg, fmt.Errorf("config is invalid: %s (run 'kubectl-guard config validate')", strings.Join(problems, "; "))
	}

	// Best-effort context for messaging; failures are handled below.
	ctx, ctxErr := resolveContextWith(args, current)

	// Enrich resource matching with discovered CRD short names (cached), so that
	// protecting a CRD by kind also blocks its short name (e.g. "secretstore"
	// blocks `get ss`). Best-effort and additive: on any failure it is a no-op and
	// matching stays on the built-in short names. Only worth doing when resource
	// protection is configured.
	if cfg.HasProtectedResources() {
		cfg.SetDiscoveredShortNames(discover(cfg, args))
	}

	// Protected resources are blocked globally, regardless of context or verb.
	if MatchesProtectedResource(cfg, args) {
		return Blocked, ctx, cfg, nil
	}

	p := ParseArgs(args)

	// --server points at an arbitrary API server the guard cannot map to a
	// context name. When context protection is configured, fail closed rather
	// than allow a command against an unverified (possibly production) cluster.
	// Use --context pointing at a named context instead.
	if p.HasServer && len(cfg.ProtectedContexts) > 0 {
		return Deny, ctx, cfg, fmt.Errorf("--server overrides the cluster target and cannot be mapped to a context; refusing because protected contexts are configured (use --context instead)")
	}

	// A state-altering command in dry-run mode (--dry-run=client|server, not
	// none) changes no cluster state, so skip context/namespace gating. This
	// reduces cry-wolf prompts on safe operations. Protected-resource blocks
	// above still apply: a dry-run of a protected resource is still blocked.
	//
	// Verbs with no --dry-run flag (exec, port-forward, proxy, ...) are excluded:
	// they cannot be dry-run, so a --dry-run token on such a command must never
	// buy an ungated pass.
	if IsStateAltering(args) && p.IsDryRun() && SupportsDryRun(args) {
		return Allow, ctx, cfg, nil
	}

	// Context protection. If we cannot resolve the context while protected
	// contexts are configured, fail closed (we can't confirm it's unprotected).
	contextProtected := false
	if ctx != "" && cfg.IsContextProtected(ctx) {
		contextProtected = true
	} else if (ctxErr != nil || ctx == "") && len(cfg.ProtectedContexts) > 0 {
		if ctxErr != nil {
			return Deny, "", cfg, fmt.Errorf("cannot resolve current context: %w", ctxErr)
		}
		return Deny, "", cfg, fmt.Errorf("cannot resolve current context")
	}

	// Optional policy: deny any impersonation (--as*) on a protected context.
	if contextProtected && cfg.BlockImpersonation && p.HasImpersonation() {
		return Deny, ctx, cfg, fmt.Errorf("impersonation (--as) is blocked on protected context %q", ctx)
	}

	// Namespace/context gating only applies to state-altering commands, so the
	// namespace resolution (which may shell out for the context's baked-in
	// namespace, per tier 2) is deferred until we know the verb mutates state.
	// This keeps read-only commands (get/describe/logs/...) from spawning a
	// kubectl subprocess just because namespace protection is configured.
	if !IsStateAltering(args) {
		return Allow, ctx, cfg, nil
	}

	// The target namespace comes from --namespace/-n, then the namespace baked
	// into the resolved context, then kubectl's "default". --all-namespaces/-A
	// spans every namespace, so it is gated when any namespace is protected
	// (like "get all" spans resources).
	namespaceProtected := namespaceTargetProtected(cfg, p, ctx, nsFor)

	if contextProtected || namespaceProtected {
		// Block mode: hard-refuse state-altering commands with no prompt. If
		// either the matching context or namespace is in block mode, block wins
		// (most restrictive). --yes cannot bypass this: it only auto-confirms
		// RequireConfirmation, and Blocked is a separate result.
		if (contextProtected && cfg.ContextMode == config.ContextModeBlock) ||
			(namespaceProtected && cfg.NamespaceMode == config.NamespaceModeBlock) {
			return Blocked, ctx, cfg, nil
		}
		return RequireConfirmation, ctx, cfg, nil
	}

	return Allow, ctx, cfg, nil
}

// namespaceTargetProtected reports whether the command targets a protected
// namespace, by any of three routes (any match gates):
//
//  1. --all-namespaces/-A spans every namespace, so it is treated as protected
//     whenever any namespace pattern is configured;
//  2. the command's resource kind is `namespace` and one of the namespace NAMES
//     it addresses is protected — `kubectl delete namespace kube-system` carries
//     no -n flag, so route 3 would resolve "default" and miss it entirely;
//  3. the namespace the command runs IN (from -n, the context, or "default")
//     matches a protected pattern.
//
// This function is only reached for state-altering verbs: checkWith returns
// Allow for reads before calling it, so `kubectl get namespace kube-system` is
// never gated.
func namespaceTargetProtected(cfg namespaceChecker, p ParsedArgs, ctx string, nsFor NamespaceForContextFunc) bool {
	if p.AllNamespaces && cfg.HasProtectedNamespaces() {
		return true
	}
	if _, ok := protectedNamespaceNameTarget(cfg, p); ok {
		return true
	}
	return cfg.IsNamespaceProtected(resolveTargetNamespace(cfg, p, ctx, nsFor))
}

// protectedNamespaceNameTarget reports whether a state-altering command targets
// a protected namespace as its OBJECT (rather than as the namespace it runs in),
// returning the matched target for messaging.
//
// A wide-scope namespace command (`delete namespace --all`, `delete ns -l x=y`)
// names nothing the guard can check, so with any namespace protection configured
// it fails closed: the guard cannot prove a protected namespace is not among the
// targets.
func protectedNamespaceNameTarget(cfg namespaceChecker, p ParsedArgs) (string, bool) {
	t := namespaceTargetsFrom(p)
	if !t.Kind || !cfg.HasProtectedNamespaces() {
		return "", false
	}
	if t.Wide {
		return "all namespaces", true
	}
	for _, name := range t.Names {
		if cfg.IsNamespaceProtected(name) {
			return name, true
		}
	}
	return "", false
}

// ProtectedNamespaceNameTarget is the exported form of
// protectedNamespaceNameTarget, used by user-facing messages so they name the
// namespace OBJECT that triggered gating (e.g. "kube-system" for
// `delete namespace kube-system`) rather than the namespace the command would
// otherwise be considered to run in (e.g. "default").
func ProtectedNamespaceNameTarget(cfg *config.Config, args []string) (string, bool) {
	if cfg == nil {
		return "", false
	}
	return protectedNamespaceNameTarget(cfg, ParseArgs(args))
}

// resolveTargetNamespace determines the namespace a command targets for
// protection decisions, in priority order:
//  1. an explicit --namespace/-n flag;
//  2. the namespace baked into the resolved context (best-effort);
//  3. kubectl's "default".
//
// The context-namespace lookup (step 2) only runs when namespace protection is
// configured, because it shells out; a lookup error falls back to "default"
// rather than failing closed, so a transient kubeconfig read cannot block every
// namespace-gated command. Explicit -n and -A protection are unaffected.
func resolveTargetNamespace(cfg namespaceChecker, p ParsedArgs, ctx string, nsFor NamespaceForContextFunc) string {
	if p.HasNamespace && p.Namespace != "" {
		return p.Namespace
	}
	if cfg.HasProtectedNamespaces() && nsFor != nil {
		if ns, err := nsFor(p.Kubeconfig, ctx); err == nil && ns != "" {
			return ns
		}
	}
	return "default"
}

// ResolvedTargetNamespace returns the namespace a command targets, applying the
// same resolution the guard decision used (--namespace/-n, then the context's
// baked-in namespace, then "default"). It is used for user-facing messages so
// they name the namespace that actually triggered gating, including one derived
// from the context. It may shell out for the context lookup, so callers should
// use it only on the (interactive) gated path, not the hot read path.
func ResolvedTargetNamespace(cfg *config.Config, args []string, ctx string) string {
	return resolveTargetNamespace(cfg, ParseArgs(args), ctx, defaultContextNamespace)
}

// namespaceChecker is satisfied by *config.Config; kept as an interface so the
// guard decision logic stays testable without a real config file.
type namespaceChecker interface {
	HasProtectedNamespaces() bool
	IsNamespaceProtected(namespace string) bool
}

// ExecKubectl replaces the current process with the REAL kubectl. It resolves
// the real binary via RealKubectlPath so that a PATH-shadowing install (where
// a shim named "kubectl" points at the guard) cannot make the guard exec itself
// in a loop.
func ExecKubectl(args []string) error {
	kubectl, err := RealKubectlPath()
	if err != nil {
		return err
	}

	// Prepend "kubectl" to args for proper argv[0]
	fullArgs := append([]string{"kubectl"}, args...)

	return syscall.Exec(kubectl, fullArgs, os.Environ())
}

// RunKubectl runs the REAL kubectl and returns its output. It uses
// RealKubectlPath so internal lookups don't recurse into a PATH-shadowing shim.
func RunKubectl(args ...string) ([]byte, error) {
	cmd, err := kubectlCommand(args...)
	if err != nil {
		return nil, err
	}
	return cmd.Output()
}

// kubectlCommand builds an exec.Cmd targeting the REAL kubectl (never the
// guard's own shim). All internal kubectl invocations must go through here, or
// through RealKubectlPath directly, so a PATH-shadowing install does not cause
// the guard to recurse into itself when resolving contexts.
func kubectlCommand(args ...string) (*exec.Cmd, error) {
	path, err := RealKubectlPath()
	if err != nil {
		return nil, err
	}
	return exec.Command(path, args...), nil
}

// kubectlCommandContext is kubectlCommand with a context, so a slow or hung
// kubectl invocation (a stalled apiserver call, a hanging exec-credential auth
// plugin) can be bounded by a deadline instead of blocking the guard forever.
func kubectlCommandContext(ctx context.Context, args ...string) (*exec.Cmd, error) {
	path, err := RealKubectlPath()
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, path, args...), nil
}

// RealKubectlPath resolves the path to the real kubectl binary by walking PATH
// in order and skipping any directory whose "kubectl" entry is the guard itself
// (e.g. a PATH-shadowing shim that symlinks "kubectl" to this binary). This
// prevents the guard from exec'ing or querying itself in a loop. It returns the
// first non-self kubectl, or falls back to exec.LookPath when PATH contains no
// self-shadow (the common alias install).
func RealKubectlPath() (string, error) {
	self, selfErr := os.Executable()

	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, "kubectl")
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		// Skip our own binary: the shim is typically a symlink to the guard.
		if selfErr == nil && sameExecutable(candidate, self) {
			continue
		}
		return candidate, nil
	}

	// No self-shadow on PATH (plain alias install): defer to the standard
	// lookup so the common case keeps working.
	return exec.LookPath("kubectl")
}

// sameExecutable reports whether path and other refer to the same executable
// file, following symlinks (the shim is a symlink to the guard binary) and
// comparing inodes via os.SameFile.
func sameExecutable(path, other string) bool {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	if resolved, err := filepath.EvalSymlinks(other); err == nil {
		other = resolved
	}
	a, errA := os.Stat(path)
	b, errB := os.Stat(other)
	if errA != nil || errB != nil {
		return false
	}
	return os.SameFile(a, b)
}

// findAllOnPath returns every executable named name found on PATH, in PATH
// order (mirrors `which -a`).
func findAllOnPath(name string) []string {
	var found []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		found = append(found, candidate)
	}
	return found
}

// DoctorReport summarizes whether PATH-shadowing interception is active. It is
// the data behind `kubectl-guard doctor`.
type DoctorReport struct {
	// GuardPath is the absolute path of this guard binary (best-effort).
	GuardPath string
	// Intercepted reports whether the first kubectl on PATH resolves to the
	// guard, i.e. PATH-shadowing is active.
	Intercepted bool
	// RealKubectlPath is the resolved path of the real kubectl binary (the
	// first kubectl on PATH that is not the guard), or empty if not found.
	RealKubectlPath string
	// KubectlOnPath lists every kubectl found on PATH, in PATH order (like
	// `which -a kubectl`).
	KubectlOnPath []string
	// Err is non-nil if the real kubectl could not be resolved.
	Err error
}

// Doctor inspects PATH to report whether PATH-shadowing interception is active
// and where the real kubectl lives. It powers `kubectl-guard doctor`.
func Doctor() DoctorReport {
	var report DoctorReport
	if self, err := os.Executable(); err == nil {
		report.GuardPath = self
	}
	report.KubectlOnPath = findAllOnPath("kubectl")
	if len(report.KubectlOnPath) > 0 && report.GuardPath != "" {
		report.Intercepted = sameExecutable(report.KubectlOnPath[0], report.GuardPath)
	}
	if real, err := RealKubectlPath(); err != nil {
		report.Err = err
	} else {
		report.RealKubectlPath = real
	}
	return report
}

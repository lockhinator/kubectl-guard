package guard

import (
	"fmt"

	"github.com/lockhinator/kubectl-guard/config"
)

// ExplainResult is the outcome of a policy preflight: what the guard WOULD decide
// for a command, and why, without running kubectl, prompting, or auditing.
type ExplainResult struct {
	Decision  string // allow | needs-confirmation | blocked | denied | setup-required
	Reason    string // human-readable explanation of the matched rule
	Rule      string // machine-readable matched rule (e.g. protected-context, blast-radius)
	Verb      string // the resolved kubectl verb
	Class     string // safe | state-altering | unknown
	Context   string // resolved context (best-effort)
	Namespace string // resolved target namespace
	Resource  string // protected resource token, when the block is resource-driven
}

// Explain runs the guard's real decision logic (Check) for args and reports the
// outcome and the rule that produced it. It is a pure query: Check never execs
// kubectl, prompts, or writes an audit entry, so Explain does not either.
//
// The DECISION comes straight from Check (authoritative). The reason is derived
// by re-evaluating the same policy predicates the decision uses, in the same
// precedence, so the explanation tracks the real logic.
func Explain(args []string) ExplainResult {
	result, ctx, cfg, err := Check(args)
	return explainFrom(result, ctx, cfg, err, args)
}

// explainFrom builds the ExplainResult from a decision. Split out so tests can
// drive it with injected resolvers via checkWithResolvers.
func explainFrom(result Result, ctx string, cfg *config.Config, err error, args []string) ExplainResult {
	r := ExplainResult{Context: ctx, Verb: commandVerb(args)}
	r.Class = classifyVerb(cfg, args)
	if cfg != nil {
		p := ParseArgs(args)
		r.Namespace = p.ResolvedNamespace()
	}

	switch result {
	case SetupRequired:
		r.Decision, r.Rule, r.Reason = "setup-required", "no-config", "no configuration exists; the guard would run setup"
		return r
	case Deny:
		r.Decision, r.Rule = "denied", "fail-closed"
		if err != nil {
			r.Reason = err.Error()
		} else {
			r.Reason = "the guard could not verify the command is safe (fail-closed)"
		}
		return r
	case Blocked:
		r.Decision = "blocked"
		explainBlocked(&r, cfg, args, ctx)
		return r
	case RequireConfirmation:
		r.Decision = "needs-confirmation"
		explainGated(&r, cfg, args, ctx)
		return r
	default: // Allow
		r.Decision = "allow"
		explainAllow(&r, cfg, args, ctx)
		return r
	}
}

// classifyVerb reports the safe/state-altering/unknown class of the command,
// honoring command_overrides.
func classifyVerb(cfg *config.Config, args []string) string {
	if IsUnknownCommand(cfg, args) {
		return "unknown"
	}
	if IsStateAlteringWith(cfg, args) {
		return "state-altering"
	}
	if IsSafeCommandWith(cfg, args) {
		return "safe"
	}
	return "unknown"
}

func explainBlocked(r *ExplainResult, cfg *config.Config, args []string, ctx string) {
	if MatchesProtectedResource(cfg, args) {
		r.Rule = "protected-resource"
		if cands := ExtractResourceCandidates(args); len(cands) > 0 {
			r.Resource = cands[0]
		}
		r.Reason = "targets a protected resource"
		if r.Resource != "" {
			r.Reason = fmt.Sprintf("targets protected resource %q", r.Resource)
		}
		return
	}
	ctxMode, nsMode := EffectiveTargetModes(cfg, args, ctx)
	// The cases mirror runGuard's Blocked-reason precedence EXACTLY (main.go), so
	// `explain` reports the same reason the runtime would — an agent branches on
	// the --json reason token, and the two must never disagree.
	switch {
	case cfg != nil && cfg.ReadOnlyActive() && !IsSafeCommandWith(cfg, args):
		r.Rule, r.Reason = "read-only-mode", "global read-only / freeze mode: only known-safe reads run"
	case cfg != nil && cfg.IsContextProtected(ctx) && ctxMode == config.ContextModeBlock:
		r.Rule, r.Reason = "protected-context-block-mode", fmt.Sprintf("protected context %q is in block mode", ctx)
	case IsSensitiveAccess(cfg, args) && cfg != nil && cfg.SensitiveAccessMode() == config.SensitiveAccessBlock:
		r.Rule, r.Reason = "sensitive-access-block", fmt.Sprintf("%q is a sensitive-access verb (sensitive_access: block)", r.Verb)
	case IsBlastRadiusActive(cfg, args) && cfg != nil && cfg.BlastRadiusMode() == config.BlastRadiusBlock:
		_, why := BlastRadius(args)
		r.Rule, r.Reason = "blast-radius-block", fmt.Sprintf("wide-scope mutation (blast_radius: block): %s", why)
	case IsSensitiveKindActive(cfg, args) && cfg != nil && cfg.SensitiveKindMode() == config.SensitiveKindBlock:
		r.Rule, r.Reason = "sensitive-kind-block", "targets a sensitive kind (sensitive_kind_mode: block)"
	default:
		if srv, ok := ClusterProtected(cfg, args, ctx); ok && cfg.EffectiveClusterMode(srv) == config.ContextModeBlock {
			r.Rule, r.Reason = "protected-cluster-block-mode", fmt.Sprintf("protected cluster %q is in block mode", srv)
			return
		}
		r.Rule, r.Reason = "protected-namespace-block-mode", fmt.Sprintf("protected namespace is in block mode (namespace_mode: %s)", nsMode)
	}
}

func explainGated(r *ExplainResult, cfg *config.Config, args []string, ctx string) {
	if cfg == nil {
		r.Rule, r.Reason = "gated", "requires confirmation"
		return
	}
	wide, blastReason := BlastRadius(args)
	nameTarget, byName := ProtectedNamespaceNameTarget(cfg, args)
	clusterServer, clusterHit := ClusterProtected(cfg, args, ctx)
	p := ParseArgs(args)
	switch {
	case IsSensitiveAccess(cfg, args) && !cfg.IsContextProtected(ctx) && !byName:
		r.Rule, r.Reason = "sensitive-access", fmt.Sprintf("%q is a sensitive-access verb, gated on any context", r.Verb)
	case byName:
		r.Rule, r.Reason = "protected-namespace", fmt.Sprintf("targets protected namespace %q", nameTarget)
	case p.AllNamespaces && cfg.HasProtectedNamespaces():
		r.Rule, r.Reason = "protected-namespace", "spans all namespaces while a namespace is protected"
	case p.HasNamespace && p.Namespace != "" && cfg.IsNamespaceProtected(p.Namespace):
		r.Rule, r.Reason = "protected-namespace", fmt.Sprintf("targets protected namespace %q", p.Namespace)
	case cfg.IsContextProtected(ctx):
		r.Rule, r.Reason = "protected-context", fmt.Sprintf("protected context %q", ctx)
	case clusterHit:
		r.Rule, r.Reason = "protected-cluster", fmt.Sprintf("resolved API server %q matches protected_clusters", clusterServer)
	case wide && cfg.BlastRadiusMode() != config.BlastRadiusOff:
		r.Rule, r.Reason = "blast-radius", fmt.Sprintf("wide-scope mutation (blast_radius: %s): %s", cfg.BlastRadiusMode(), blastReason)
	case IsUnknownCommand(cfg, args) && cfg.UnknownVerbMode() != config.UnknownVerbAllow:
		r.Rule, r.Reason = "unknown-verb", fmt.Sprintf("unrecognized verb %q on a protected target (unknown_verb: %s)", LeadingVerb(args), cfg.UnknownVerbMode())
	case cfg.HasProtectedNamespaces():
		r.Rule, r.Reason = "protected-namespace", fmt.Sprintf("targets protected namespace %q", ResolvedTargetNamespace(cfg, args, ctx))
	default:
		r.Rule, r.Reason = "gated", "requires confirmation"
	}
}

func explainAllow(r *ExplainResult, cfg *config.Config, args []string, ctx string) {
	switch {
	case cfg == nil:
		r.Rule, r.Reason = "allow", "no configuration; command passes"
	case IsSafeCommandWith(cfg, args):
		r.Rule, r.Reason = "read-only", "read-only command; not gated"
	case IsStateAlteringWith(cfg, args) && ParseArgs(args).IsDryRun() && SupportsDryRun(args) && !IsSensitiveAccess(cfg, args):
		r.Rule, r.Reason = "dry-run-skip", "a --dry-run changes no cluster state, so gating is skipped"
	case cfg.IsContextProtected(ctx):
		r.Rule, r.Reason = "allow", fmt.Sprintf("protected context %q, but this command is not gated by any active policy", ctx)
	default:
		r.Rule, r.Reason = "allow", "no protected context/namespace/resource applies"
	}
}

// JSONResult builds the structured decision object for the explain result,
// matching the runtime --json shape (JSONResult) so agents parse one schema.
//
// The Reason field carries the machine-readable matched RULE (e.g.
// "protected-context", "blast-radius", "unknown-verb"), not the human prose — a
// stable token an agent can branch on, and strictly more informative than the
// runtime --json's needs-confirmation reason ("aborted"). The human `explain`
// output shows the prose reason instead. The block-mode/resource rule tokens
// match the runtime --json Blocked reasons.
func (r ExplainResult) JSONResult(commandStr string) JSONResult {
	return JSONResult{
		Decision: r.Decision,
		Reason:   r.Rule,
		Context:  r.Context,
		Command:  commandStr,
		Resource: r.Resource,
	}
}

// Package guard implements the core protection logic for kubectl-guard.
package guard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	return checkWithResolvers(args, defaultCurrentContext, defaultContextNamespace, DiscoverShortNames, defaultInCluster, defaultServerForContext)
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
	return checkWithResolvers(args, current, noContextNamespace, noShortNames, notInCluster, noServerForContext)
}

// checkWithResolvers is the testable core of Check: the current-context lookup,
// the context-namespace lookup, the CRD short-name discovery, and the in-cluster
// detection are all injected so the protection decision can be exercised without
// kubectl or a real pod.
func checkWithResolvers(args []string, current CurrentContextFunc, nsFor NamespaceForContextFunc, discover ShortNameDiscoverer, inCluster InClusterFunc, serverFor ServerForContextFunc) (Result, string, *config.Config, error) {
	// Config must be readable; if we cannot tell what is protected we refuse. The
	// decision path loads the EFFECTIVE config: the enforced SYSTEM baseline (if
	// any) merged most-restrictively under the USER config (issue #86). The merged
	// config already has the merge + ApplyDefaults applied, and its enforcement
	// metadata (SystemEnforced / pinned audit sink) travels with it so the audit
	// writes and env-forbidding downstream honor the floor automatically. When no
	// system layer exists this is byte-identical to the prior Exists()+Load() path.
	cfg, exists, err := config.LoadEffective()
	if err != nil {
		return Deny, "", nil, fmt.Errorf("cannot load config: %w", err)
	}
	if !exists {
		return SetupRequired, "", nil, nil
	}

	// A group/world-writable config is a tamper signal: anyone who can rewrite
	// ~/.kubectl-guard.yaml can disable protection by emptying the protected lists.
	// In strict mode (strict_config_perms or KUBECTL_GUARD_STRICT) this fails
	// CLOSED — refuse every command until the mode is fixed — so a tampered or
	// exposed config can never run with silently-weakened protection. The
	// non-strict WARNING is surfaced by the caller (main), which owns user-facing
	// output; the decision core only enforces the strict deny.
	if insecure, detail, permErr := config.InsecureConfigPerms(); permErr == nil && insecure && cfg.StrictPerms() {
		return Deny, "", cfg, fmt.Errorf("strict mode is set and %s; refusing until fixed (secure the config: chmod 600 the file and 700 its directory)", detail)
	}

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

	// Sensitive-access policy: the sensitive verbs (exec/cp/attach/… or the
	// configured sensitive_verbs) reach into a workload with the caller's
	// credentials, so their risk is about what they can read/reach, not WHERE
	// they run or whether they mutate state. Computed up front because it must
	// override BOTH the dry-run skip below (a dry-run still reads/reaches — e.g.
	// `create secret --dry-run=client -o yaml` echoes the secret) and the
	// read-only early return further down.
	sensitiveActive := cfg.SensitiveAccessMode() != config.SensitiveAccessOff &&
		cfg.IsSensitiveVerb(commandVerb(args))

	// Blast-radius policy: a wide-scope / bulk mutation (delete --all, apply
	// --prune, a selector or --all-namespaces on a destructive verb, a force
	// delete) is gated on EVERY context because its danger is about how much it
	// destroys, not where it runs. Unlike sensitive-access it is about the
	// state-mutation axis, so a genuine --dry-run (which changes nothing) is NOT
	// gated: it is deliberately excluded from the dry-run skip below, letting that
	// early return pass a dry-run of a wide mutation through.
	blastActive := IsBlastRadiusActive(cfg, args)

	// Sensitive-kind policy: a state-altering command whose target kind (token or
	// -f manifest) matches sensitive_kinds is gated on EVERY context, while reads
	// of the kind pass. Orthogonal to context/namespace like sensitive-access and
	// blast-radius, so it threads through the same seams (in-cluster fall-through,
	// read-only early return, the gate, and block-mode).
	sensitiveKindActive := IsSensitiveKindActive(cfg, args)

	// Global read-only / freeze mode (incident panic button). When active, EVERY
	// command that is not a KNOWN-SAFE read is Blocked regardless of
	// context/namespace/actor, so an operator can freeze all mutations instantly
	// and everywhere. This fails SAFE: it gates on "not provably a safe read"
	// (!IsSafeCommandWith), not "known-dangerous" (IsStateAlteringWith) — otherwise
	// an unknown/plugin mutating verb the guard cannot classify (e.g. a krew plugin
	// that spawns a privileged pod) would slip the panic button. The tradeoff is
	// that read-only plugins are also blocked under freeze, which is the correct
	// default for an incident. A genuine --dry-run of a KNOWN state-altering verb
	// still passes (it changes nothing); a --dry-run token on an unknown verb buys
	// no pass (the plugin may ignore it). --yes does NOT override — this is
	// absolute, unlike a confirm. KUBECTL_GUARD_BYPASS still bypasses (the
	// documented, loudly-audited escape hatch). Checked before context/namespace
	// gating because it does not depend on which context is targeted.
	genuineDryRun := IsStateAlteringWith(cfg, args) && p.IsDryRun() && SupportsDryRun(args)
	if cfg.ReadOnlyActive() && !IsSafeCommandWith(cfg, args) && !genuineDryRun {
		return Blocked, ctx, cfg, nil
	}

	// --server points at an arbitrary API server the guard cannot map to a
	// context name. When context protection is configured, fail closed rather
	// than allow a command against an unverified (possibly production) cluster.
	// Use --context pointing at a named context instead.
	if p.HasServer && (len(cfg.ProtectedContexts) > 0 || len(cfg.ProtectedClusters) > 0) {
		return Deny, ctx, cfg, fmt.Errorf("--server overrides the cluster target and cannot be mapped to a context; refusing because protected contexts or clusters are configured (use --context instead)")
	}

	// --cluster retargets the API server via a named kubeconfig cluster, decoupled
	// from the context NAME the guard gates on: `--context=dev --cluster=prod`
	// gates on "dev" while the command hits prod. Refuse it under protected
	// contexts, like --server.
	if p.HasClusterOverride && (len(cfg.ProtectedContexts) > 0 || len(cfg.ProtectedClusters) > 0) {
		return Deny, ctx, cfg, fmt.Errorf("--cluster overrides the cluster target independently of the context name; refusing because protected contexts or clusters are configured (use --context instead)")
	}

	// Cluster-identity protection (#85): resolve the target context's API server
	// and match it against protected_clusters, so protection keys on the CLUSTER
	// the command hits, not just the spoofable context NAME. Purely additive — a
	// resolution failure just means cluster protection does not apply (name-based
	// protection is unchanged). Only resolve when cluster protection is configured,
	// so a name-only config never touches the server resolver (byte-identical to
	// before this feature).
	clusterProtected := false
	targetServer := ""
	if cfg.HasProtectedClusters() {
		if srv, serr := serverFor(p.Kubeconfig, ctx); serr == nil && srv != "" {
			targetServer = srv
			clusterProtected = cfg.IsClusterProtected(srv)
		}
	}

	// A state-altering command in dry-run mode (--dry-run=client|server, not
	// none) changes no cluster state, so skip context/namespace gating. This
	// reduces cry-wolf prompts on safe operations. Protected-resource blocks
	// above still apply: a dry-run of a protected resource is still blocked.
	//
	// Verbs with no --dry-run flag (exec, port-forward, proxy, ...) are excluded:
	// they cannot be dry-run, so a --dry-run token on such a command must never
	// buy an ungated pass. A sensitive-access verb is also excluded: dry-run is
	// about the state-mutation axis, but sensitive-access is about reading/
	// reaching, which a dry-run does not prevent.
	if IsStateAlteringWith(cfg, args) && p.IsDryRun() && SupportsDryRun(args) && !sensitiveActive {
		return Allow, ctx, cfg, nil
	}

	// Context protection. If we cannot resolve the context while protected
	// contexts are configured, we normally fail closed. But in-cluster (running
	// in a pod on the serviceaccount config, or CI with an in-cluster kubeconfig)
	// there is no context NAME to evaluate, so a blanket deny makes the guard
	// unusable there. The in_cluster policy decides what to do instead.
	contextProtected := false
	inClusterNamespace := "" // SA namespace to use as the namespace fallback (in-cluster namespace mode)
	if ctx != "" && cfg.IsContextProtected(ctx) {
		contextProtected = true
	} else if (ctxErr != nil || ctx == "") && len(cfg.ProtectedContexts) > 0 {
		saNS, isInCluster := inCluster()
		if !isInCluster {
			// Out-of-cluster: fail closed, unchanged.
			if ctxErr != nil {
				return Deny, "", cfg, fmt.Errorf("cannot resolve current context: %w", ctxErr)
			}
			return Deny, "", cfg, fmt.Errorf("cannot resolve current context")
		}
		switch cfg.InClusterMode() {
		case config.InClusterDeny:
			return Deny, "", cfg, fmt.Errorf("running in-cluster with no named context and in_cluster=deny; refusing (set in_cluster: namespace to gate by the serviceaccount namespace instead)")
		case config.InClusterAllow:
			// in_cluster: allow passes the (unevaluable) context protection
			// through, but the orthogonal, context-INDEPENDENT signals must still
			// gate even in-cluster: sensitive-access and blast-radius and
			// sensitive-kind (about what a verb reads/reaches or how much it
			// destroys), AND namespace protection for an EXPLICITLY-named target
			// (-n <ns>, -A, or the namespace as the command's object) — those are
			// fully evaluable from argv regardless of the unresolvable context.
			// Only the IMPLICIT run-in namespace (the serviceaccount-namespace
			// fallback) is relaxed by allow, so explicitNSProtected passes
			// fallbackNS "" (no SA-namespace gating). Fall through to the unified
			// gate below when any of these apply (contextProtected stays false);
			// only a command gated by none gets the blanket allow here.
			explicitNSProtected := namespaceTargetProtected(cfg, p, ctx, "", nsFor)
			if !sensitiveActive && !blastActive && !sensitiveKindActive && !explicitNSProtected {
				return Allow, "", cfg, nil
			}
		default: // InClusterNamespace: context protection cannot be evaluated
			// in-cluster, so gate by the serviceaccount namespace instead of the
			// unresolvable context. contextProtected stays false.
			if saNS == "" {
				// We are in-cluster but cannot determine the serviceaccount
				// namespace, so we cannot evaluate namespace protection either.
				// Fail closed rather than pass through: an unknowable identity must
				// not silently disable protection. (defaultInCluster already refuses
				// to report in-cluster without a readable SA namespace, so this is a
				// belt-and-suspenders guard against any other InClusterFunc.)
				return Deny, "", cfg, fmt.Errorf("running in-cluster but the serviceaccount namespace is unreadable; refusing (set in_cluster: allow to override, or use -n to name the namespace)")
			}
			inClusterNamespace = saNS
		}
	}

	// A resolved server matching protected_clusters gates the command even when the
	// context NAME is unprotected (an alias, or a crafted --kubeconfig/--context).
	// Purely additive: this can only turn contextProtected from false to true, so
	// it flows through the impersonation block, the unified gate, and unknownProtected
	// exactly like name protection, and never weakens an existing decision.
	//
	// Note it does NOT interact with the in-cluster fall-through above (the
	// InClusterAllow early return): cluster protection resolved a server from a
	// kubeconfig, which is the resolvable-context path, whereas that branch is only
	// reached when the context NAME is unresolvable. So the fail-open there is left
	// exactly as-is.
	//
	// nameProtected records that the context NAME matched protected_contexts,
	// distinct from a cluster-only match. It matters for the block decision below:
	// the name's ctxMode is authoritative for a name match, but for a CLUSTER-only
	// match ctxMode is just the global fallback (EffectiveContextMode of an
	// unprotected name returns the global mode), which would wrongly escalate a
	// per-entry `mode: confirm` cluster to block under global context_mode: block.
	nameProtected := contextProtected
	if clusterProtected {
		contextProtected = true
	}

	// Optional policy: deny any impersonation (--as*) on a protected context.
	if contextProtected && cfg.BlockImpersonation && p.HasImpersonation() {
		return Deny, ctx, cfg, fmt.Errorf("impersonation (--as) is blocked on protected context %q", ctx)
	}

	// Namespace/context gating only applies to state-altering commands, so the
	// namespace resolution (which may shell out for the context's baked-in
	// namespace, per tier 2) is deferred until we know the verb mutates state.
	// This keeps read-only commands (get/describe/logs/...) from spawning a
	// kubectl subprocess just because namespace protection is configured. A
	// non-state-altering command that is NOT sensitive AND NOT a wide/bulk mutation
	// passes through here. blastActive must be checked too: sensitive-access and
	// blast-radius are ORTHOGONAL policies (about what a verb can reach / how much
	// it destroys) that compose most-restrictive regardless of the safe/dangerous
	// classification. A `command_overrides.safe` downgrade makes stateAltering
	// false, so without this a safe-overridden bulk verb (e.g. `delete` marked
	// safe) would slip past a blast-radius BLOCK — inconsistent with the sensitive
	// case and with "block is un-bypassable". (When no override is in play,
	// blastActive already implies stateAltering, so this is a no-op.)
	// Unknown-verb strict policy (#72): a verb the guard cannot classify as safe
	// or state-altering (a plugin, a future kubectl verb, or a gap in the lists) is
	// normally allowed — "unknown ⇒ allowed". On a PROTECTED target that is the
	// wrong default: the guard cannot prove the command is safe, so unknown_verb:
	// gate/deny makes it fail toward gating. unknownStrict makes such a verb skip
	// the read-only early return so its target's protection is evaluated; on an
	// unprotected target it still falls through to Allow below.
	unknownStrict := cfg.UnknownVerbMode() != config.UnknownVerbAllow && IsUnknownCommand(cfg, args)

	stateAltering := IsStateAlteringWith(cfg, args)
	if !stateAltering && !sensitiveActive && !blastActive && !sensitiveKindActive && !unknownStrict {
		return Allow, ctx, cfg, nil
	}

	// The target namespace comes from --namespace/-n, then the namespace baked
	// into the resolved context, then kubectl's "default". --all-namespaces/-A
	// spans every namespace, so it is gated when any namespace is protected
	// (like "get all" spans resources). Evaluated for state-altering verbs, and
	// for an unknown verb under a strict policy (so its namespace is checked too).
	namespaceProtected := false
	if stateAltering || unknownStrict {
		namespaceProtected = namespaceTargetProtected(cfg, p, ctx, inClusterNamespace, nsFor)
	}

	// An unknown verb is only gated/denied when the target is actually protected;
	// on an unprotected target it passes (plugins keep working elsewhere).
	unknownProtected := unknownStrict && (contextProtected || namespaceProtected)
	if unknownProtected && cfg.UnknownVerbMode() == config.UnknownVerbDeny {
		return Deny, ctx, cfg, fmt.Errorf(
			"unrecognized verb %q on a protected target and unknown_verb=deny; refusing (classify it with `config command-override`, or set unknown_verb: gate)",
			LeadingVerb(args))
	}

	if contextProtected || namespaceProtected || sensitiveActive || blastActive || sensitiveKindActive {
		// Per-pattern + per-actor modes. The base modes come from the matched
		// context/namespace PATTERN (EffectiveContextMode / EffectiveNamespaceMode);
		// a matching actor policy can then make them STRICTER (confirm → block) for a
		// known actor, but never weaker than the per-pattern/global posture.
		actor := resolveActor(cfg, currentUser())
		runNS := resolveTargetNamespace(cfg, p, ctx, inClusterNamespace, nsFor)
		// ctxMode: per-pattern mode for the matched context, tightened by the actor
		// policy. nsActorMode: the run-in namespace's per-pattern mode, tightened by
		// the actor policy — its ONLY role here is to carry the actor's unconditional
		// namespace tightening (block regardless of which namespace), because the
		// authoritative per-pattern namespace mode across ALL target routes (-A, a
		// namespace named as the object, or the run-in namespace) is computed by
		// effectiveNamespaceModeForTarget and unioned in below.
		ctxMode, nsActorMode := cfg.EffectiveModesForActor(actor, ctx, runNS)
		nsBlock := nsActorMode == config.NamespaceModeBlock ||
			effectiveNamespaceModeForTarget(cfg, p, runNS) == config.NamespaceModeBlock

		// A protected-cluster match blocks when its OWN effective mode is block
		// (EffectiveClusterMode: the per-entry mode, or the global context mode when
		// the entry inherits). This is kept separate from the name arm below: for a
		// cluster-ONLY match the name-derived ctxMode is just the global fallback, so
		// folding it into the name arm would escalate a per-entry `mode: confirm`
		// cluster to block under global context_mode: block. Using EffectiveClusterMode
		// honors the entry's own mode. Most-restrictive across name + cluster wins.
		clusterBlock := clusterProtected && cfg.EffectiveClusterMode(targetServer) == config.ContextModeBlock

		// Block mode: hard-refuse with no prompt. If ANY matching signal is in
		// block mode, block wins (most restrictive). --yes cannot bypass this: it
		// only auto-confirms RequireConfirmation, and Blocked is a separate result.
		// The name arm uses nameProtected (not contextProtected) so a cluster-only
		// match does not borrow the name's global-fallback ctxMode.
		if (nameProtected && ctxMode == config.ContextModeBlock) || clusterBlock ||
			(namespaceProtected && nsBlock) ||
			(sensitiveActive && cfg.SensitiveAccessMode() == config.SensitiveAccessBlock) ||
			(blastActive && cfg.BlastRadiusMode() == config.BlastRadiusBlock) ||
			(sensitiveKindActive && cfg.SensitiveKindMode() == config.SensitiveKindBlock) {
			return Blocked, ctx, cfg, nil
		}
		return RequireConfirmation, ctx, cfg, nil
	}

	return Allow, ctx, cfg, nil
}

// commandVerb returns the lower-cased kubectl verb the guard resolves for args,
// or "" when none is found. It is a thin wrapper over ExtractCommand for callers
// that only need the verb.
func commandVerb(args []string) string {
	cmd, _ := ExtractCommand(args)
	return cmd
}

// IsSensitiveAccess reports whether the sensitive-access policy applies to args
// under cfg (the policy is enabled and the verb is in the sensitive set). Used by
// user-facing messages so a sensitive-access gate is named as such rather than as
// a protected context.
func IsSensitiveAccess(cfg *config.Config, args []string) bool {
	if cfg == nil {
		return false
	}
	return cfg.SensitiveAccessMode() != config.SensitiveAccessOff && cfg.IsSensitiveVerb(commandVerb(args))
}

// ClusterProtected reports whether the command's target context resolves to an
// API server matched by protected_clusters, returning the resolved server. It is
// for the message/explain layer so a cluster-driven gate can be named as such. It
// reads the kubeconfig to resolve the server (like ResolvedTargetNamespace), so
// it is for the gated/interactive path only, never the hot read path. It returns
// ("", false) when no cluster protection is configured or the server cannot be
// resolved — matching the decision core's additive, resolve-only-when-configured
// behavior, so it can never claim a gate the core did not make.
func ClusterProtected(cfg *config.Config, args []string, ctx string) (server string, protected bool) {
	if cfg == nil || !cfg.HasProtectedClusters() {
		return "", false
	}
	p := ParseArgs(args)
	srv, err := defaultServerForContext(p.Kubeconfig, ctx)
	if err != nil || srv == "" {
		return "", false
	}
	if cfg.IsClusterProtected(srv) {
		return srv, true
	}
	return "", false
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
func namespaceTargetProtected(cfg namespaceChecker, p ParsedArgs, ctx, fallbackNS string, nsFor NamespaceForContextFunc) bool {
	if p.AllNamespaces && cfg.HasProtectedNamespaces() {
		return true
	}
	if _, ok := protectedNamespaceNameTarget(cfg, p); ok {
		return true
	}
	return cfg.IsNamespaceProtected(resolveTargetNamespace(cfg, p, ctx, fallbackNS, nsFor))
}

// effectiveNamespaceModeForTarget returns the MOST RESTRICTIVE per-pattern
// namespace mode across every route by which the command targets a PROTECTED
// namespace — mirroring namespaceTargetProtected's three routes so the mode and
// the "is it protected?" decision can never disagree:
//
//  1. --all-namespaces spans every namespace → most restrictive over ALL patterns
//     (MostRestrictiveNamespaceMode), because the command touches each of them;
//  2. a namespace addressed as the command's OBJECT (`delete namespace kube-system`)
//     → that namespace's EffectiveNamespaceMode (a wide/unenumerable object target
//     → all patterns, same as route 1);
//  3. the namespace the command runs IN (runNS) → its EffectiveNamespaceMode.
//
// It returns block if ANY protected route resolves to block, else confirm. Only a
// PROTECTED namespace contributes (guarded by IsNamespaceProtected), so an
// unprotected run-in namespace does not fold the global mode in. Actor-policy
// tightening is applied by the caller (it is unconditional, so it composes as a
// union with this result). runNS is precomputed by the caller to avoid a repeated
// context-namespace lookup.
func effectiveNamespaceModeForTarget(cfg *config.Config, p ParsedArgs, runNS string) string {
	isBlock := func(m string) bool { return m == config.NamespaceModeBlock }
	if p.AllNamespaces && cfg.HasProtectedNamespaces() && isBlock(cfg.MostRestrictiveNamespaceMode()) {
		return config.NamespaceModeBlock
	}
	if t := namespaceTargetsFrom(p); t.Kind && cfg.HasProtectedNamespaces() {
		if t.Wide {
			if isBlock(cfg.MostRestrictiveNamespaceMode()) {
				return config.NamespaceModeBlock
			}
		} else {
			for _, name := range t.Names {
				if cfg.IsNamespaceProtected(name) && isBlock(cfg.EffectiveNamespaceMode(name)) {
					return config.NamespaceModeBlock
				}
			}
		}
	}
	if cfg.IsNamespaceProtected(runNS) && isBlock(cfg.EffectiveNamespaceMode(runNS)) {
		return config.NamespaceModeBlock
	}
	return config.NamespaceModeConfirm
}

// EffectiveTargetModes returns the actor-effective context and namespace
// protection modes the guard's block decision used for a command: the per-pattern
// context mode for the resolved context, and the most-restrictive per-pattern
// namespace mode across every target route, each tightened by the matching actor
// policy. It is for the message/explain layer (labeling a Blocked or gated
// decision) and may shell out for namespace resolution, so it is for the gated
// path only, never the hot read path. cfg==nil yields the safe confirm defaults.
func EffectiveTargetModes(cfg *config.Config, args []string, ctx string) (ctxMode, nsMode string) {
	if cfg == nil {
		return config.ContextModeConfirm, config.NamespaceModeConfirm
	}
	p := ParseArgs(args)
	fallbackNS := ""
	if saNS, inCl := defaultInCluster(); inCl {
		fallbackNS = saNS
	}
	runNS := resolveTargetNamespace(cfg, p, ctx, fallbackNS, defaultContextNamespace)
	actor := resolveActor(cfg, currentUser())
	cm, nsActorMode := cfg.EffectiveModesForActor(actor, ctx, runNS)
	nsMode = config.NamespaceModeConfirm
	if nsActorMode == config.NamespaceModeBlock ||
		effectiveNamespaceModeForTarget(cfg, p, runNS) == config.NamespaceModeBlock {
		nsMode = config.NamespaceModeBlock
	}
	return cm, nsMode
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
//
// fallbackNS is the namespace used when neither an explicit -n nor the context's
// baked-in namespace resolves: "default" out-of-cluster, or the serviceaccount
// namespace in-cluster (namespace mode), where a command with no -n runs in the
// pod's namespace rather than "default".
func resolveTargetNamespace(cfg namespaceChecker, p ParsedArgs, ctx, fallbackNS string, nsFor NamespaceForContextFunc) string {
	if p.HasNamespace && p.Namespace != "" {
		return p.Namespace
	}
	if cfg.HasProtectedNamespaces() && nsFor != nil {
		if ns, err := nsFor(p.Kubeconfig, ctx); err == nil && ns != "" {
			return ns
		}
	}
	if fallbackNS != "" {
		return fallbackNS
	}
	return "default"
}

// ResolvedTargetNamespace returns the namespace a command targets, applying the
// same resolution the guard decision used (--namespace/-n, then the context's
// baked-in namespace, then the serviceaccount namespace in-cluster, then
// "default"). It is used for user-facing messages so they name the namespace that
// actually triggered gating. It may shell out for the context lookup and reads
// the in-cluster signal, so callers should use it only on the (interactive) gated
// path, not the hot read path.
func ResolvedTargetNamespace(cfg *config.Config, args []string, ctx string) string {
	fallbackNS := ""
	if saNS, inCluster := defaultInCluster(); inCluster {
		fallbackNS = saNS
	}
	return resolveTargetNamespace(cfg, ParseArgs(args), ctx, fallbackNS, defaultContextNamespace)
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

	// execReplace is platform-specific: on unix it is syscall.Exec (process
	// replacement, preserving kubectl's exit code); on native Windows — an
	// explicit non-goal (see README "Platform support") — it returns an error
	// (Windows has no execve). The binary short-circuits with a WSL2 message on
	// GOOS=windows before reaching here, so the Windows stub is a belt-and-braces.
	return execReplace(kubectl, fullArgs, os.Environ())
}

// ExecKubectlPath replaces this process with an already-resolved kubectl path.
// Approval flows use this to avoid a second mutable PATH lookup after authentication.
func ExecKubectlPath(path string, args []string) error {
	return execReplace(path, append([]string{"kubectl"}, args...), os.Environ())
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

// DefaultShimDir returns the PATH-shadowing shim directory that
// `make install-shim` creates: $HOME/.local/share/kubectl-guard/shims. It
// mirrors the Makefile's SHIM_DIR default so `kubectl-guard uninstall` removes
// exactly what the installer put there.
func DefaultShimDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "kubectl-guard", "shims"), nil
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

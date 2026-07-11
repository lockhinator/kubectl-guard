package config

import (
	"fmt"
	"math"
)

// auditRetention estimates the maximum bytes of audit history a config keeps:
// the per-file size cap times the number of archives. Unbounded (audit_max_size_mb
// of 0, no rotation) keeps everything, modeled as the maximum value so that any
// finite cap counts as less. Used to detect a reduction in audit retention.
func auditRetention(c *Config) int64 {
	if c.AuditMaxSizeMB <= 0 {
		return math.MaxInt64
	}
	return int64(c.AuditMaxSizeMB) * int64(c.AuditMaxFilesOrDefault())
}

// WeakensProtection compares an old and a new config and returns a human-readable
// description of every change that REDUCES the guard's protection: a removed
// protected target, a downgraded mode, a disabled guard, an un-gated verb, a
// removed/weakened actor policy, or reduced audit coverage. An empty result means
// the change is additive, neutral, or strengthens protection.
//
// It is the classifier behind `require_confirm_weakening` (gate weakening
// changes) and the config-change audit reason. A change is judged purely by
// comparing the two configs, so it is agnostic to which subcommand produced it.
func WeakensProtection(old, new *Config) []string {
	if old == nil || new == nil {
		return nil
	}
	var w []string

	// Removed protected targets — the headline weakening.
	w = append(w, removedEach("removed protected context", old.ProtectedContexts, new.ProtectedContexts)...)
	w = append(w, removedEach("removed protected resource", old.ProtectedResources, new.ProtectedResources)...)
	w = append(w, removedEach("removed protected namespace", old.ProtectedNamespaces, new.ProtectedNamespaces)...)
	w = append(w, removedEach("removed sensitive kind", old.SensitiveKinds, new.SensitiveKinds)...)

	// Mode downgrades (a lower strength rank is weaker).
	w = weakerMode(w, "context_mode", contextModeRank, old.effectiveContextMode(), new.effectiveContextMode())
	w = weakerMode(w, "namespace_mode", namespaceModeRank, old.effectiveNamespaceMode(), new.effectiveNamespaceMode())
	w = weakerMode(w, "sensitive_access", sensitiveAccessRank, old.SensitiveAccessMode(), new.SensitiveAccessMode())
	w = weakerMode(w, "blast_radius", blastRadiusRank, old.BlastRadiusMode(), new.BlastRadiusMode())
	w = weakerMode(w, "sensitive_kind_mode", sensitiveKindRank, old.SensitiveKindMode(), new.SensitiveKindMode())
	w = weakerMode(w, "unknown_verb", unknownVerbRank, old.UnknownVerbMode(), new.UnknownVerbMode())
	w = weakerMode(w, "audit_mode", auditModeRank, auditModeOrDefault(old.AuditMode), auditModeOrDefault(new.AuditMode))
	w = weakerMode(w, "in_cluster", inClusterRank, old.InClusterMode(), new.InClusterMode())

	// confirm_mode: type-name (must type the name) → simple (y/N) is easier to
	// satisfy, so it is a downgrade. type-name → agent-relay is a different axis
	// (it relays for external confirmation, it does not auto-approve), so it is not
	// treated as weaker.
	if old.ConfirmMode == ConfirmModeTypeName && new.ConfirmMode == ConfirmModeSimple {
		w = append(w, "downgraded confirm_mode from type-name to simple")
	}

	// Disabled guards / reduced audit coverage.
	if old.ReadOnly && !new.ReadOnly {
		w = append(w, "disabled read_only (unfreeze)")
	}
	if old.BlockImpersonation && !new.BlockImpersonation {
		w = append(w, "disabled block_impersonation")
	}
	if old.RequireConfirmWeakening && !new.RequireConfirmWeakening {
		w = append(w, "disabled require_confirm_weakening")
	}
	if old.RequireJustification && !new.RequireJustification {
		w = append(w, "disabled require_justification")
	}
	if old.AuditSyslog && !new.AuditSyslog {
		w = append(w, "disabled audit_syslog shipping")
	}
	if old.AuditHMACKeyFile != "" && new.AuditHMACKeyFile == "" {
		w = append(w, "removed audit_hmac_key_file (audit chain no longer forgery-resistant)")
	}
	// A configured webhook that is CLEARED or REDIRECTED (to a different, possibly
	// dead/attacker endpoint) defeats audit shipping — a redirect is stealthier
	// than clearing (a URL still appears set), so any change away from the current
	// one is weakening. Setting a webhook for the first time (empty → set) is not.
	if old.AuditWebhookURL != "" && new.AuditWebhookURL != old.AuditWebhookURL {
		w = append(w, "changed or removed audit_webhook_url shipping")
	}
	// A reduction in audit-log retention evicts audit history faster — whether by
	// shrinking an existing cap OR by introducing a tight cap where the log was
	// previously unbounded (0 → 1 MB / 1 archive rapidly evicts everything). Model
	// unbounded (audit_max_size_mb: 0) as infinite retention and flag any decrease;
	// enlarging the cap or disabling rotation (→ unbounded) is not a reduction.
	if auditRetention(new) < auditRetention(old) {
		w = append(w, "reduced audit-log retention (rotation size/archive count)")
	}
	if old.ShouldDiscoverShortNames() && !new.ShouldDiscoverShortNames() {
		w = append(w, "disabled discover_short_names (fewer resources matched)")
	}

	// command_overrides: a NEW `safe` entry downgrades a verb to pass-through; a
	// REMOVED state_altering/unsafe_safe entry un-gates a verb.
	for _, v := range addedEach(old.CommandOverrides.Safe, new.CommandOverrides.Safe) {
		w = append(w, "marked verb safe (pass-through): "+v)
	}
	for _, v := range removedEach2(old.CommandOverrides.StateAltering, new.CommandOverrides.StateAltering) {
		w = append(w, "un-gated verb (removed from state_altering): "+v)
	}
	for _, v := range removedEach2(old.CommandOverrides.UnsafeSafe, new.CommandOverrides.UnsafeSafe) {
		w = append(w, "un-gated verb (removed from unsafe_safe): "+v)
	}

	// actor_policies: a removed policy, or one whose mode was downgraded from block.
	w = append(w, weakenedActorPolicies(old.ActorPolicies, new.ActorPolicies)...)

	return w
}

// auditModeOrDefault fills the empty audit mode with its default for comparison.
func auditModeOrDefault(m string) string {
	if m == "" {
		return AuditModeAll
	}
	return m
}

// Strength ranks: a higher number is stronger protection. A drop is a weakening.
var (
	contextModeRank     = map[string]int{ContextModeConfirm: 1, ContextModeBlock: 2}
	namespaceModeRank   = map[string]int{NamespaceModeConfirm: 1, NamespaceModeBlock: 2}
	sensitiveAccessRank = map[string]int{SensitiveAccessOff: 1, SensitiveAccessGate: 2, SensitiveAccessBlock: 3}
	blastRadiusRank     = map[string]int{BlastRadiusOff: 1, BlastRadiusGate: 2, BlastRadiusBlock: 3}
	sensitiveKindRank   = map[string]int{SensitiveKindOff: 1, SensitiveKindConfirm: 2, SensitiveKindBlock: 3}
	unknownVerbRank     = map[string]int{UnknownVerbAllow: 1, UnknownVerbGate: 2, UnknownVerbDeny: 3}
	auditModeRank       = map[string]int{AuditModeOff: 1, AuditModeGated: 2, AuditModeAll: 3}
	inClusterRank       = map[string]int{InClusterAllow: 1, InClusterNamespace: 2, InClusterDeny: 3}
)

// weakerMode appends a description when new's rank is below old's for the field.
func weakerMode(w []string, field string, rank map[string]int, oldV, newV string) []string {
	if rank[newV] < rank[oldV] {
		return append(w, fmt.Sprintf("downgraded %s from %q to %q", field, oldV, newV))
	}
	return w
}

// removedEach returns "<label>: x" for every item in old missing from new.
func removedEach(label string, old, new []string) []string {
	var out []string
	for _, x := range removedEach2(old, new) {
		out = append(out, label+": "+x)
	}
	return out
}

// removedEach2 returns the items present in old but not in new (exact match).
func removedEach2(old, new []string) []string {
	present := make(map[string]bool, len(new))
	for _, x := range new {
		present[x] = true
	}
	var out []string
	for _, x := range old {
		if !present[x] {
			out = append(out, x)
		}
	}
	return out
}

// addedEach returns the items present in new but not in old (exact match).
func addedEach(old, new []string) []string {
	return removedEach2(new, old)
}

// weakenedActorPolicies reports removed policies and per-actor mode downgrades.
func weakenedActorPolicies(old, new []ActorPolicy) []string {
	newByActor := make(map[string]ActorPolicy, len(new))
	for _, p := range new {
		newByActor[p.Actor] = p
	}
	var w []string
	for _, o := range old {
		n, ok := newByActor[o.Actor]
		if !ok {
			w = append(w, "removed actor policy for "+o.Actor)
			continue
		}
		if o.ContextMode == ContextModeBlock && n.ContextMode != ContextModeBlock {
			w = append(w, fmt.Sprintf("downgraded actor %s context_mode from block", o.Actor))
		}
		if o.NamespaceMode == NamespaceModeBlock && n.NamespaceMode != NamespaceModeBlock {
			w = append(w, fmt.Sprintf("downgraded actor %s namespace_mode from block", o.Actor))
		}
	}
	return w
}

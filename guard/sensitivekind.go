package guard

import (
	"strings"

	"github.com/lockhinator/kubectl-guard/config"
)

// sensitiveKindChecker adapts a config's sensitive_kinds to the
// ProtectedResourceChecker interface, so the shared -f manifest kind scanner
// (pathContainsProtectedKind) can be reused to match a manifest's kind against
// the sensitive list instead of the protected-resource list.
type sensitiveKindChecker struct{ cfg *config.Config }

func (s sensitiveKindChecker) HasProtectedResources() bool { return s.cfg.HasSensitiveKinds() }
func (s sensitiveKindChecker) IsResourceProtected(candidate string) bool {
	return s.cfg.IsSensitiveKind(candidate)
}

// IsSensitiveKindActive reports whether args are a STATE-ALTERING command whose
// target kind (a resource token or an inspectable -f manifest kind) matches a
// configured sensitive kind, with the policy on. This is the middle protection
// tier: it gates mutations to a kind on EVERY context while leaving reads alone.
//
// It uses the built-in IsStateAltering (not the config-aware form) so a
// command_overrides.safe downgrade cannot slip a mutation past a sensitive-kind
// BLOCK — consistent with blast-radius and "block is un-bypassable".
//
// Unlike MatchesProtectedResource it does NOT conservatively match --raw or an
// un-inspectable source: those block-everything semantics belong to
// protected_resources (which forbids all access to a kind), whereas this tier
// only gates a mutation whose target kind is actually known to match — otherwise
// setting any sensitive kind would gate every `apply -f -`.
func IsSensitiveKindActive(cfg *config.Config, args []string) bool {
	if cfg == nil || cfg.SensitiveKindMode() == config.SensitiveKindOff || !cfg.HasSensitiveKinds() {
		return false
	}
	if !IsStateAltering(args) {
		return false
	}
	return commandTargetsSensitiveKind(cfg, args)
}

// commandTargetsSensitiveKind reports whether the command's target kind — from a
// resource token (before the "--" separator) or an inspectable -f manifest —
// matches a configured sensitive kind.
func commandTargetsSensitiveKind(cfg *config.Config, args []string) bool {
	p := ParseArgs(args)
	// cordon/uncordon/drain address a NODE by bare name with no "node" token —
	// the canonical node-maintenance mutations an operator adds this policy to
	// guard — so they have no resource token to match. Recognize them explicitly
	// against a sensitive "node" kind (reusing the same nodeTargetVerbs set the
	// preview path uses for the implicit node type).
	if verb, _ := ExtractCommand(args); nodeTargetVerbs[verb] && cfg.IsSensitiveKind("node") {
		return true
	}
	for i, cand := range p.ResourceCandidates() {
		// ResourceCandidates is Positional[1:], so candidate i is at
		// Positional[i+1]; tokens at or past "--" are payload, not resource tokens.
		if i+1 >= p.PositionalsBeforeSep {
			continue
		}
		for _, part := range strings.Split(cand, ",") {
			part = strings.TrimSpace(part)
			if part != "" && cfg.IsSensitiveKind(part) {
				return true
			}
		}
	}
	checker := sensitiveKindChecker{cfg}
	for _, f := range p.InspectableFilenames() {
		if pathContainsProtectedKind(f, checker) {
			return true
		}
	}
	return false
}

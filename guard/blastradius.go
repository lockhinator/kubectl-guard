package guard

import (
	"strconv"
	"strings"

	"github.com/lockhinator/kubectl-guard/config"
)

// bulkMutationVerbs are the state-altering verbs where a wide-scope selector
// (--all, -l/--selector/--field-selector, --all-namespaces) picks which EXISTING
// objects to mutate, so one command hits many live objects at once. Membership is
// exactly the verbs that accept such a flag for LIVE-object selection, verified
// against `kubectl <verb> --help` (v1.33).
//
// Deliberately EXCLUDED (each would be a false positive):
//   - the pure-access verbs (exec/cp/attach/debug/port-forward/proxy/certificate)
//     act on a single target and take no such selector;
//   - `expose`/`run` CREATE one object and use -l/--labels/--selector to label the
//     NEW object, not to fan out over existing ones;
//   - `apply`/`replace` operate on a MANIFEST: a bare -l/--all there NARROWS which
//     manifest objects apply (a subset of a plain `apply -f`, which is not gated),
//     so gating it is backwards. apply's genuinely-wide forms — `--prune` (deletes
//     live resources absent from the manifest) and `--force` (delete-and-recreate)
//     — are caught by BlastRadius before this set is consulted;
//   - `patch`/`autoscale`/`edit` take no -l/--all at all (kubectl rejects them).
//
// `rollout` restart/undo/pause/resume take -l/--selector and act on every matching
// workload — a mass, disruptive mutation; its read-only subcommands (status/
// history) are not state-altering, so IsStateAltering excludes them before this
// set is consulted.
var bulkMutationVerbs = map[string]bool{
	"delete": true, "label": true, "annotate": true, "scale": true,
	"taint": true, "drain": true, "cordon": true, "uncordon": true,
	"set": true, "rollout": true,
}

// BlastRadius classifies whether a command is a wide-scope / high-blast-radius
// mutation whose danger comes from HOW MUCH it changes, independent of WHERE it
// runs. It returns the widest matching signal's human-readable reason, or an
// empty reason when the command is not wide-scope.
//
// Read-only commands are never wide (a `get pods --all-namespaces` reads a lot
// but destroys nothing). A genuine dry-run is filtered out by the caller (the
// guard's dry-run skip runs before the blast-radius gate), because a dry-run
// changes nothing regardless of scope.
func BlastRadius(args []string) (wide bool, reason string) {
	if !IsStateAltering(args) {
		return false, ""
	}
	p := ParseArgs(args)
	verb, _ := ExtractCommand(args)

	// apply --prune deletes any live resource (within the selector/allowlist) that
	// is absent from the manifest — the widest possible delete.
	if verb == "apply" && p.Prune {
		return true, "apply --prune deletes any live resource not present in the manifest"
	}

	// Force deletion skips graceful termination (immediate removal), risking data
	// loss for stateful workloads; on apply/replace, --force deletes and recreates
	// the object rather than patching it.
	if isForceDelete(verb, p) {
		if verb == "delete" {
			return true, "--force / --grace-period=0 skips graceful termination (immediate deletion)"
		}
		return true, "--force deletes and recreates the resource instead of patching it"
	}

	if bulkMutationVerbs[verb] {
		switch {
		case p.AllNamespaces:
			return true, "--all-namespaces spans every namespace"
		case p.All:
			return true, "--all targets every object of the type in the namespace"
		case p.HasSelector:
			return true, "a label/field selector can match many objects at once"
		}
	}
	return false, ""
}

// isForceDelete reports whether the command is a force/immediate deletion (for
// delete: --force, or --grace-period=0) or a force delete-and-recreate (for
// apply/replace: --force). --grace-period=0 requires --force on real kubectl, but
// the guard treats a bare grace-period=0 as a force intent too (fail-safe).
func isForceDelete(verb string, p ParsedArgs) bool {
	switch verb {
	case "delete":
		if p.Force {
			return true
		}
		if p.HasGracePeriod {
			if n, err := strconv.Atoi(strings.TrimSpace(p.GracePeriod)); err == nil && n == 0 {
				return true
			}
		}
		return false
	case "apply", "replace":
		return p.Force
	}
	return false
}

// IsBlastRadiusActive reports whether the blast-radius policy is enabled (gate or
// block) and the command is a wide-scope mutation the policy applies to.
func IsBlastRadiusActive(cfg *config.Config, args []string) bool {
	if cfg == nil || cfg.BlastRadiusMode() == config.BlastRadiusOff {
		return false
	}
	wide, _ := BlastRadius(args)
	return wide
}

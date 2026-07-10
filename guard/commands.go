package guard

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/lockhinator/kubectl-guard/config"
)

// safeCommands are read-only top-level commands that don't modify cluster
// state and have no subcommand nuance.
var safeCommands = map[string]bool{
	"get":           true,
	"describe":      true,
	"logs":          true,
	"top":           true,
	"explain":       true,
	"api-resources": true,
	"api-versions":  true,
	"version":       true,
	"cluster-info":  true,
	"wait":          true,
	"diff":          true,
}

// stateAlteringCommands are the gated verbs: they require confirmation on
// protected contexts/namespaces (or are refused in block mode).
//
// Most mutate cluster state in the CRUD sense. The rest are high-risk *access*
// vectors that mutate nothing but hand the caller a live channel into the
// cluster with the caller's credentials — exec/attach/cp into a running pod,
// and port-forward/proxy, which open a tunnel to a production workload or
// expose the whole API server locally. The guard's premise is gating production
// access, not just production writes, so these gate too.
var stateAlteringCommands = map[string]bool{
	"apply":        true,
	"create":       true,
	"delete":       true,
	"patch":        true,
	"replace":      true,
	"edit":         true,
	"scale":        true,
	"autoscale":    true,
	"expose":       true,
	"run":          true,
	"set":          true,
	"label":        true,
	"annotate":     true,
	"taint":        true,
	"drain":        true,
	"cordon":       true,
	"uncordon":     true,
	"exec":         true,
	"cp":           true,
	"debug":        true,
	"attach":       true,
	"port-forward": true,
	"proxy":        true,
	// certificate approve/deny issues or refuses a client certificate — a
	// credential-issuance and privilege-escalation primitive, not a read.
	"certificate": true,
}

// noDryRunCommands are gated verbs that kubectl gives no --dry-run flag.
// A dry-run of a gated command normally skips context/namespace gating because
// it changes nothing; for these verbs there is no such thing as a dry run, so a
// --dry-run token on the command line must not be allowed to skip gating.
//
// Today kubectl rejects the unknown flag, so nothing would run anyway — but the
// guard must not depend on kubectl's flag validation to stay closed.
// Membership verified against `kubectl <verb> --help` (v1.33).
var noDryRunCommands = map[string]bool{
	"exec": true, "cp": true, "attach": true, "debug": true,
	"port-forward": true, "proxy": true, "edit": true, "config": true,
	"certificate": true,
}

// noDryRunSubcommands is noDryRunCommands at subcommand granularity, for verbs
// where support is mixed. `rollout undo` really does take --dry-run; its
// siblings restart/pause/resume do not, so only those are excluded.
var noDryRunSubcommands = map[string]map[string]bool{
	"rollout": {"restart": true, "pause": true, "resume": true},
}

// SupportsDryRun reports whether the command's verb has a meaningful --dry-run.
// Callers use it to decide whether a --dry-run flag may skip gating. Verbs with
// no such flag can never be dry-run, so they must always gate.
func SupportsDryRun(args []string) bool {
	cmd, subCmd := ExtractCommand(args)
	if subs, ok := noDryRunSubcommands[cmd]; ok {
		return !subs[strings.ToLower(subCmd)]
	}
	return !noDryRunCommands[cmd]
}

// safeSubcommands maps a command to the subset of its subcommands that are
// read-only. Any other subcommand of these commands is treated as
// state-altering. A bare invocation (no subcommand) only prints help and is
// treated as safe.
//
// Notably this makes kubectl "config use-context" and "auth reconcile"
// state-altering, while keeping "config view"/"config get-contexts" and
// "auth can-i" read-only.
var safeSubcommands = map[string]map[string]bool{
	"rollout": {"status": true, "history": true},
	"config":  {"view": true, "get-contexts": true, "current-context": true},
	"auth":    {"can-i": true, "whoami": true},
}

// shortTakesValue lists single-letter kubectl flags that consume a value
// (the rest of the token, or the next argument). f and k are manifest sources
// handled specially by parseShortCluster. Every other short flag is treated as
// boolean. This replaces the old exact-match knownShortFlags set, which could
// not recognize clustered flags like "-Rf" or "-nf" (the G1 gap).
//
// 'v' is kubectl's global verbosity shorthand (-v 3). It MUST be here: if its
// value is not consumed, "3" lands in verb position and a gated verb after it
// is never seen (the S3 verb-shift bypass).
var shortTakesValue = map[byte]bool{
	'n': true, 'l': true, 'o': true, 'c': true, 's': true, 'p': true, 'v': true,
}

// knownLongFlags are kubectl long flags that take a separate value
// (not --flag=value style). --context/--kubeconfig/--filename/--kustomize and
// the identity flags (--as*, --token, --server, --namespace) are handled
// explicitly in ParseArgs and intentionally omitted here.
//
// This set must be a superset of kubectl's global (persistent) value-taking
// flags, because those are the only flags that may legally precede the verb.
// Any such flag missing here leaves its value in verb position, hiding the real
// verb from classification and silently failing open (the S3 verb-shift
// bypass). kubectl's four boolean globals — --disable-compression,
// --insecure-skip-tls-verify, --match-server-version, --warnings-as-errors —
// consume no value and must NOT be listed, or they would swallow the verb.
// Verified against `kubectl options` (v1.33).
var knownLongFlags = map[string]bool{
	// Command-scoped value flags.
	"--selector": true, "--output": true, "--container": true,
	// kubectl global (persistent) value-taking flags.
	"--cluster": true, "--user": true, "--username": true, "--password": true,
	"--cache-dir": true, "--certificate-authority": true,
	"--client-certificate": true, "--client-key": true,
	"--tls-server-name": true, "--request-timeout": true,
	"--profile": true, "--profile-output": true,
	"--v": true, "--vmodule": true, "--log-flush-frequency": true,
	// Command-scoped value flags that carry SECRET material. These must be
	// consumed here, not merely redacted by RedactCommand: an unconsumed value
	// lands in the positional stream, where GetCommandDescription (the confirm
	// prompt) and JSONForResult's "resource" field would print it verbatim,
	// never having passed through the redactor.
	"--patch": true, "--overrides": true, "--exec-arg": true,
	"--from-literal": true, "--env": true, "--exec-env": true,
	"--auth-provider-arg": true, "--docker-password": true,
	"--docker-email": true, "--tls-private-key": true,
}

// recognizedVerb reports whether v is a kubectl verb the guard can classify.
func recognizedVerb(v string) bool {
	if _, ok := safeSubcommands[v]; ok {
		return true
	}
	return safeCommands[v] || stateAlteringCommands[v]
}

// verbPositionalIndex returns the index into pos of the verb the guard resolves,
// or -1 when no positional is a recognized verb. It is the single source of
// truth for "which positional is the verb", so that every consumer agrees.
//
// Normally that is pos[0]. When pos[0] is unrecognized the guard scans forward
// (see ExtractCommand): a global flag whose value it failed to consume can leave
// that value sitting in verb position. Any caller that indexes positionals
// RELATIVE to the verb must use this, not a hardcoded 0 — otherwise it reads the
// wrong tokens exactly when the fallback fires.
func verbPositionalIndex(pos []string) int {
	if len(pos) == 0 {
		return -1
	}
	if recognizedVerb(strings.ToLower(pos[0])) {
		return 0
	}
	for i := 1; i < len(pos); i++ {
		if recognizedVerb(strings.ToLower(pos[i])) {
			return i
		}
	}
	return -1
}

// ProtectedResourceChecker is satisfied by *config.Config; kept as an interface
// so command classification stays testable without shelling out.
type ProtectedResourceChecker interface {
	IsResourceProtected(candidate string) bool
	HasProtectedResources() bool
}

// ParsedArgs is the single, consistent view of a kubectl argument list. All
// extraction (command, resources, context, filenames) derives from one
// ParseArgs pass so the pieces can never disagree about flag boundaries or
// the "--" separator.
type ParsedArgs struct {
	Positional      []string
	Context         string // value of --context
	Kubeconfig      string // value of --kubeconfig
	Filenames       []string
	Kustomize       string // value of -k / --kustomize
	ExplicitContext bool
	// VerbIndex is the index of the kubectl verb (first positional) in the
	// original args, or -1 if none was found before the "--" separator.
	VerbIndex int

	// PositionalsBeforeSep is how many of Positional appeared before the "--"
	// separator. Everything at or past this index is a payload token (exec
	// args, a shell command), not a kubectl resource token. Positional merges
	// both, so this preserves the boundary for consumers that must distinguish
	// them — e.g. an "/etc/hosts" in an exec payload is not an API path.
	PositionalsBeforeSep int

	// PositionalIndexes[i] is the index in the original args slice of
	// Positional[i]. It lets a caller map a positional back to the token it came
	// from, without re-deriving which flags consumed a value.
	PositionalIndexes []int

	// Targeting & identity flags. --server points at a different API server
	// (a different cluster) the guard cannot map to a context; --as* impersonate
	// another identity; credentials can be overridden with --token. Captured so
	// the guard can fail closed on --server and attribute impersonation in the
	// audit log.
	Server    string // --server / -s
	HasServer bool
	// HasClusterOverride is set by --cluster, which selects a named cluster from
	// kubeconfig and thereby RETARGETS the API server the command hits — decoupled
	// from the context NAME the guard gates on. Like --server, it is refused when
	// protected contexts are configured (the guard cannot verify which cluster the
	// command actually reaches).
	HasClusterOverride bool
	AsUser             string   // --as
	AsGroups           []string // --as-group (repeatable)
	AsUID              string   // --as-uid
	HasAs              bool     // any --as / --as-group / --as-uid present
	Token              string   // --token
	HasToken           bool

	// DryRun captures --dry-run (client|server|none). A bare --dry-run is
	// treated as client. State-altering commands in dry-run mode change no
	// cluster state and skip context/namespace gating.
	DryRun    string
	HasDryRun bool

	// Namespace targeting. --namespace/-n sets an explicit namespace;
	// --all-namespaces/-A spans every namespace (gated when any namespace is
	// protected, like "get all" spans resources).
	Namespace     string
	HasNamespace  bool
	AllNamespaces bool

	// All is kubectl's --all flag: "select ALL resources of the given type in
	// the namespace". It is distinct from --all-namespaces/-A. On `delete TYPE`
	// it replaces the NAME argument, so the guard cannot enumerate what the
	// command targets. Verified against `kubectl delete --help` (v1.33): --all is
	// boolean and has no single-letter shorthand.
	All bool

	// HasSelector reports whether a selector flag was given that stands in for an
	// explicit NAME: -l/--selector (label) OR --field-selector. On
	// `delete TYPE -l label` / `delete TYPE --field-selector metadata.name=x` the
	// affected objects are chosen server-side, so they are not knowable from argv.
	HasSelector bool

	// Prune is kubectl's `apply --prune`: after applying the manifest, DELETE any
	// live resource (matching the selector/allowlist) that is not present in it.
	// It is the widest possible delete, so it is a blast-radius signal. Boolean,
	// like --all; --prune=false does not prune. Verified against
	// `kubectl apply --help` (v1.33).
	Prune bool

	// Force is kubectl's `--force`. On delete it means force/immediate deletion
	// (skip graceful termination); on apply/replace it means delete-and-recreate.
	// Boolean; --force=false is not a force operation. It is distinct from
	// --force-conflicts (server-side apply), which splitLong keeps separate.
	Force bool

	// GracePeriod captures --grace-period's value (a duration in seconds). On
	// delete, --grace-period=0 is an immediate/force deletion. HasGracePeriod
	// distinguishes an unset flag from an explicit "0".
	GracePeriod    string
	HasGracePeriod bool

	// Raw is the value of --raw: a literal API-server path, e.g.
	// "/api/v1/namespaces/default/secrets/db-creds". kubectl requests it
	// verbatim, so no resource token ever appears in the command and resource
	// protection has nothing to match against. Available on get/create/replace/
	// delete, so --raw is a write vector as well as a read one.
	Raw    string
	HasRaw bool
}

// HasImpersonation reports whether any --as / --as-group / --as-uid flag is
// set, i.e. the command impersonates another identity.
func (p ParsedArgs) HasImpersonation() bool {
	return p.HasAs
}

// IsDryRun reports whether the command runs in dry-run mode, mirroring
// kubectl's own --dry-run parsing (cmdutil.GetDryRunStrategy). Anything kubectl
// treats as a real mutation must NOT be treated as a dry-run here, or the guard
// would skip gating on a command that actually changes cluster state.
//
// kubectl parses the flag with strconv.ParseBool first: any boolean-false form
// (false/f/F/0/False/FALSE/...) means DryRunNone -> a REAL mutation. Only
// "client", "server", "unchanged" (bare --dry-run), and boolean-true forms are
// genuine dry-runs. "none" and any invalid value gate normally (kubectl rejects
// invalid values, so nothing runs anyway; failing closed is correct).
func (p ParsedArgs) IsDryRun() bool {
	if !p.HasDryRun {
		return false
	}
	if b, err := strconv.ParseBool(p.DryRun); err == nil {
		// true (client) is a dry-run; false is a real mutation.
		return b
	}
	switch strings.ToLower(p.DryRun) {
	case "client", "server", "unchanged":
		return true
	default: // "none" or an invalid value: gate normally.
		return false
	}
}

// ImpersonationString summarizes the impersonation identity (--as / --as-group
// / --as-uid) for the audit log, or "" when none is set. It combines all three
// so that group- or uid-only impersonation (e.g. --as-group=system:masters with
// no --as) is still attributed, not silently dropped.
func (p ParsedArgs) ImpersonationString() string {
	if !p.HasAs {
		return ""
	}
	var parts []string
	if p.AsUser != "" {
		parts = append(parts, p.AsUser)
	}
	for _, g := range p.AsGroups {
		parts = append(parts, "group:"+g)
	}
	if p.AsUID != "" {
		parts = append(parts, "uid:"+p.AsUID)
	}
	return strings.Join(parts, ",")
}

// ResolvedNamespace returns the namespace a command targets, for protection
// decisions. An explicit --namespace/-n wins; otherwise kubectl's default
// ("default") is assumed. (Resolving the namespace baked into a context would
// require parsing kubeconfig and is not done here.)
func (p ParsedArgs) ResolvedNamespace() string {
	if p.HasNamespace && p.Namespace != "" {
		return p.Namespace
	}
	return "default"
}

// ResourceCandidates returns the positional arguments after the verb. Any may
// be a resource type or "type/name" token.
func (p ParsedArgs) ResourceCandidates() []string {
	if len(p.Positional) <= 1 {
		return nil
	}
	return p.Positional[1:]
}

// InspectableFilenames returns -f targets we can open and scan: local files
// only (never "-" stdin or http(s) URLs).
func (p ParsedArgs) InspectableFilenames() []string {
	var out []string
	for _, f := range p.Filenames {
		if isInspectableFile(f) {
			out = append(out, f)
		}
	}
	return out
}

// HasUninspectableSource reports whether the command reads manifests from a
// source we cannot scan (stdin "-", a URL, or a kustomize directory).
func (p ParsedArgs) HasUninspectableSource() bool {
	if p.Kustomize != "" {
		return true
	}
	for _, f := range p.Filenames {
		if !isInspectableFile(f) {
			return true
		}
	}
	return false
}

func isInspectableFile(f string) bool {
	return f != "-" && !strings.HasPrefix(f, "http://") && !strings.HasPrefix(f, "https://")
}

// splitLong splits "--name" or "--name=value" into (name, value, hasInline).
func splitLong(arg string) (name, val string, hasInline bool) {
	if eq := strings.IndexByte(arg, '='); eq >= 0 {
		return arg[:eq], arg[eq+1:], true
	}
	return arg, "", false
}

// addSource records a manifest source: 'f' -> filename, 'k' -> kustomize dir.
func (p *ParsedArgs) addSource(c byte, val string) {
	if c == 'f' {
		p.Filenames = append(p.Filenames, val)
	} else {
		p.Kustomize = val
	}
}

// parseShortCluster walks a bundled short-flag token (e.g. "-Rf", "-nf",
// "-fn") the way pflag does, recording any -f/-k source it finds and reporting
// whether the next argument is consumed as a value. This closes the G1 gap
// where a clustered source flag (e.g. "apply -Rf dir") was neither recognized
// nor scanned.
//
// Walk semantics: a value-taking flag consumes the rest of the token (or the
// next argument); a boolean flag (e.g. -R) is skipped and the walk continues.
// f and k are sources whose value becomes a filename/kustomize target.
func (p *ParsedArgs) parseShortCluster(arg string, rest []string) (consumeNext bool) {
	shorthands := arg[1:] // strip leading "-"
	for len(shorthands) > 0 {
		c := shorthands[0]
		switch {
		case c == 'f' || c == 'k':
			if len(shorthands) > 1 {
				p.addSource(c, strings.TrimPrefix(shorthands[1:], "="))
				return false
			}
			if len(rest) > 0 {
				p.addSource(c, rest[0])
				return true
			}
			return false
		case c == 's':
			// -s / --server points at a different API server; capture it so the
			// guard can fail closed when context protection is configured.
			p.HasServer = true
			if len(shorthands) > 1 {
				p.Server = strings.TrimPrefix(shorthands[1:], "=")
				return false
			}
			if len(rest) > 0 {
				p.Server = rest[0]
				return true
			}
			return false
		case c == 'n':
			// -n / --namespace sets the target namespace.
			p.HasNamespace = true
			if len(shorthands) > 1 {
				p.Namespace = strings.TrimPrefix(shorthands[1:], "=")
				return false
			}
			if len(rest) > 0 {
				p.Namespace = rest[0]
				return true
			}
			return false
		case c == 'l':
			// -l / --selector stands in for a NAME argument; record that the
			// command's targets cannot be enumerated from argv. It consumes the
			// rest of the token, or the next argument.
			p.HasSelector = true
			if len(shorthands) > 1 {
				return false
			}
			return len(rest) > 0
		case shortTakesValue[c]:
			// consumes the rest of the token, or the next argument.
			if len(shorthands) > 1 {
				return false
			}
			return len(rest) > 0
		default:
			// boolean short flag. -A / --all-namespaces spans every namespace.
			if c == 'A' {
				p.AllNamespaces = true
			}
			shorthands = shorthands[1:]
		}
	}
	return false
}

// ParseArgs performs one pass over a kubectl argument list, honoring the "--"
// separator consistently for every consumer. It stops interpreting flags at
// "--", so a trailing "--context=dev" can no longer trick context resolution
// (the S1 bypass), and it stops positional collection there to match kubectl.
func ParseArgs(args []string) ParsedArgs {
	var p ParsedArgs
	p.VerbIndex = -1
	skipNext := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "--" {
			// kubectl treats everything after "--" as positional (resource names,
			// exec args, etc.). Flags stop here, so a trailing "--context=dev"
			// cannot spoof context resolution (S1); but resource tokens after
			// "--" must still be matched (H4).
			p.PositionalsBeforeSep = len(p.Positional)
			for j := i + 1; j < len(args); j++ {
				p.Positional = append(p.Positional, args[j])
				p.PositionalIndexes = append(p.PositionalIndexes, j)
			}
			return p
		}
		switch {
		case strings.HasPrefix(arg, "--"):
			name, val, hasInline := splitLong(arg)
			switch name {
			case "--context":
				p.ExplicitContext = true
				if hasInline {
					p.Context = val
				} else if i+1 < len(args) {
					p.Context = args[i+1]
					skipNext = true
				}
			case "--kubeconfig":
				if hasInline {
					p.Kubeconfig = val
				} else if i+1 < len(args) {
					p.Kubeconfig = args[i+1]
					skipNext = true
				}
			case "--filename":
				if hasInline {
					p.Filenames = append(p.Filenames, val)
				} else if i+1 < len(args) {
					p.Filenames = append(p.Filenames, args[i+1])
					skipNext = true
				}
			case "--kustomize":
				if hasInline {
					p.Kustomize = val
				} else if i+1 < len(args) {
					p.Kustomize = args[i+1]
					skipNext = true
				}
			case "--server":
				p.HasServer = true
				if hasInline {
					p.Server = val
				} else if i+1 < len(args) {
					p.Server = args[i+1]
					skipNext = true
				}
			case "--cluster":
				// --cluster retargets the API server via a named kubeconfig
				// cluster. Consume its value (like knownLongFlags did) and record
				// its presence so the guard can refuse it under protected contexts.
				p.HasClusterOverride = true
				if !hasInline && i+1 < len(args) {
					skipNext = true
				}
			case "--as":
				p.HasAs = true
				if hasInline {
					p.AsUser = val
				} else if i+1 < len(args) {
					p.AsUser = args[i+1]
					skipNext = true
				}
			case "--as-group":
				p.HasAs = true
				if hasInline {
					p.AsGroups = append(p.AsGroups, val)
				} else if i+1 < len(args) {
					p.AsGroups = append(p.AsGroups, args[i+1])
					skipNext = true
				}
			case "--as-uid":
				p.HasAs = true
				if hasInline {
					p.AsUID = val
				} else if i+1 < len(args) {
					p.AsUID = args[i+1]
					skipNext = true
				}
			case "--token":
				p.HasToken = true
				if hasInline {
					p.Token = val
				} else if i+1 < len(args) {
					p.Token = args[i+1]
					skipNext = true
				}
			case "--namespace":
				p.HasNamespace = true
				if hasInline {
					p.Namespace = val
				} else if i+1 < len(args) {
					p.Namespace = args[i+1]
					skipNext = true
				}
			case "--all-namespaces":
				// Honor an explicit boolean value: --all-namespaces=false does
				// NOT span namespaces (matches kubectl), so it must not be gated
				// as if it did. A bare --all-namespaces or a non-boolean value
				// means true.
				if hasInline {
					if b, err := strconv.ParseBool(val); err == nil {
						p.AllNamespaces = b
					} else {
						p.AllNamespaces = true
					}
				} else {
					p.AllNamespaces = true
				}
			case "--all":
				// Boolean, like --all-namespaces: it must NOT consume the next
				// argument, or a following verb would be swallowed. --all=false
				// selects nothing extra and must not be treated as wide-scope.
				if hasInline {
					if b, err := strconv.ParseBool(val); err == nil {
						p.All = b
					} else {
						p.All = true
					}
				} else {
					p.All = true
				}
			case "--prune":
				// Boolean, like --all: honor --prune=false, and never consume the
				// next argument (it would swallow a following token).
				if hasInline {
					if b, err := strconv.ParseBool(val); err == nil {
						p.Prune = b
					} else {
						p.Prune = true
					}
				} else {
					p.Prune = true
				}
			case "--force":
				// Boolean. --force=false is not a force operation.
				if hasInline {
					if b, err := strconv.ParseBool(val); err == nil {
						p.Force = b
					} else {
						p.Force = true
					}
				} else {
					p.Force = true
				}
			case "--grace-period":
				// Takes a value (seconds). Consume it in the space form so it does
				// not land in verb/resource position.
				p.HasGracePeriod = true
				if hasInline {
					p.GracePeriod = val
				} else if i+1 < len(args) {
					p.GracePeriod = args[i+1]
					skipNext = true
				}
			case "--selector", "--field-selector":
				// Both take a value and both stand in for the NAME argument:
				// `delete ns -l env=prod` and `delete ns --field-selector
				// metadata.name=kube-system` name no object positionally, so the
				// affected namespaces are chosen server-side and cannot be read off
				// argv. --field-selector must be consumed here too, or its value
				// lands in the positional stream (a verb-shift / mis-parse) AND the
				// namespace-name gate is bypassed (`delete namespace
				// --field-selector metadata.name=kube-system` targets kube-system
				// but names it nowhere the guard can check). Verified accepted on
				// `kubectl delete` (v1.33).
				p.HasSelector = true
				if !hasInline && i+1 < len(args) {
					skipNext = true
				}
			case "--raw":
				p.HasRaw = true
				if hasInline {
					p.Raw = val
				} else if i+1 < len(args) {
					p.Raw = args[i+1]
					skipNext = true
				}
			case "--dry-run":
				p.HasDryRun = true
				if hasInline {
					p.DryRun = val
				} else {
					p.DryRun = "true" // bare --dry-run behaves as client
				}
			default:
				// Other long flag: skip its value if it's a known value-taker.
				if !hasInline && knownLongFlags[arg] {
					skipNext = true
				}
			}
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			// Single-dash short flags, possibly clustered (e.g. "-Rf", "-nf").
			if p.parseShortCluster(arg, args[i+1:]) {
				skipNext = true
			}
		default:
			if p.VerbIndex < 0 {
				p.VerbIndex = i
			}
			p.Positional = append(p.Positional, arg)
			p.PositionalIndexes = append(p.PositionalIndexes, i)
		}
	}
	// No "--" separator: every positional is a kubectl token.
	p.PositionalsBeforeSep = len(p.Positional)
	return p
}

// StripGuardFlags removes guard-only flags from args and reports whether the
// --json flag was requested. These flags belong to the guard, not kubectl, and
// must never be forwarded. --json is recognized as "--json", "--json=true",
// or "--json=false" and is only honored before the "--" separator (after it,
// tokens are positional kubectl args such as exec payloads).
func StripGuardFlags(args []string) (filtered []string, jsonMode bool) {
	seenSep := false
	for _, a := range args {
		if a == "--" {
			seenSep = true
			filtered = append(filtered, a)
			continue
		}
		if !seenSep {
			switch a {
			case "--json", "--json=true":
				jsonMode = true
				continue
			case "--json=false":
				jsonMode = false
				continue
			}
		}
		filtered = append(filtered, a)
	}
	return filtered, jsonMode
}

// StripNoPrompt removes the guard-only --no-prompt flag from args and reports
// whether headless/no-prompt mode was requested. Like --json, it belongs to the
// guard and must never be forwarded to kubectl. Recognized as "--no-prompt",
// "--no-prompt=true", or "--no-prompt=false", and only before the "--"
// separator (after it, tokens are positional kubectl args).
func StripNoPrompt(args []string) (filtered []string, noPrompt bool) {
	seenSep := false
	for _, a := range args {
		if a == "--" {
			seenSep = true
			filtered = append(filtered, a)
			continue
		}
		if !seenSep {
			switch a {
			case "--no-prompt", "--no-prompt=true":
				noPrompt = true
				continue
			case "--no-prompt=false":
				noPrompt = false
				continue
			}
		}
		filtered = append(filtered, a)
	}
	return filtered, noPrompt
}

// StripYes removes the guard-only --yes flag from args and reports whether
// audited auto-confirm was requested. Like --json/--no-prompt, it belongs to
// the guard and must never be forwarded to kubectl. Recognized as "--yes",
// "--yes=true", or "--yes=false", and only before the "--" separator.
func StripYes(args []string) (filtered []string, yes bool) {
	seenSep := false
	for _, a := range args {
		if a == "--" {
			seenSep = true
			filtered = append(filtered, a)
			continue
		}
		if !seenSep {
			switch a {
			case "--yes", "--yes=true":
				yes = true
				continue
			case "--yes=false":
				yes = false
				continue
			}
		}
		filtered = append(filtered, a)
	}
	return filtered, yes
}

// PositionalArgs returns the non-flag arguments before "--". Thin wrapper over
// ParseArgs kept for callers/tests.
func PositionalArgs(args []string) []string {
	return ParseArgs(args).Positional
}

// ExtractCommand extracts the kubectl command and its first subcommand from
// args, ignoring flags. The verb is normalized to lowercase to prevent
// uppercase bypass (e.g., "DELETE" should match "delete").
//
// Normally the verb is the first positional. If that token is not a verb the
// guard recognizes, the parser may have failed to consume the value of a global
// flag it does not know about, leaving that value sitting in verb position and
// hiding the real verb — an ungated fail-open. So when the leading positional is
// unrecognized, fall back to the first recognized verb later in the positional
// stream. Relative to trusting pos[0] this can only ever add gating, never
// remove it. A command with no recognized verb anywhere (a plugin,
// `completion`, ...) keeps its leading token and is classified as before.
//
// The fallback is a backstop, NOT the primary defense: it does not fire when
// pos[0] happens to be a recognized *safe* verb. A future kubectl global flag
// that takes a value AND is missing from knownLongFlags could put a safe verb
// name in verb position (`--future-flag get delete pod x` -> resolves "get")
// and hide a gated verb. The real invariant is that knownLongFlags/shortTakesValue
// stay a superset of kubectl's persistent value-taking flags; see their doc
// comments. Verified complete against `kubectl options` (v1.33).
func ExtractCommand(args []string) (cmd string, subCmd string) {
	pos := PositionalArgs(args)
	if len(pos) == 0 {
		return "", ""
	}
	i := verbPositionalIndex(pos)
	if i < 0 {
		return strings.ToLower(pos[0]), ""
	}
	if i+1 < len(pos) {
		return strings.ToLower(pos[i]), pos[i+1]
	}
	return strings.ToLower(pos[i]), ""
}

// ExtractResourceCandidates returns the positional arguments after the verb.
func ExtractResourceCandidates(args []string) []string {
	return ParseArgs(args).ResourceCandidates()
}

// ExtractFilenames returns the paths supplied via -f / --filename (in any
// form). Directories, "-" (stdin), and URLs are returned verbatim.
func ExtractFilenames(args []string) []string {
	return ParseArgs(args).Filenames
}

// IsSafeCommand returns true if the command is read-only.
func IsSafeCommand(args []string) bool {
	if len(args) == 0 {
		return true
	}

	cmd, subCmd := ExtractCommand(args)
	if cmd == "" {
		return true
	}

	if subs, ok := safeSubcommands[cmd]; ok {
		if subCmd == "" {
			return true // bare command prints help
		}
		return subs[subCmd]
	}

	return safeCommands[cmd]
}

// IsDryRun reports whether args run kubectl in dry-run mode (--dry-run=client
// or =server, or a bare --dry-run). --dry-run=none/=false are not dry-runs.
func IsDryRun(args []string) bool {
	return ParseArgs(args).IsDryRun()
}

// IsStateAltering returns true if the command modifies cluster state.
func IsStateAltering(args []string) bool {
	if len(args) == 0 {
		return false
	}

	cmd, subCmd := ExtractCommand(args)
	if cmd == "" {
		return false
	}

	if subs, ok := safeSubcommands[cmd]; ok {
		if subCmd == "" {
			return false // bare command prints help
		}
		_, safe := subs[subCmd]
		return !safe
	}

	return stateAlteringCommands[cmd]
}

// IsDiffable reports whether a command can be previewed with `kubectl diff`:
// it must apply a manifest (apply/create/replace with a -f/-k source), so there
// is something to diff. delete/scale/exec/patch have no manifest to diff and
// are skipped.
func IsDiffable(args []string) bool {
	cmd, _ := ExtractCommand(args)
	switch cmd {
	case "apply", "create", "replace":
	default:
		return false
	}
	p := ParseArgs(args)
	return len(p.Filenames) > 0 || p.Kustomize != ""
}

// DiffArgs returns a copy of args with the kubectl verb replaced by "diff",
// preserving global flags (--context, -n, -f, ...), suitable for `kubectl diff`.
// It returns nil if no verb token is found before the "--" separator.
func DiffArgs(args []string) []string {
	p := ParseArgs(args)
	if p.VerbIndex < 0 {
		return nil
	}
	out := make([]string, len(args))
	copy(out, args)
	out[p.VerbIndex] = "diff"
	return out
}

// GetCommandDescription returns a human-readable description of the command.
func GetCommandDescription(args []string) string {
	cmd, subCmd := ExtractCommand(args)
	if subCmd != "" {
		return cmd + " " + subCmd
	}
	return cmd
}

// HasUninspectableSource reports whether args read manifests from stdin, a
// URL, or a kustomize directory (sources the guard cannot scan).
func HasUninspectableSource(args []string) bool {
	return ParseArgs(args).HasUninspectableSource()
}

// HasRawPath reports whether args carry a --raw API-server path, which the
// guard cannot map to a resource type. Used to explain a Blocked decision.
func HasRawPath(args []string) bool {
	return ParseArgs(args).HasRaw
}

// redactedValue replaces a secret flag's value everywhere the guard surfaces a
// command string. The flag name is kept so the record stays useful.
const redactedValue = "***"

// secretValueFlags carry secret material (or PII) as their entire value. Both
// "--flag=value" and "--flag value" forms are redacted.
//
// --certificate-authority / --client-certificate / --client-key /
// --tls-private-key usually name a file rather than inline material. The guard
// redacts them anyway: proving a value is a path and not inline key material is
// not worth the risk of being wrong, and a redacted path costs only a little
// debuggability.
// --patch/--overrides carry an arbitrary JSON/YAML blob that may embed secret
// material directly (`patch secret db -p '{"stringData":{"password":"x"}}'` is
// the usual way to set a secret from the CLI). The guard cannot prove such a
// blob is free of secrets, so it redacts the whole value — the same "cannot
// prove it is safe" stance taken for --raw and un-inspectable -f sources. The
// verb and target resource are still logged, so the record shows what was
// patched, just not with what. --patch-file and --from-file name a path, not
// inline material, and are left alone.
var secretValueFlags = map[string]bool{
	"--token":                 true,
	"--password":              true,
	"--docker-password":       true,
	"--docker-email":          true, // PII
	"--client-key":            true,
	"--client-certificate":    true,
	"--certificate-authority": true,
	"--patch":                 true,
	"--overrides":             true,
	"--exec-arg":              true,
	// --tls-private-key is not a flag in kubectl v1.33, but the ticket calls for
	// it; kept as a cheap guard in case a plugin or a future release adds it.
	"--tls-private-key": true,
}

// secretConfigProperties are fragments of a kubeconfig property path whose
// VALUE is credential material. `kubectl config set PROPERTY_NAME
// PROPERTY_VALUE` writes the secret as a bare POSITIONAL with no flag in front
// of it — kubectl's own help shows
// `config set users.cluster-admin.client-key-data cert_data_here`.
//
// Matching is on the property name, not the value, so ordinary settings such as
// `config set current-context prod` and `config set clusters.x.server https://…`
// stay legible. Public material (certificate-authority-data,
// client-certificate-data) is deliberately not matched.
var secretConfigProperties = []string{
	"token", "password", "secret", "client-key", "key-data", "credential",
}

// isSecretConfigProperty reports whether a `kubectl config set` property name
// addresses credential material, so its value must be redacted.
func isSecretConfigProperty(property string) bool {
	lc := strings.ToLower(property)
	for _, fragment := range secretConfigProperties {
		if strings.Contains(lc, fragment) {
			return true
		}
	}
	return false
}

// configSetRedactions returns the arg indexes RedactCommand must redact for a
// `kubectl config set PROPERTY_NAME PROPERTY_VALUE`, keyed to how each should
// be rendered.
//
// It works off ParseArgs' positional list rather than scanning raw tokens,
// because the property is "the first positional after the subcommand" and only
// ParseArgs knows which tokens were swallowed as flag values. Scanning raw
// tokens instead lets an intervening `--kubeconfig /vault/secrets/kc` be
// mistaken for the property name — which would blank the property and let the
// real secret through.
//
// Positions are taken RELATIVE to the resolved verb, never from a hardcoded
// pos[0]. ExtractCommand may resolve `config set` from a later positional (its
// verb-shift fallback), and indexing from zero in that case reads "set" as the
// property name, redacts nothing, and leaks the value.
func configSetRedactions(p ParsedArgs) map[int]int {
	pos, idx := p.Positional, p.PositionalIndexes
	if len(idx) != len(pos) {
		return nil // invariant broken; do not guess at indexes
	}
	v := verbPositionalIndex(pos)
	// pos[v:] = [config, set, PROPERTY, VALUE]
	if v < 0 || v+2 >= len(pos) {
		return nil
	}
	property := pos[v+2]

	// kubectl rejects the single-token `PROPERTY=VALUE` form, but the guard may
	// still be asked to audit the attempt; do not record it in cleartext.
	if key, _, found := strings.Cut(property, "="); found {
		if isSecretConfigProperty(key) {
			return map[int]int{idx[v+2]: redactValueOfPair}
		}
		return nil
	}

	if v+3 >= len(pos) || !isSecretConfigProperty(property) {
		return nil
	}
	return map[int]int{idx[v+3]: redactWhole}
}

// keyValueSecretFlags carry a "key=value" pair whose VALUE is secret. The key
// is preserved (it names what was set) and only the value is redacted, so
// `--from-literal=password=hunter2` becomes `--from-literal=password=***`.
//
// --env covers `kubectl run --env=K=V` and `kubectl set env --env=K=V`;
// environment variables are a primary carrier of credentials. --exec-env and
// --auth-provider-arg carry kubeconfig credential material on
// `kubectl config set-credentials`. Redacting the value while keeping the key
// means the audit log still records WHICH variable was set, just not to what.
var keyValueSecretFlags = map[string]bool{
	"--from-literal":      true,
	"--env":               true,
	"--exec-env":          true,
	"--auth-provider-arg": true,
}

// redactKeyValue redacts the value of a "key=value" token, keeping the key.
// A token with no "=" is redacted whole, since we cannot tell key from value.
// "-" is kubectl's read-from-stdin idiom (`--env -`), not a secret, and is kept
// so the record still shows where the values came from.
func redactKeyValue(token string) string {
	if token == "-" {
		return token
	}
	if eq := strings.IndexByte(token, '='); eq >= 0 {
		return token[:eq+1] + redactedValue
	}
	return redactedValue
}

// redactsPositionalPairs reports whether the verb takes its KEY=VALUE pairs as
// positional arguments rather than as flag values. `kubectl set env
// RESOURCE/NAME KEY=VALUE` is the documented form, so the secret has no flag in
// front of it for the redactor to match on.
//
// Deliberately scoped to `set env`: `set image deploy/x nginx=nginx:latest` and
// `label pod nginx env=prod` carry no secrets and must stay legible.
func redactsPositionalPairs(cmd, subCmd string) bool {
	return cmd == "set" && strings.EqualFold(subCmd, "env")
}

// How a secret flag's value is rendered: the whole value, or just the value
// half of a "key=value" pair.
const (
	redactNone = iota
	redactWhole
	redactValueOfPair
)

// secretShortAlias resolves a single-letter flag to the secret-bearing long
// flag it aliases, for the given verb.
//
// It MUST be verb-scoped: kubectl reuses letters across commands, and the same
// letter can be value-taking in one verb and boolean in another. `-p` is
// --patch on `patch` (takes a value) but the boolean --previous on `logs`, so a
// global alias would consume `nginx` in `kubectl logs -p nginx` and corrupt the
// audit record. `-e` is --env on `set env` and is not a valid shorthand on
// `run`. Verified against `kubectl <verb> --help` (v1.33).
func secretShortAlias(cmd, subCmd string, c byte) (kind int, ok bool) {
	switch {
	case cmd == "patch" && c == 'p':
		return redactWhole, true
	case redactsPositionalPairs(cmd, subCmd) && c == 'e':
		return redactValueOfPair, true
	}
	return redactNone, false
}

// redactShortCluster renders a bundled short-flag token (e.g. "-e", "-e=K=V",
// "-eK=V", "-p", "-Re") when it carries a secret-bearing shorthand, mirroring
// how pflag consumes values: the flag takes the rest of the token, or the next
// argument. matched=false means the token holds no secret shorthand and should
// be passed through untouched.
//
// The walk stops at the first value-taking flag, because that flag swallows the
// remainder of the token — nothing after it is a separate shorthand.
func redactShortCluster(cmd, subCmd, arg string) (out string, next int, matched bool) {
	shorthands := arg[1:] // strip the leading "-"
	for i := 0; i < len(shorthands); i++ {
		c := shorthands[i]
		if kind, ok := secretShortAlias(cmd, subCmd, c); ok {
			prefix := arg[:i+2] // "-" plus every shorthand up to and including c
			rest := shorthands[i+1:]
			switch {
			case rest == "":
				// Value is the next argument.
				return prefix, kind, true
			case strings.HasPrefix(rest, "="):
				return prefix + "=" + renderSecret(kind, rest[1:]), redactNone, true
			default:
				return prefix + renderSecret(kind, rest), redactNone, true
			}
		}
		if shortConsumesValue(c) {
			return "", redactNone, false // consumes the rest; no shorthand beyond
		}
	}
	return "", redactNone, false
}

// shortConsumesValue reports whether a single-letter flag takes a value, i.e.
// swallows the remainder of its token or the next argument.
//
// 'f' and 'k' are the manifest sources (-f file, -k dir). They are value-taking
// but live outside shortTakesValue because parseShortCluster handles them
// specially, so any other walker over a short cluster must add them back — or
// it will step past a source's value and mis-bind the following token
// (`set env -fe deploy/web FOO=bar` would redact the resource name).
func shortConsumesValue(c byte) bool {
	return c == 'f' || c == 'k' || shortTakesValue[c]
}

// renderSecret redacts a value according to kind.
func renderSecret(kind int, value string) string {
	if kind == redactValueOfPair {
		return redactKeyValue(value)
	}
	return redactedValue
}

// RedactCommand renders args as a command string with secret-bearing flag
// values replaced by "***". Every place the guard surfaces a command — the
// audit log, --json output, and human-facing messages — must use this instead
// of strings.Join, or the guard leaks the very secrets it exists to protect
// into the one file it owns.
//
// Redaction is applied to every token, including those after the "--"
// separator, so a kubectl credential flag that appears in an exec payload
// (`exec pod -- app --token abc`) is still redacted. The audit string is written
// for a human reading an incident, not to be replayed verbatim.
//
// Caveats, documented in the README: this cannot redact secrets that never
// appear in argv — the *contents* of a `--from-file` path, or a value piped on
// stdin — and it has no control over the user's shell history. Nor can it redact
// secrets carried by an *application's* own flags or inline env assignments in an
// exec/run payload after "--" (`-- env PASSWORD=x`, `-- app --db-password=x`): the
// payload is an arbitrary foreign command line whose flag names the guard cannot
// know, and blanking every key=value/unknown --flag there would destroy the audit
// record of what ran. Only kubectl's own credential flags are matched in a payload.
// RedactCommand renders RedactArgs as a single space-joined command string.
func RedactCommand(args []string) string {
	return strings.Join(RedactArgs(args), " ")
}

// RedactArgs returns a copy of args with secret-bearing values replaced by
// "***". Callers that surface individual tokens (a resource name, a command
// description) should derive them from this slice rather than the raw args, so
// a secret can never reach a message or JSON field by skipping the redactor.
// The input slice is never modified; kubectl is always given the real args.
func RedactArgs(args []string) []string {
	// next describes what to do with the NEXT token, for the "--flag value"
	// (rather than "--flag=value") form.
	next := redactNone

	// Short-flag aliases and positional KEY=VALUE pairs are both verb-dependent,
	// so resolve the verb once up front.
	parsed := ParseArgs(args)
	cmd, subCmd := ExtractCommand(args)
	positionalPairs := redactsPositionalPairs(cmd, subCmd)

	// `config set users.admin.token <value>` puts the secret in a bare
	// positional. Resolve exactly which arg index that is, up front.
	var byIndex map[int]int
	if cmd == "config" && strings.EqualFold(subCmd, "set") {
		byIndex = configSetRedactions(parsed)
	}

	out := make([]string, 0, len(args))
	for i, arg := range args {
		if next != redactNone {
			out = append(out, renderSecret(next, arg))
			next = redactNone
			continue
		}
		if kind, ok := byIndex[i]; ok {
			out = append(out, renderSecret(kind, arg))
			continue
		}

		name, val, hasInline := splitLong(arg)
		switch {
		case secretValueFlags[name]:
			if hasInline {
				out = append(out, name+"="+redactedValue)
			} else {
				out = append(out, name)
				next = redactWhole
			}
		case keyValueSecretFlags[name]:
			if hasInline {
				out = append(out, name+"="+redactKeyValue(val))
			} else {
				out = append(out, name)
				next = redactValueOfPair
			}
		case strings.HasPrefix(arg, "--"):
			// A long flag that carries no secret.
			out = append(out, arg)
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			// Possibly a bundled short-flag token carrying a secret shorthand.
			if rendered, consumes, matched := redactShortCluster(cmd, subCmd, arg); matched {
				out = append(out, rendered)
				next = consumes
			} else {
				out = append(out, arg)
			}
		case positionalPairs && strings.Contains(arg, "="):
			// A bare KEY=VALUE positional under `set env`.
			out = append(out, redactKeyValue(arg))
		default:
			out = append(out, arg)
		}
	}
	return out
}

// namespaceKind is the canonical form config.NormalizeResource produces for
// "namespace", "namespaces", "ns", and "ns.v1".
const namespaceKind = "namespace"

// dashDashPayloadVerbs are the verbs for which a "--" separator introduces a
// FOREIGN command, not more kubectl arguments. `kubectl exec pod -- kubectl
// delete ns/x` runs kubectl inside the pod; the tokens after "--" are that
// container command's argv and must never be read as kubectl targets.
//
// Every OTHER verb — delete, edit, patch, label, ... — uses "--" only to end
// flag parsing, so `kubectl delete -- namespace kube-system` still deletes the
// namespace. Treating "--" as a payload boundary for those verbs let a protected
// namespace be deleted ungated (a real bypass). Verified against kubectl v1.33:
// exec/run/debug document `-- COMMAND`; delete/edit pass post-"--" tokens to the
// resource builder as TYPE/NAME.
var dashDashPayloadVerbs = map[string]bool{
	"exec": true, "run": true, "debug": true,
	"attach": true, "cp": true, "port-forward": true, "proxy": true,
}

// NamespaceTargets describes how a command addresses the `namespace` KIND, as
// opposed to the namespace a command runs *in* (which comes from --namespace/-n
// or the context). `kubectl delete namespace kube-system` carries no -n flag, so
// namespace protection would otherwise resolve the target namespace to "default"
// and never notice that the object being destroyed IS a protected namespace.
type NamespaceTargets struct {
	// Kind is true when the command's resource type is namespace/ns, in any of
	// the forms kubectl accepts.
	Kind bool
	// Names are the namespace names addressed positionally, from either
	// `namespace NAME...` or `ns/NAME` type/name tokens.
	Names []string
	// Wide is true when the command targets the namespace kind with --all or a
	// label selector instead of names. kubectl's own usage is
	// `delete TYPE [(NAME | -l label | --all)]`, so in that case the affected
	// namespaces are NOT knowable from argv and the guard must fail closed.
	Wide bool
}

// namespaceTargetsFrom extracts the namespace-kind targets from an already
// parsed command.
//
// kubectl accepts several shapes, all of which must be recognized or the gate is
// trivially bypassed. Verified against `kubectl delete --help` (v1.33), whose
// usage line is `kubectl delete TYPE [(NAME | -l label | --all)]` and whose own
// example is `kubectl delete pod,service baz foo`:
//
//	delete namespace kube-system        bare kind, one name
//	delete ns kube-system               short name
//	delete namespaces a b c             plural kind, several names
//	delete ns/kube-system               type/name token
//	delete pod/x ns/kube-system         type/name mixed with other kinds
//	delete ns,pod foo                   COMMA TYPE LIST: names apply to every type
//	delete namespace --all              wide: names unknowable
//	delete ns -l env=prod               wide: names unknowable
//
// Only tokens before the "--" separator are resource tokens; an "ns/x" inside an
// exec payload is a foreign command's argument, not a kubectl target.
func namespaceTargetsFrom(p ParsedArgs) NamespaceTargets {
	var out NamespaceTargets

	v := verbPositionalIndex(p.Positional)
	if v < 0 {
		return out
	}
	// For a resource verb, tokens after "--" are still TYPE/NAME arguments, so
	// scan through the end of the positional list. Only for the exec-family verbs
	// is "--" a foreign-command boundary; there, clip at the separator so an
	// `exec pod -- kubectl delete ns/x` payload is not read as a target.
	end := len(p.Positional)
	if dashDashPayloadVerbs[strings.ToLower(p.Positional[v])] {
		end = p.PositionalsBeforeSep
	}
	if v+1 >= end {
		return out
	}
	toks := p.Positional[v+1 : end]

	// The first positional after the verb is the TYPE (or a comma-separated TYPE
	// list). A bare namespace kind there means every later positional is a NAME
	// of a namespace.
	bareKindIsNamespace := false
	for _, part := range strings.Split(toks[0], ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.Contains(part, "/") {
			continue
		}
		if config.NormalizeResource(part) == namespaceKind {
			bareKindIsNamespace = true
		}
	}

	// Every token is comma-split. kubectl only comma-splits the TYPE argument, not
	// a NAME, so this over-splits a name like "foo,kube-system" into two names.
	// That is deliberately kept: it only ever adds candidate names (fail-CLOSED,
	// it can gate more but never less), and a real namespace name cannot contain a
	// comma anyway (RFC 1123 label). Splitting names also catches a comma list of
	// type/name tokens (`ns/a,ns/b`) without needing to know kubectl's exact rule.
	for i, tok := range toks {
		for _, part := range strings.Split(tok, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			// A "type/name" token names its own kind, wherever it appears — so
			// `delete pod/x ns/kube-system` is caught even though the leading
			// TYPE is not a namespace.
			if slash := strings.IndexByte(part, '/'); slash >= 0 {
				if config.NormalizeResource(part[:slash]) == namespaceKind && slash+1 < len(part) {
					out.Kind = true
					out.Names = append(out.Names, part[slash+1:])
				}
				continue
			}
			if i == 0 {
				continue // the TYPE token itself, not a name
			}
			if bareKindIsNamespace {
				out.Names = append(out.Names, part)
			}
		}
	}

	if bareKindIsNamespace {
		out.Kind = true
	}
	if out.Kind && len(out.Names) == 0 && (p.All || p.HasSelector) {
		// `delete namespace --all` / `delete ns -l env=prod`: the command targets
		// namespaces but names none. We cannot prove a protected namespace is not
		// among them.
		out.Wide = true
	}
	return out
}

// NamespaceNameTargets returns the namespace names a command addresses by name,
// or nil when it does not target the namespace kind.
func NamespaceNameTargets(args []string) []string {
	return namespaceTargetsFrom(ParseArgs(args)).Names
}

// NamespaceKindIsWide reports whether the command targets the namespace kind
// with --all or a label selector, so the affected namespaces cannot be read off
// the command line.
func NamespaceKindIsWide(args []string) bool {
	return namespaceTargetsFrom(ParseArgs(args)).Wide
}

// MatchesProtectedResource reports whether args target a protected resource,
// either via an explicit resource token, an inspectable -f file/dir whose kind
// is protected, an un-inspectable source (-f -, URL, -k), or a --raw API path —
// the latter two when resource protection is active (we cannot prove they are
// safe, so we block).
func MatchesProtectedResource(cfg ProtectedResourceChecker, args []string) bool {
	if cfg == nil || !cfg.HasProtectedResources() {
		return false
	}
	p := ParseArgs(args)

	// --raw requests a literal API-server path. The guard cannot map that path
	// to a resource type, so with resource protection active it cannot prove the
	// request is safe — e.g. `get --raw /api/v1/namespaces/default/secrets/db`
	// reads a secret with no "secret" token anywhere in the command. Block, the
	// same conservative stance taken for stdin/URL/kustomize sources. When no
	// resource protection is configured, --raw is untouched (/healthz, /version).
	if p.HasRaw {
		return true
	}

	for i, cand := range p.ResourceCandidates() {
		// ResourceCandidates is Positional[1:], so candidate i sits at
		// Positional[i+1]. Tokens at or past the "--" separator are payload
		// (exec args, a shell command line), not kubectl resource tokens.
		isResourceToken := i+1 < p.PositionalsBeforeSep

		// G5: kubectl accepts comma-separated resource lists like
		// "secret,configmap"; match each part independently.
		for _, part := range strings.Split(cand, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			// An API path in resource position (a leading "/") cannot be
			// normalized to a resource type: NormalizeResource strips at the
			// first "/" and returns "", which silently matches nothing. Treat it
			// as un-inspectable rather than let it slip through as a non-match.
			// Only applies before "--": "exec pod -- ls /tmp" is a payload path,
			// not an API path, and must not be blocked.
			if isResourceToken && strings.HasPrefix(part, "/") {
				return true
			}
			// G7: "all" / "*" span every resource type, including protected
			// ones, so they are blocked when any resource is protected.
			lc := strings.ToLower(part)
			if lc == "all" || lc == "*" {
				return true
			}
			if cfg.IsResourceProtected(part) {
				return true
			}
		}
	}
	for _, f := range p.InspectableFilenames() {
		if pathContainsProtectedKind(f, cfg) {
			return true
		}
	}
	// Conservative: an active resource block plus an un-scannable source must
	// be treated as a potential match.
	if p.HasUninspectableSource() {
		return true
	}
	return false
}

// pathContainsProtectedKind reports whether the given path (a regular file or
// a directory, the latter covering "-f dir" / "-Rf dir") contains a manifest
// whose kind is protected. Directories are walked recursively so that a secret
// nested in an applied directory is caught.
//
// NOTE: there is an inherent TOCTOU window between this scan and kubectl's own
// read (kubectl re-opens the file after we exec it). The threat model is
// accidental commands, not a determined adversary who swaps a symlink between
// the two reads; a full fix would require buffering and re-injecting the file
// contents, which is out of scope.
func pathContainsProtectedKind(path string, cfg ProtectedResourceChecker) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		found := false
		_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if fileContainsProtectedKind(p, cfg) {
				found = true
				return filepath.SkipAll
			}
			return nil
		})
		return found
	}
	return fileContainsProtectedKind(path, cfg)
}

// maxManifestDocBytes caps a single YAML document during the streaming scan.
// A Kubernetes object is bounded by etcd's ~1.5MB request limit, so 64MB is ~40x
// headroom and no real manifest reaches it. If one document somehow exceeds it,
// the scan cannot prove the document is free of a protected kind, so it fails
// CLOSED (treats the file as protected) rather than reading unboundedly or
// silently skipping the rest — matching the conservative stance elsewhere in
// MatchesProtectedResource for un-inspectable sources.
const maxManifestDocBytes = 64 * 1024 * 1024

// splitYAMLDocs is a bufio.SplitFunc that yields one YAML document per token,
// splitting on the literal "\n---" separator. This is byte-for-byte the same
// document boundary the previous implementation used
// (bytes.Split(data, []byte("\n---"))), so the streaming scan detects exactly the
// same documents — including the robustness that split had for leading "---",
// CRLF, consecutive separators, and a malformed document followed by a real one.
// It is validated against that behavior by TestStreamingScanMatchesBytesSplit.
func splitYAMLDocs(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if i := bytes.Index(data, []byte("\n---")); i >= 0 {
		return i + len("\n---"), data[:i], nil
	}
	if atEOF {
		if len(data) == 0 {
			return 0, nil, nil
		}
		return len(data), data, nil
	}
	// Separator not yet in view: ask bufio.Scanner for more data.
	return 0, nil, nil
}

// newDocScanner builds the streaming YAML-document scanner used by
// fileContainsProtectedKind. The buffer starts small and grows only as a single
// document requires, capped at maxManifestDocBytes so peak memory is the largest
// single document rather than the whole file.
func newDocScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxManifestDocBytes)
	scanner.Split(splitYAMLDocs)
	return scanner
}

// fileContainsProtectedKind reports whether a single regular file is a
// YAML/JSON manifest (possibly multi-document) whose kind is protected.
//
// The file is scanned by STREAMING one document at a time rather than reading it
// all into memory: a helm-generated manifest can be tens of MB across thousands
// of resources, and the previous os.ReadFile + unmarshal-all approach held the
// whole thing (and, via yaml.v3, a multiple of it) resident at once. Streaming
// bounds memory to the largest single document, and — because it returns on the
// first protected kind — a manifest whose protected resource is early (the common
// case) is decided after reading only a few KB, never touching the rest.
func fileContainsProtectedKind(path string, cfg ProtectedResourceChecker) bool {
	f, err := os.Open(path)
	if err != nil {
		// Match the previous behavior: an unreadable file is not treated as a
		// match here (MatchesProtectedResource handles un-inspectable SOURCES —
		// stdin/URL/kustomize — separately and conservatively).
		return false
	}
	defer func() { _ = f.Close() }()
	return readerContainsProtectedKind(f, cfg)
}

// readerContainsProtectedKind streams the YAML documents from r and reports
// whether any document's kind is protected. It returns as soon as the first
// protected kind is seen — so for the common case (a protected resource in an
// early document) it reads only that far and never touches the rest of r. It is
// separate from fileContainsProtectedKind so the short-circuit can be exercised
// through a byte-counting reader in tests.
func readerContainsProtectedKind(r io.Reader, cfg ProtectedResourceChecker) bool {
	scanner := newDocScanner(r)
	for scanner.Scan() {
		var meta struct {
			Kind string `yaml:"kind"`
		}
		if yaml.Unmarshal(scanner.Bytes(), &meta) == nil && meta.Kind != "" {
			if cfg.IsResourceProtected(meta.Kind) {
				return true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		// The only expected error is bufio.ErrTooLong on a single document larger
		// than the cap. We could not scan it, so we cannot prove it is safe: fail
		// closed. This is unreachable for any real Kubernetes manifest.
		return true
	}
	return false
}

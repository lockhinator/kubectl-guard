// Package config handles loading and saving kubectl-guard configuration.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Confirmation modes for protected contexts.
const (
	ConfirmModeSimple   = "simple"    // y/N prompt (default)
	ConfirmModeTypeName = "type-name" // must type the context name exactly
	// ConfirmModeAgentRelay does not prompt stdin at all. On a gated command it
	// emits a structured "needs-confirmation" object on stderr and exits with
	// the needs-confirmation code, so an agent framework can relay the request
	// to its human. The human completes the exact request once through the
	// OS-authenticated `kubectl-guard approve` command; plain --yes is rejected.
	ConfirmModeAgentRelay = "agent-relay"
)

// Protection modes for protected contexts/namespaces. "confirm" (default)
// prompts; "block" hard-refuses state-altering commands with no prompt.
const (
	ContextModeConfirm   = "confirm"
	ContextModeBlock     = "block"
	NamespaceModeConfirm = "confirm"
	NamespaceModeBlock   = "block"
)

// Audit modes control what gets written to the audit log.
const (
	AuditModeAll   = "all"   // log every command, including allowed passthrough (default)
	AuditModeGated = "gated" // log only interventions (blocked/confirmed/aborted/denied)
	AuditModeOff   = "off"   // log nothing
)

// Unknown-verb policy for a verb the guard cannot classify (a plugin, a future
// kubectl verb, or a gap in the built-in lists) on a PROTECTED context/namespace.
// "allow" (default) keeps the prior behavior; a security tool cannot prove an
// unknown verb is safe, so "gate"/"deny" fail toward gating on protected targets.
const (
	UnknownVerbAllow = "allow" // default: unknown verbs pass (current behavior)
	UnknownVerbGate  = "gate"  // gate an unknown verb on a protected target
	UnknownVerbDeny  = "deny"  // refuse an unknown verb on a protected target
)

// Blast-radius policies gate wide-scope / bulk mutations independently of
// context, because a command's danger is also about HOW MUCH it changes, not
// only WHERE it runs: `delete --all`, `apply --prune`, a label/field selector on
// a destructive verb, `--all-namespaces`, and force deletion are dangerous even
// on a "dev" cluster — and are exactly the mistakes an agent makes.
const (
	BlastRadiusOff   = "off"   // default: wide mutations gate only on protected targets
	BlastRadiusGate  = "gate"  // require confirmation on any context
	BlastRadiusBlock = "block" // refuse on any context
)

// Sensitive-access policies gate interactive / data-movement verbs (exec, cp,
// attach, debug, port-forward, proxy) on EVERY context — not just protected ones
// — because their risk is about what they can read/reach (secrets in a pod, a
// root shell on a node via `debug`, a tunnel to a workload), independent of where
// they run.
const (
	SensitiveAccessOff   = "off"   // default: these verbs gate only on protected targets
	SensitiveAccessGate  = "gate"  // require confirmation on any context
	SensitiveAccessBlock = "block" // refuse on any context
)

// Sensitive-kind policies gate STATE-ALTERING commands on a configured kind
// (node, namespace, persistentvolume, a critical CRD) on EVERY context, while
// leaving reads of that kind alone — the middle tier between "block all access to
// a kind" (protected_resources) and "gate mutations by location"
// (protected_contexts/namespaces).
const (
	SensitiveKindOff     = "off"     // default: mutations to the kind are not specially gated
	SensitiveKindConfirm = "confirm" // require confirmation on any context
	SensitiveKindBlock   = "block"   // refuse on any context
)

// Output-redaction modes control the OPT-IN structured redaction of read output
// (#108). "off" (default) keeps the guard's byte-for-byte syscall.Exec passthrough
// — the guard never sees a byte of kubectl's output. "structured" engages the
// redaction path ONLY for a non-interactive, non-watch `get` with `-o json|yaml`:
// the guard runs kubectl as a child with a piped stdout, blanks KNOWN sensitive
// fields (Secret data/stringData, a container env[].value) in the parsed document,
// and re-emits. It is best-effort defense-in-depth against ACCIDENTAL disclosure
// (a secret scrolling in an agent-captured terminal), explicitly NOT a containment
// boundary — an unparseable document passes through UNREDACTED (fail-open) rather
// than dropping the user's read. Every other command keeps syscall.Exec untouched.
const (
	RedactOutputOff        = "off"        // default: no redaction; syscall.Exec passthrough
	RedactOutputStructured = "structured" // redact known fields on get -o json|yaml
)

// In-cluster policies decide what happens when the guard runs with no named
// context (inside a pod on the serviceaccount config, or CI with an in-cluster
// kubeconfig) and protected contexts are configured. Without a context name the
// guard cannot evaluate context protection, so historically it failed closed and
// denied everything, making it unusable in-cluster.
const (
	// InClusterNamespace (default) gates by the resolved serviceaccount
	// namespace instead of the context name, so namespace protection still
	// applies in-cluster. Commands in an unprotected namespace pass through.
	InClusterNamespace = "namespace"
	// InClusterDeny reproduces the previous fail-closed behavior: refuse every
	// state-altering command in-cluster when protected contexts are configured.
	InClusterDeny = "deny"
	// InClusterAllow relaxes only the UNEVALUABLE axes in-cluster: the context
	// name (unknowable without a kubeconfig) and the IMPLICIT run-in namespace
	// (the serviceaccount-namespace fallback that InClusterNamespace would gate
	// on). It is NOT a full passthrough. The context-INDEPENDENT signals still
	// gate: protected resources (global), sensitive-access, blast-radius,
	// sensitive-kind, AND namespace protection for an EXPLICITLY-named target
	// (-n <ns>, -A, or the namespace as the command's object) — those are
	// evaluable from argv regardless of the unresolvable context, so "allow"
	// differs from "namespace" precisely by relaxing the SA-namespace fallback,
	// not the explicit target. A deliberately-permissive opt-in for the
	// unevaluable context / implicit-namespace axes only.
	InClusterAllow = "allow"
)

const (
	configFileName = ".kubectl-guard.yaml"
	auditFileName  = ".kubectl-guard-audit.log"
)

// MaxConfirmTimeoutSeconds caps confirm_timeout_seconds. It is one year — far
// above any real confirmation-prompt timeout and far below the ~9.2e9 point
// where time.Duration(n)*time.Second overflows int64 nanoseconds and wraps
// negative (which would silently mean "wait forever"). A deliberate wait-forever
// is spelled 0.
const MaxConfirmTimeoutSeconds = 365 * 24 * 60 * 60

// ProtectedPattern is one entry in protected_contexts / protected_namespaces: a
// glob pattern plus an optional per-pattern protection mode. Mode "" means the
// pattern inherits the global context_mode / namespace_mode (the back-compat
// default); a non-empty Mode ("confirm" | "block") overrides the global mode for
// the contexts/namespaces this pattern matches.
//
// The YAML form is backward compatible: a bare string ("prod-*") decodes to
// {Pattern: "prod-*", Mode: ""} and re-marshals to the bare string, so an
// existing string-only config parses and round-trips unchanged. The object form
// ({pattern: "prod-*", mode: block}) carries an explicit per-pattern mode.
type ProtectedPattern struct {
	Pattern string
	Mode    string // "" = inherit the global mode; otherwise "confirm" | "block"
}

// UnmarshalYAML accepts EITHER a bare scalar (the back-compat form: the pattern,
// with an inherited mode) or a mapping {pattern, mode}. Any other node kind is an
// error, so a malformed entry fails the config closed rather than silently
// dropping a protected pattern.
func (pp *ProtectedPattern) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		pp.Mode = ""
		return node.Decode(&pp.Pattern)
	case yaml.MappingNode:
		var raw struct {
			Pattern string `yaml:"pattern"`
			Mode    string `yaml:"mode"`
		}
		if err := node.Decode(&raw); err != nil {
			return err
		}
		pp.Pattern = raw.Pattern
		pp.Mode = raw.Mode
		return nil
	default:
		return fmt.Errorf("protected pattern must be a string or a {pattern, mode} mapping")
	}
}

// MarshalYAML emits the bare pattern string when no per-pattern mode is set
// (preserving the back-compat YAML shape so a string-only config round-trips to
// bare strings), else a {pattern, mode} mapping.
func (pp ProtectedPattern) MarshalYAML() (any, error) {
	if pp.Mode == "" {
		return pp.Pattern, nil
	}
	return map[string]string{"pattern": pp.Pattern, "mode": pp.Mode}, nil
}

// Patterns builds a ProtectedPattern slice from bare pattern strings, each with
// an inherited (empty) mode — the programmatic equivalent of the bare-string YAML
// form. Used by env/flag bootstrap, the setup wizard, and tests.
func Patterns(names ...string) []ProtectedPattern {
	out := make([]ProtectedPattern, 0, len(names))
	for _, n := range names {
		out = append(out, ProtectedPattern{Pattern: n})
	}
	return out
}

// ProtectedCluster protects by CLUSTER identity (the API server URL) rather than
// the spoofable context name. Exactly one of Server (exact URL) or ServerPattern
// (glob) identifies the cluster; Mode is the optional per-entry mode ("" inherits
// the global context_mode, else "confirm"|"block"). Unlike ProtectedPattern it is
// always a YAML mapping, so it needs no custom (Un)MarshalYAML.
//
// ServerPattern uses the same glob semantics as context/namespace patterns, so
// "*.prod.example.com" matches subdomains but NOT the apex "prod.example.com" —
// list the apex separately (or add a "prod.example.com" exact server) if the API
// server lives there. Match on the API server URL means a cluster reachable via
// multiple distinct URLs/IPs must have each form listed to be fully covered.
type ProtectedCluster struct {
	Server        string `yaml:"server,omitempty"`
	ServerPattern string `yaml:"server_pattern,omitempty"`
	Mode          string `yaml:"mode,omitempty"`
}

// normalizeServerForMatch lower-cases and trims a trailing slash so server URLs
// compare stably (scheme+host are case-insensitive; API servers rarely carry a
// path). Used for BOTH the config value and the resolved server, so a Prod/prod
// or trailing-slash difference cannot dodge protection.
func normalizeServerForMatch(s string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(s), "/"))
}

// isDefaultPort reports whether port is the default for scheme (so it can be
// dropped when canonicalizing a server URL).
func isDefaultPort(scheme, port string) bool {
	return (scheme == "https" && port == "443") || (scheme == "http" && port == "80")
}

// canonicalServer returns a canonical form of an API server URL for EXACT
// comparison, so two spellings that reach the SAME cluster compare equal. It
// lower-cases the scheme+host, strips a trailing FQDN dot ("host." == "host"),
// drops userinfo (credentials do not change the target), and drops a default port
// ("https://h" == "https://h:443"). A bare host or unparseable value falls back to
// lower-case + trailing slash/dot trim. This closes the trailing-dot and
// default-port/userinfo evasions against an attacker-crafted kubeconfig.
func canonicalServer(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.TrimRight(strings.ToLower(s), "/.")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if isDefaultPort(scheme, port) {
		port = ""
	}
	hostport := host
	if port != "" {
		hostport += ":" + port
	}
	path := strings.TrimRight(u.Path, "/")
	if scheme != "" {
		return scheme + "://" + hostport + path
	}
	return hostport + path
}

// serverHosts returns the host forms of a server URL for glob matching: the bare
// "host" and, when the port is non-default, "host:port". The hostname is
// lower-cased and its trailing FQDN dot stripped. Best-effort (net/url); nil on
// parse failure. This lets a pattern like "*.prod.example.com" match
// "https://api.prod.example.com.:6443" even though matchGlob's "*" would otherwise
// have to cross the "//" and the port in the full URL.
func serverHosts(server string) []string {
	u, err := url.Parse(strings.TrimSpace(server))
	if err != nil || u.Host == "" {
		return nil
	}
	hostname := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	if hostname == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	// Include the explicit "host:port" form (so a pattern written with a port still
	// matches) AND the bare "host" (so a port-less pattern matches a ported server).
	if port := u.Port(); port != "" {
		add(hostname + ":" + port)
	}
	add(hostname)
	return out
}

// matches reports whether this entry protects the given (raw) server URL. An
// exact Server is compared on the canonical form (canonicalServer), so trailing
// slash/dot, case, userinfo, and default-port differences that still hit the same
// cluster cannot dodge it. A ServerPattern is matched against the canonical URL
// AND each host form, so both "https://prod.eks..." (full) and "*.prod.example.com"
// (host) styles work.
func (pc ProtectedCluster) matches(server string) bool {
	cs := canonicalServer(server)
	if cs == "" {
		return false
	}
	if pc.Server != "" && canonicalServer(pc.Server) == cs {
		return true
	}
	if pc.ServerPattern != "" {
		pat := normalizeServerForMatch(pc.ServerPattern)
		// Match the pattern against several forms of the target so it works
		// regardless of how the user wrote it: the CANONICAL URL (default port /
		// userinfo dropped), the RAW normalized URL (port kept — so a full-URL
		// pattern written with an explicit :443/:80 still matches), and each host
		// form (with and without port). Trying more forms only ever ADDS a match
		// (fail-safe), so it cannot introduce a bypass.
		targets := append([]string{cs, normalizeServerForMatch(server)}, serverHosts(server)...)
		for _, t := range targets {
			if matchGlob(pat, t) {
				return true
			}
		}
	}
	return false
}

// identifier returns the raw string that identifies this entry (its Server or
// ServerPattern), used for dedupe and removal.
func (pc ProtectedCluster) identifier() string {
	if pc.ServerPattern != "" {
		return pc.ServerPattern
	}
	return pc.Server
}

// key returns the display/completion key for this entry, distinguishing an exact
// server from a pattern ("server=https://..." / "server_pattern=*.prod...").
func (pc ProtectedCluster) key() string {
	if pc.ServerPattern != "" {
		return "server_pattern=" + pc.ServerPattern
	}
	return "server=" + pc.Server
}

// patternStrings returns just the glob patterns from a ProtectedPattern slice,
// for display, joining, and completion where the per-pattern mode is not needed.
func patternStrings(pats []ProtectedPattern) []string {
	out := make([]string, len(pats))
	for i, p := range pats {
		out[i] = p.Pattern
	}
	return out
}

// ProtectedContextPatterns / ProtectedNamespacePatterns return the bare glob
// patterns of the protected lists, for the CLI (`config list`, completion) which
// does not need the per-pattern mode.
func (c *Config) ProtectedContextPatterns() []string   { return patternStrings(c.ProtectedContexts) }
func (c *Config) ProtectedNamespacePatterns() []string { return patternStrings(c.ProtectedNamespaces) }

// Config represents the kubectl-guard configuration.
type Config struct {
	// ProtectedContexts are context name patterns (glob) that require
	// confirmation (or, per-pattern/global mode, a hard block) for state-altering
	// commands. A bare-string YAML entry inherits the global context_mode; an
	// object entry ({pattern, mode}) sets a per-pattern mode. See ProtectedPattern.
	ProtectedContexts []ProtectedPattern `yaml:"protected_contexts,omitempty"`

	// ProtectedClusters protect by CLUSTER identity (the API server URL) rather
	// than the spoofable context NAME. A command is gated if the context name
	// matches ProtectedContexts OR the resolved API server matches a
	// ProtectedClusters entry. Strictly additive: a server that cannot be resolved
	// simply leaves name-based protection unchanged. See ProtectedCluster.
	ProtectedClusters []ProtectedCluster `yaml:"protected_clusters,omitempty"`

	// ProtectedResources are resource names (e.g. "secret") whose access is
	// blocked entirely on every context, regardless of verb. Singular, plural,
	// and short-name forms ("secret", "secrets", "cm") match the same things.
	ProtectedResources []string `yaml:"protected_resources,omitempty"`

	// ProtectedNamespaces are namespace name patterns (glob) that gate
	// state-altering commands when the target namespace matches. Composes with
	// protected contexts: a command is gated if either matches. Like
	// ProtectedContexts, each entry may be a bare string (inherits namespace_mode)
	// or a {pattern, mode} object.
	ProtectedNamespaces []ProtectedPattern `yaml:"protected_namespaces,omitempty"`

	// ContextMode controls how protected contexts treat state-altering
	// commands: "confirm" (default) prompts; "block" hard-refuses.
	ContextMode string `yaml:"context_mode,omitempty"`

	// NamespaceMode is the equivalent of ContextMode for protected namespaces.
	NamespaceMode string `yaml:"namespace_mode,omitempty"`

	// ConfirmMode controls the confirmation prompt for protected contexts.
	// "simple" (default) is a y/N prompt; "type-name" requires the user to
	// type the context name exactly.
	ConfirmMode string `yaml:"confirm_mode,omitempty"`

	// AuditLog is the path to the audit log file. When empty it defaults to
	// ~/.kubectl-guard-audit.log.
	AuditLog string `yaml:"audit_log,omitempty"`

	// AuditMode controls what is written to the audit log: "all" (default,
	// every command), "gated" (only interventions), or "off".
	AuditMode string `yaml:"audit_mode,omitempty"`

	// AuditMaxSizeMB enables size-based rotation of the audit log: when the file
	// would exceed this many megabytes, it is rotated to <log>.1 (older archives
	// shift to .2, .3, …). 0 (default) disables rotation — the log grows unbounded,
	// the pre-v0.6.0 behavior.
	AuditMaxSizeMB int `yaml:"audit_max_size_mb,omitempty"`

	// AuditMaxFiles is how many rotated archives to keep (<log>.1 … <log>.N); the
	// oldest is deleted on each rotation. Only meaningful when AuditMaxSizeMB > 0.
	// Empty/0 uses the default (defaultAuditMaxFiles).
	AuditMaxFiles int `yaml:"audit_max_files,omitempty"`

	// AuditWebhookURL, when set, POSTs each audited entry as a JSON body to this
	// http(s) URL (a SIEM, Slack, etc.). Best-effort and synchronous with a short
	// timeout: a slow or failing webhook does not block the command beyond that
	// timeout, and a delivery failure is never fatal. Local file logging still
	// happens regardless.
	AuditWebhookURL string `yaml:"audit_webhook_url,omitempty"`

	// AuditSyslog, when true, also writes each audited entry to the local syslog
	// (LOG_USER/LOG_INFO, tag "kubectl-guard"). Best-effort; local file logging
	// still happens regardless.
	AuditSyslog bool `yaml:"audit_syslog,omitempty"`

	// AuditHMACKeyFile is a path to a file whose contents are the HMAC key for the
	// tamper-evident audit chain (#78). When set (or KUBECTL_GUARD_AUDIT_KEY is
	// exported), each entry's chain hash is an HMAC, so an attacker who can write
	// the log cannot forge a valid continuation without the key. Unset ⇒ plain
	// SHA-256 (tamper-evident but forgeable by a local attacker).
	AuditHMACKeyFile string `yaml:"audit_hmac_key_file,omitempty"`

	// Actor is a static default identity for who drove a command (e.g.
	// "ci-deploy"), stamped into audit entries when KUBECTL_GUARD_ACTOR is
	// unset. Empty falls back to the OS username.
	Actor string `yaml:"actor,omitempty"`

	// ActorPolicies are per-actor overrides of the global context_mode /
	// namespace_mode, so a known agent label can be held to a stricter posture
	// than a human ("agents never mutate prod, humans may confirm"). The actor is
	// resolved exactly as for auditing (KUBECTL_GUARD_ACTOR → actor → OS user) and
	// matched by glob. An override can only make a mode STRICTER (confirm → block),
	// never weaker — KUBECTL_GUARD_ACTOR is self-asserted, so a self-named actor
	// must not be able to relax protection below the global posture. See
	// EffectiveModesForActor.
	ActorPolicies []ActorPolicy `yaml:"actor_policies,omitempty"`

	// BlockImpersonation, when true, denies any command carrying --as / --as-group
	// / --as-uid on a protected context. Impersonation is a common
	// privilege-escalation and audit-evasion vector. Off by default.
	BlockImpersonation bool `yaml:"block_impersonation,omitempty"`

	// DiffBeforeConfirm, when true, runs `kubectl diff` (server-side) and shows
	// the result on stderr before the confirmation prompt for diffable commands.
	// Off by default (diff adds latency and needs server-side dry-run RBAC).
	DiffBeforeConfirm bool `yaml:"diff_before_confirm,omitempty"`

	// PreviewBeforeConfirm, when true, previews what a gated command will affect
	// before prompting: `kubectl diff` for diffable applies (like
	// DiffBeforeConfirm), and a read-only `kubectl get <target/selector> -o name`
	// for non-diffable destructive commands (delete/scale/label/... — where the
	// affected objects are otherwise invisible at the prompt, e.g. `delete pod -l
	// app=x` might match one pod or fifty). Best-effort: a failed preview warns and
	// prompts anyway. Off by default (adds a read round-trip per gated command).
	PreviewBeforeConfirm bool `yaml:"preview_before_confirm,omitempty"`

	// ConfirmTimeoutSeconds bounds how long the confirmation prompt waits for an
	// answer. 0 (default) waits forever, preserving the previous behavior. When
	// positive, an unanswered prompt aborts (fail-safe: an unanswered "are you
	// sure?" resolves to no) with the needs-confirmation exit code, audited as
	// aborted/timeout. Only affects the interactive prompt; --json/--yes/no-TTY
	// paths already resolve without blocking.
	ConfirmTimeoutSeconds int `yaml:"confirm_timeout_seconds,omitempty"`

	// SensitiveAccess gates the sensitive-access verbs on EVERY context:
	// "off" (default), "gate" (confirm), or "block" (refuse). See SensitiveVerbs.
	SensitiveAccess string `yaml:"sensitive_access,omitempty"`

	// SensitiveVerbs overrides which verbs the sensitive-access policy applies to.
	// Empty uses the defaults: exec, cp, attach, debug, port-forward, proxy.
	SensitiveVerbs []string `yaml:"sensitive_verbs,omitempty"`

	// SensitiveKinds gates STATE-ALTERING commands whose target kind (resource
	// token or -f manifest kind) matches, on EVERY context, while leaving reads
	// alone. SensitiveKind is the mode: "off" (default), "confirm", or "block".
	// Kinds are matched via NormalizeResource, so singular/plural/short-name all
	// hit (node/nodes/no). See guard.IsSensitiveKindActive.
	SensitiveKinds []string `yaml:"sensitive_kinds,omitempty"`
	SensitiveKind  string   `yaml:"sensitive_kind_mode,omitempty"`

	// BlastRadius gates wide-scope / bulk mutations on EVERY context: "off"
	// (default), "gate" (confirm), or "block" (refuse). Triggers are a destructive
	// verb with --all, a label/field selector, --all-namespaces, a force delete
	// (--force / --grace-period=0), or `apply --prune`. A genuine --dry-run is not
	// gated (it changes nothing). See guard.BlastRadius for the classifier.
	BlastRadius string `yaml:"blast_radius,omitempty"`

	// RedactOutput is the OPT-IN structured-output redaction mode (#108): "off"
	// (default) or "structured". Off is byte-for-byte identical to no guard on the
	// output path (syscall.Exec). Structured engages ONLY on a non-interactive,
	// non-watch `get -o json|yaml`, blanking KNOWN sensitive fields; it is
	// best-effort defense-in-depth, NOT a containment boundary. See RedactOutputMode.
	RedactOutput string `yaml:"redact_output,omitempty"`

	// CommandOverrides lets a team tailor the built-in safe/state-altering verb
	// classification without forking: mark a custom/plugin verb dangerous, or a
	// default-safe verb (e.g. logs) as requiring confirmation. See ClassifyOverride.
	CommandOverrides CommandOverrides `yaml:"command_overrides,omitempty"`

	// RequireConfirmWeakening, when true, makes a `config` change that WEAKENS
	// protection (removing a protected target, downgrading a mode, disabling the
	// audit/impersonation guards, …) require interactive confirmation; additive
	// changes stay frictionless. Every config change is audited regardless. Off by
	// default. See WeakensProtection.
	RequireConfirmWeakening bool `yaml:"require_confirm_weakening,omitempty"`

	// UnknownVerb is the strict-mode policy for a verb the guard cannot classify as
	// safe or state-altering, on a PROTECTED context/namespace: "allow" (default),
	// "gate" (require confirmation), or "deny" (refuse). Unknown verbs on
	// UNPROTECTED targets always pass, so plugins keep working elsewhere.
	UnknownVerb string `yaml:"unknown_verb,omitempty"`

	// StrictConfigPerms, when true, turns a group/world-writable config file from a
	// warning into a fatal fail-closed error (every command Denied until the mode is
	// fixed). Save writes the config 0600; a looser mode means another user (or a
	// misbehaving dotfiles manager) can rewrite the policy — e.g. empty the protected
	// lists — and silently disable protection. Off by default. Also settable via the
	// KUBECTL_GUARD_STRICT env var. See InsecureConfigPerms / StrictPerms.
	StrictConfigPerms bool `yaml:"strict_config_perms,omitempty"`

	// RequireJustification, when true, requires a free-text reason at confirmation
	// time for a gated command; the reason is recorded on the audit entry (for
	// compliance / post-incident review). An empty reason aborts (fail closed).
	// Non-interactive approvals supply it with --reason; --yes without a reason
	// aborts. Off by default. See ui reason capture and the --reason flag.
	RequireJustification bool `yaml:"require_justification,omitempty"`

	// ReadOnly is the global freeze / incident panic button. When true, EVERY
	// state-altering command is Blocked regardless of context/namespace/actor;
	// reads pass, a genuine --dry-run passes, and --yes does NOT override (it is
	// absolute, not a confirm). Toggled by `freeze`/`unfreeze`, or per-invocation
	// via the KUBECTL_GUARD_READONLY env var. See ReadOnlyActive.
	ReadOnly bool `yaml:"read_only,omitempty"`

	// InCluster is the policy for running with no named context (in a pod, or CI
	// with an in-cluster kubeconfig): "namespace" (default) gates by the resolved
	// serviceaccount namespace, "deny" fails closed, "allow" passes through. Empty
	// means the default.
	InCluster string `yaml:"in_cluster,omitempty"`

	// DiscoverShortNames controls whether the guard discovers CRD short names by
	// querying `kubectl api-resources` (cached), so protecting a CRD by its kind
	// also blocks its short name (e.g. protecting "secretstore" blocks
	// `kubectl get ss`). nil/true enables it (the default); set to false to opt
	// out (air-gapped / latency-sensitive). Discovery is best-effort and only ever
	// ADDS short names, so it can never weaken protection below the built-ins.
	DiscoverShortNames *bool `yaml:"discover_short_names,omitempty"`

	// Enforced marks a SYSTEM-layer config as an enforced baseline. It is
	// meaningful ONLY in the system layer (/etc/kubectl-guard/config.yaml, or
	// SystemConfigPath): when true, the system config is a protection FLOOR the
	// user cannot weaken, and the env escape hatches (KUBECTL_GUARD_BYPASS /
	// KUBECTL_GUARD_AUDIT_LOG / KUBECTL_GUARD_CONFIG) are forbidden. It is ignored
	// in a user config. See LoadEffective / Merge / EnforcedSystemConfig.
	Enforced bool `yaml:"enforced,omitempty"`

	// discovered maps a runtime-discovered short name to its canonical resource
	// form (e.g. "ss" -> "secretstore"). It is populated by the guard from the
	// api-resources cache before matching and is NOT serialized. nil means "not
	// discovered / built-ins only".
	discovered map[string]string `yaml:"-"`

	// systemEnforced is set on a MERGED config (by LoadEffective) when an enforced
	// system layer was applied. It is the single signal the env-forbidding checks
	// consult (AuditPath, Path). Never serialized; the merged config is never saved.
	systemEnforced bool `yaml:"-"`

	// auditLogPinned is set on a MERGED config when an enforced system layer pins
	// the audit destination (system audit_log non-empty). "" = not pinned. Exposed
	// via PinnedAuditLog for display; env-ignoring itself is gated on systemEnforced
	// so an enforced baseline that does NOT set audit_log still ignores the env
	// override and falls back to the default (never the env). Never serialized.
	auditLogPinned string `yaml:"-"`

	// systemLayer is the raw SYSTEM-layer config that produced a MERGED config
	// (nil when there is no system layer). It backs `config list` provenance
	// ("[system]" tags) and doctor's baseline reporting. Never serialized.
	systemLayer *Config `yaml:"-"`
}

// defaultSensitiveVerbs are the verbs the sensitive-access policy applies to
// when SensitiveVerbs is not overridden: interactive / data-movement / reach
// verbs that read into or open a channel to a workload with the caller's
// credentials. debug is included because `debug node/...` gives a root shell on
// the node and `debug` ephemeral containers can read a running pod's secrets and
// serviceaccount token — the same exfiltration path as exec. proxy exposes the
// whole API server locally, like port-forward tunnels to one workload.
var defaultSensitiveVerbs = []string{"exec", "cp", "attach", "debug", "port-forward", "proxy"}

// SensitiveAccessMode returns the sensitive-access policy, defaulting to off.
// An invalid value is caught by Validate (fail-closed), so off is only reached
// for the genuine default.
func (c *Config) SensitiveAccessMode() string {
	switch c.SensitiveAccess {
	case SensitiveAccessGate, SensitiveAccessBlock:
		return c.SensitiveAccess
	default:
		return SensitiveAccessOff
	}
}

// IsSensitiveVerb reports whether verb is in the sensitive-access verb set — the
// configured override, or the defaults. Comparison is case-insensitive and
// trims whitespace on the configured entries, so a quoted YAML value like
// `- " exec "` still matches (it would otherwise pass validation but silently
// never match — a fail-open on the user's intent).
func (c *Config) IsSensitiveVerb(verb string) bool {
	verbs := c.SensitiveVerbs
	if len(verbs) == 0 {
		verbs = defaultSensitiveVerbs
	}
	verb = strings.TrimSpace(verb)
	for _, v := range verbs {
		if strings.EqualFold(strings.TrimSpace(v), verb) {
			return true
		}
	}
	return false
}

// CommandOverrides tailors command classification. safe moves a verb to
// read-only (pass-through); state_altering and unsafe_safe both move a verb to
// state-altering (gated) — the two names distinguish intent (add a custom
// dangerous verb vs. promote a default-safe one like logs), but resolve
// identically. All matching is case-insensitive and whitespace-trimmed.
type CommandOverrides struct {
	// Safe verbs are treated as read-only, passing through even if a built-in
	// classifies them as state-altering (a deliberate, documented downgrade).
	Safe []string `yaml:"safe,omitempty"`
	// StateAltering verbs are treated as state-altering (gated on protected
	// contexts/namespaces) — for a custom or plugin verb the guard cannot know.
	StateAltering []string `yaml:"state_altering,omitempty"`
	// UnsafeSafe promotes a DEFAULT-SAFE verb (e.g. logs, if apps log secrets) to
	// state-altering, so it requires confirmation. Resolves the same as
	// StateAltering; kept separate to document the "this was safe, make it gated"
	// intent.
	UnsafeSafe []string `yaml:"unsafe_safe,omitempty"`
}

// CommandClass is the classification a command-override assigns to a verb.
type CommandClass int

const (
	// ClassNone means no override applies; the built-in classification is used.
	ClassNone CommandClass = iota
	// ClassSafe means the verb is treated as read-only (pass-through).
	ClassSafe
	// ClassStateAltering means the verb is treated as state-altering (gated).
	ClassStateAltering
)

// ClassifyOverride returns the override class for a verb, or ClassNone when no
// override applies. State-altering (including unsafe_safe) wins a contradiction
// with safe — the most-restrictive resolution, so a verb listed in both is gated
// rather than passed. Case-insensitive and whitespace-trimmed.
func (c *Config) ClassifyOverride(verb string) CommandClass {
	verb = strings.ToLower(strings.TrimSpace(verb))
	if verb == "" {
		return ClassNone
	}
	if containsFold(c.CommandOverrides.StateAltering, verb) || containsFold(c.CommandOverrides.UnsafeSafe, verb) {
		return ClassStateAltering
	}
	if containsFold(c.CommandOverrides.Safe, verb) {
		return ClassSafe
	}
	return ClassNone
}

// containsFold reports whether list contains verb, comparing case-insensitively
// after trimming whitespace on each entry.
func containsFold(list []string, verb string) bool {
	for _, v := range list {
		if strings.EqualFold(strings.TrimSpace(v), verb) {
			return true
		}
	}
	return false
}

// SetCommandOverride classifies verb as ClassSafe or ClassStateAltering, removing
// it from any other override list first so the two never contradict. It returns
// false for an empty verb or an unusable class. A verb set to ClassStateAltering
// lands in the state_altering list (unsafe_safe is a hand-authored alias only).
func (c *Config) SetCommandOverride(verb string, class CommandClass) bool {
	verb = strings.ToLower(strings.TrimSpace(verb))
	if verb == "" || (class != ClassSafe && class != ClassStateAltering) {
		return false
	}
	c.removeCommandOverride(verb)
	switch class {
	case ClassSafe:
		c.CommandOverrides.Safe = append(c.CommandOverrides.Safe, verb)
	case ClassStateAltering:
		c.CommandOverrides.StateAltering = append(c.CommandOverrides.StateAltering, verb)
	}
	return true
}

// RemoveCommandOverride deletes verb from every override list, reporting whether
// it was present in any.
func (c *Config) RemoveCommandOverride(verb string) bool {
	verb = strings.ToLower(strings.TrimSpace(verb))
	present := containsFold(c.CommandOverrides.Safe, verb) ||
		containsFold(c.CommandOverrides.StateAltering, verb) ||
		containsFold(c.CommandOverrides.UnsafeSafe, verb)
	c.removeCommandOverride(verb)
	return present
}

// removeCommandOverride strips verb from all three override lists.
func (c *Config) removeCommandOverride(verb string) {
	c.CommandOverrides.Safe = withoutFold(c.CommandOverrides.Safe, verb)
	c.CommandOverrides.StateAltering = withoutFold(c.CommandOverrides.StateAltering, verb)
	c.CommandOverrides.UnsafeSafe = withoutFold(c.CommandOverrides.UnsafeSafe, verb)
}

// withoutFold returns list with every case-insensitive match of verb removed.
func withoutFold(list []string, verb string) []string {
	out := list[:0:0]
	for _, v := range list {
		if !strings.EqualFold(strings.TrimSpace(v), verb) {
			out = append(out, v)
		}
	}
	return out
}

// UnknownVerbMode returns the unknown-verb policy, defaulting to allow. An
// invalid value is caught by Validate (fail-closed), so allow is only reached for
// the genuine default.
func (c *Config) UnknownVerbMode() string {
	switch c.UnknownVerb {
	case UnknownVerbGate, UnknownVerbDeny:
		return c.UnknownVerb
	default:
		return UnknownVerbAllow
	}
}

// SetUnknownVerb sets the unknown-verb policy if valid. The valid-value check is
// validUnknownVerbMode (config/validate.go), shared with Validate.
func (c *Config) SetUnknownVerb(mode string) bool {
	if !validUnknownVerbMode(mode) {
		return false
	}
	c.UnknownVerb = mode
	return true
}

// SensitiveKindMode returns the sensitive-kind policy, defaulting to off. An
// invalid value is caught by Validate (fail-closed).
func (c *Config) SensitiveKindMode() string {
	switch c.SensitiveKind {
	case SensitiveKindConfirm, SensitiveKindBlock:
		return c.SensitiveKind
	default:
		return SensitiveKindOff
	}
}

// HasSensitiveKinds reports whether any sensitive kinds are configured.
func (c *Config) HasSensitiveKinds() bool {
	return len(c.SensitiveKinds) > 0
}

// IsSensitiveKind reports whether candidate names a configured sensitive kind,
// case-insensitively and treating singular/plural/short-name forms as equivalent
// (node/nodes/no, namespace/ns, persistentvolume/pv).
func (c *Config) IsSensitiveKind(candidate string) bool {
	if candidate == "" || len(c.SensitiveKinds) == 0 {
		return false
	}
	nc := NormalizeResource(candidate)
	for _, k := range c.SensitiveKinds {
		if NormalizeResource(k) == nc {
			return true
		}
	}
	return false
}

// SetSensitiveKindMode sets the sensitive-kind policy if valid.
func (c *Config) SetSensitiveKindMode(mode string) bool {
	if !validSensitiveKindMode(mode) {
		return false
	}
	c.SensitiveKind = mode
	return true
}

// AddSensitiveKind adds a kind to the sensitive list if an equivalent entry is
// not already present. Returns false if it was already sensitive.
func (c *Config) AddSensitiveKind(name string) bool {
	norm := NormalizeResource(name)
	if norm == "" {
		return false
	}
	for _, k := range c.SensitiveKinds {
		if NormalizeResource(k) == norm {
			return false
		}
	}
	c.SensitiveKinds = append(c.SensitiveKinds, name)
	return true
}

// RemoveSensitiveKind removes a kind from the sensitive list. Returns false if it
// was not present.
func (c *Config) RemoveSensitiveKind(name string) bool {
	norm := NormalizeResource(name)
	for i, k := range c.SensitiveKinds {
		if NormalizeResource(k) == norm {
			c.SensitiveKinds = append(c.SensitiveKinds[:i], c.SensitiveKinds[i+1:]...)
			return true
		}
	}
	return false
}

// BlastRadiusMode returns the blast-radius policy, defaulting to off. An invalid
// value is caught by Validate (fail-closed), so off is only reached for the
// genuine default.
func (c *Config) BlastRadiusMode() string {
	switch c.BlastRadius {
	case BlastRadiusGate, BlastRadiusBlock:
		return c.BlastRadius
	default:
		return BlastRadiusOff
	}
}

// RedactOutputMode returns the output-redaction policy, defaulting to off. It
// returns RedactOutputStructured ONLY when the field is exactly that value;
// every other value — including the empty default and an invalid string (caught
// by Validate, which fails the config closed) — is off. Nil-safe: a nil config
// is off, so the redaction path is unreachable unless "structured" is explicitly
// configured (HARD INVARIANT #1: off is byte-for-byte identical to today).
func (c *Config) RedactOutputMode() string {
	if c != nil && c.RedactOutput == RedactOutputStructured {
		return RedactOutputStructured
	}
	return RedactOutputOff
}

// SetRedactOutputMode sets the output-redaction policy if valid. The valid-value
// check is validRedactOutputMode (config/validate.go), shared with Validate, so
// the setter and validator can never disagree.
func (c *Config) SetRedactOutputMode(mode string) bool {
	if !validRedactOutputMode(mode) {
		return false
	}
	c.RedactOutput = mode
	return true
}

// InClusterMode returns the configured in-cluster policy, defaulting to
// InClusterNamespace when unset. An invalid value is caught by Validate (which
// fails the config closed), so it is never reached here at runtime; defaulting to
// the safe "namespace" is the conservative fallback regardless.
func (c *Config) InClusterMode() string {
	switch c.InCluster {
	case InClusterDeny, InClusterAllow:
		return c.InCluster
	default:
		return InClusterNamespace
	}
}

// ShouldDiscoverShortNames reports whether CRD short-name discovery is enabled.
// It defaults to true; only an explicit `discover_short_names: false` disables it.
func (c *Config) ShouldDiscoverShortNames() bool {
	return c.DiscoverShortNames == nil || *c.DiscoverShortNames
}

// SetDiscoveredShortNames installs the runtime-discovered short-name map used by
// resource matching. The guard calls it after loading the api-resources cache;
// a nil or empty map leaves matching on the built-in short names only.
func (c *Config) SetDiscoveredShortNames(m map[string]string) {
	c.discovered = m
}

// ApplyDefaults fills in zero-value fields with sensible defaults.
func (c *Config) ApplyDefaults() {
	if c.ConfirmMode == "" {
		c.ConfirmMode = ConfirmModeSimple
	}
	if c.AuditMode == "" {
		c.AuditMode = AuditModeAll
	}
	if c.ContextMode == "" {
		c.ContextMode = ContextModeConfirm
	}
	if c.NamespaceMode == "" {
		c.NamespaceMode = NamespaceModeConfirm
	}
}

// ShouldAudit reports whether an entry with the given outcome should be
// written, based on the configured audit mode. outcome is one of the
// guard.Outcome* constants (passed as a string to avoid an import cycle).
func (c *Config) ShouldAudit(outcome string) bool {
	switch c.AuditMode {
	case AuditModeOff:
		return false
	case AuditModeGated:
		return outcome != "allowed"
	default: // AuditModeAll
		return true
	}
}

// defaultAuditMaxFiles is how many rotated archives to keep when rotation is on
// but audit_max_files was not set.
const defaultAuditMaxFiles = 5

// AuditMaxFilesOrDefault returns the configured archive count, or the default
// when unset. It is never less than 1 when rotation is active, so a rotation
// always preserves at least one archive rather than discarding the log.
func (c *Config) AuditMaxFilesOrDefault() int {
	if c.AuditMaxFiles > 0 {
		return c.AuditMaxFiles
	}
	return defaultAuditMaxFiles
}

// SetAuditMode sets the audit mode if the value is valid. The valid-value check
// is validAuditMode (config/validate.go), the single source of truth shared with
// Config.Validate, so the setter and the validator can never disagree.
func (c *Config) SetAuditMode(mode string) bool {
	if !validAuditMode(mode) {
		return false
	}
	c.AuditMode = mode
	return true
}

// defaultUserConfigPath returns the HOME-based user config location
// (~/.kubectl-guard.yaml), the non-env branch of Path(). It is the path the user
// layer loads from under an enforced system config, where KUBECTL_GUARD_CONFIG is
// forbidden.
func defaultUserConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, configFileName), nil
}

// Path returns the full path to the USER config file. The KUBECTL_GUARD_CONFIG
// env var overrides the location (for team / containerized / CI use where $HOME
// is not the right place). Without it, the default is ~/.kubectl-guard.yaml.
//
// EXCEPTION (issue #86): when an ENFORCED system config is present, the env
// override is IGNORED and the default path is used — an enforced baseline must
// not be defeatable by pointing the user layer somewhere the admin cannot see.
// The SYSTEM config path itself (SystemConfigPath) is never env-derived, so this
// cannot be self-referentially defeated. Making Path() enforcement-aware routes
// BOTH the decision path (LoadEffective) and the mutation path (Load/Save via
// Path) at the same file, so `config add-context` edits exactly what the guard
// reads.
func Path() (string, error) {
	if enforcedSystemActive() {
		return defaultUserConfigPath()
	}
	if p := strings.TrimSpace(os.Getenv(EnvConfig)); p != "" {
		return p, nil
	}
	return defaultUserConfigPath()
}

// AuditPath returns the audit log path. Precedence, highest first: the
// KUBECTL_GUARD_AUDIT_LOG env var (a per-invocation override, symmetric with
// KUBECTL_GUARD_CONFIG), then the config's audit_log field, then the default
// ~/.kubectl-guard-audit.log. The env var wins over the config field so a
// container/CI runner can redirect the log without editing a mounted config.
//
// EXCEPTION (issue #86): when cfg comes from an ENFORCED system baseline
// (cfg.SystemEnforced()), the env override is IGNORED — an enforced audit trail
// must not be redirectable away by an env var. The destination is then the merged
// audit_log field (the system's pinned value if it set one, else the user's) or
// the default. This is stronger than pinning only when the system sets audit_log:
// it fully honors the non-negotiable "an enforced baseline is not one env var from
// off" invariant, so even an enforced baseline that leaves audit_log unset writes
// to the default rather than the attacker-chosen env path.
func AuditPath(cfg *Config) (string, error) {
	if !cfg.SystemEnforced() {
		if p := strings.TrimSpace(os.Getenv(EnvAuditLog)); p != "" {
			return p, nil
		}
	}
	if cfg != nil && cfg.AuditLog != "" {
		return cfg.AuditLog, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, auditFileName), nil
}

// Exists checks if the config file exists.
func Exists() (bool, error) {
	path, err := Path()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Load reads the config from disk.
func Load() (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		// Wrap the raw yaml library error ("yaml: line 1: ...") with context so
		// callers surface an actionable message ("config file <path> is not valid
		// YAML: ...") rather than a bare library string.
		return nil, fmt.Errorf("config file %s is not valid YAML: %w", path, err)
	}

	cfg.ApplyDefaults()
	return &cfg, nil
}

// InsecureConfigPerms reports whether the config file OR its parent directory is
// writable by group/other — either lets another user disable protection by
// rewriting the policy (e.g. emptying the protected lists). Two vectors:
//
//   - A writable FILE (mode & 0o022) can be rewritten in place. Only the write
//     bits matter — a group/world READABLE config (e.g. 0644 rw-r--r--) cannot be
//     rewritten by others, so 0600/0640/0644 are safe; 0660/0664/0666 are not.
//   - A writable parent DIRECTORY lets an attacker atomically REPLACE the config
//     with a fresh 0600 file (rename), so a file-only check gives false assurance.
//     A sticky world-writable directory (e.g. /tmp) is safe, because only the
//     owner may rename or delete their own file there, so the sticky bit exempts it.
//
// Returns insecure=false when the file does not exist (nothing to tamper) so
// callers need not special-case first run. detail describes the specific problem
// for the warning/deny message.
func InsecureConfigPerms() (insecure bool, detail string, err error) {
	path, err := Path()
	if err != nil {
		return false, "", err
	}
	return insecurePermsAt(path)
}

// SystemConfigInsecurePerms reports whether the enforced system config file (or
// its parent directory) is group/world-writable — a LIGHT integrity check (#86,
// co-designed with #133). A hostile system file can only ADD protection (Merge is
// most-restrictive), so this is about integrity, not a bypass; it surfaces as a
// doctor warning. Returns insecure=false when the file does not exist. The full
// uid==0 ancestor-ownership walk is deferred to #133 — getting /etc ownership
// right is the OS's job.
func SystemConfigInsecurePerms() (insecure bool, detail string, err error) {
	return insecurePermsAt(SystemConfigPath)
}

// insecurePermsAt is the shared permission check behind InsecureConfigPerms and
// SystemConfigInsecurePerms.
func insecurePermsAt(path string) (insecure bool, detail string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, "", nil
		}
		return false, "", err
	}
	if m := info.Mode().Perm(); m&0o022 != 0 {
		return true, fmt.Sprintf("config file %s is group/world-writable (mode %#o)", path, uint32(m)), nil
	}
	// The file's own mode is safe, but a writable, non-sticky parent directory
	// lets an attacker replace the file wholesale while keeping it 0600.
	dir := filepath.Dir(path)
	if di, derr := os.Stat(dir); derr == nil {
		dm := di.Mode()
		if dm.Perm()&0o022 != 0 && dm&os.ModeSticky == 0 {
			return true, fmt.Sprintf("config directory %s is group/world-writable (mode %#o) and not sticky; the config can be replaced", dir, uint32(dm.Perm())), nil
		}
	}
	return false, "", nil
}

// StrictPerms reports whether strict config-permission enforcement is active,
// from either the config field or the KUBECTL_GUARD_STRICT env var. When on, a
// writable config fails closed instead of merely warning.
func (c *Config) StrictPerms() bool {
	if c != nil && c.StrictConfigPerms {
		return true
	}
	return boolEnv(EnvStrict)
}

// ReadOnlyActive reports whether global read-only / freeze mode is on, from
// either the config field or the KUBECTL_GUARD_READONLY env var (a per-invocation
// override, e.g. `KUBECTL_GUARD_READONLY=1 kubectl ...` during an incident).
func (c *Config) ReadOnlyActive() bool {
	if c != nil && c.ReadOnly {
		return true
	}
	return boolEnv(EnvReadOnly)
}

// SystemEnforced reports whether this (merged) config was produced with an
// enforced system baseline applied. It is the signal the env-forbidding checks
// consult. Nil-safe (a nil config is not enforced).
func (c *Config) SystemEnforced() bool {
	return c != nil && c.systemEnforced
}

// PinnedAuditLog returns the audit destination pinned by an enforced system
// baseline (system audit_log), and whether one is pinned. Used for display;
// AuditPath's env-ignoring is gated on SystemEnforced, not on this.
func (c *Config) PinnedAuditLog() (string, bool) {
	if c == nil || c.auditLogPinned == "" {
		return "", false
	}
	return c.auditLogPinned, true
}

// SystemLayer returns the raw SYSTEM-layer config that produced this merged
// config, or nil when there is no system layer. It backs `config list`
// provenance and doctor's baseline reporting.
func (c *Config) SystemLayer() *Config {
	if c == nil {
		return nil
	}
	return c.systemLayer
}

// Save writes the config to disk atomically.
func Save(cfg *Config) error {
	path, err := Path()
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	header := "# kubectl-guard configuration\n# Protect production contexts and sensitive resources from accidental commands\n\n"
	content := []byte(header + string(data))

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".kubectl-guard-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op if rename succeeded

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// IsContextProtected checks if a context matches any protected pattern.
// Patterns use the glob semantics documented in glob.go: '*' matches any run of
// characters (including '/' and ':', so it spans EKS ARNs and path-shaped
// context names), '?' matches one character, and '[...]' matches a class.
func (c *Config) IsContextProtected(context string) bool {
	for _, pp := range c.ProtectedContexts {
		if matchGlob(pp.Pattern, context) {
			return true
		}
	}
	return false
}

// AddContext adds a context pattern to the protected list (inheriting the global
// mode) if the exact pattern is not already present. It is a pure no-op on an
// existing pattern — it never touches an existing pattern's mode, so a plain
// re-add can never downgrade a block pattern. Use AddContextWithMode to set or
// change a per-pattern mode.
func (c *Config) AddContext(pattern string) bool {
	for i := range c.ProtectedContexts {
		if c.ProtectedContexts[i].Pattern == pattern {
			return false
		}
	}
	c.ProtectedContexts = append(c.ProtectedContexts, ProtectedPattern{Pattern: pattern})
	return true
}

// AddContextWithMode adds a protected context pattern with an explicit per-pattern
// mode ("" = inherit, "confirm", or "block"), or UPDATES the mode of an existing
// pattern. Adding a new pattern, or changing an existing pattern's mode (e.g.
// `add-context prod-* --mode block` upgrading an inherit/confirm entry to block),
// returns true; re-adding with the SAME mode is a no-op returning false. An
// invalid mode is rejected (returns false, no change) so the config fails closed.
//
// Downgrading via this method (e.g. block → inherit/confirm) is permitted but is
// classified as weakening by WeakensProtection and thus audited/gated like any
// other protection reduction.
func (c *Config) AddContextWithMode(pattern, mode string) bool {
	if mode != "" && !validContextMode(mode) {
		return false
	}
	for i := range c.ProtectedContexts {
		if c.ProtectedContexts[i].Pattern == pattern {
			if c.ProtectedContexts[i].Mode == mode {
				return false
			}
			c.ProtectedContexts[i].Mode = mode
			return true
		}
	}
	c.ProtectedContexts = append(c.ProtectedContexts, ProtectedPattern{Pattern: pattern, Mode: mode})
	return true
}

// RemoveContext removes a context pattern from the protected list.
func (c *Config) RemoveContext(pattern string) bool {
	for i := range c.ProtectedContexts {
		if c.ProtectedContexts[i].Pattern == pattern {
			c.ProtectedContexts = append(c.ProtectedContexts[:i], c.ProtectedContexts[i+1:]...)
			return true
		}
	}
	return false
}

// HasProtectedClusters reports whether any cluster-identity protection is
// configured. When false, the guard never resolves a server (name-based
// protection is byte-identical to before this feature).
func (c *Config) HasProtectedClusters() bool {
	return len(c.ProtectedClusters) > 0
}

// IsClusterProtected reports whether the resolved API server matches any
// protected_clusters entry. Comparison is case-insensitive (see
// ProtectedCluster.matches).
func (c *Config) IsClusterProtected(server string) bool {
	for _, pc := range c.ProtectedClusters {
		if pc.matches(server) {
			return true
		}
	}
	return false
}

// EffectiveClusterMode returns the MOST RESTRICTIVE mode among the protected
// cluster entries matching server: a matching entry with an explicit Mode uses
// that mode; a matching entry with Mode=="" inherits the global CONTEXT mode.
// block beats confirm. When no entry matches, the global context mode is the
// fallback. Mirrors mostRestrictiveMode / EffectiveContextMode for the cluster
// axis (which reuses the context mode constants and global).
func (c *Config) EffectiveClusterMode(server string) string {
	global := c.effectiveContextMode()
	matched := false
	for _, pc := range c.ProtectedClusters {
		if !pc.matches(server) {
			continue
		}
		matched = true
		mode := pc.Mode
		if mode == "" {
			mode = global
		}
		if mode == ContextModeBlock {
			return ContextModeBlock
		}
	}
	if !matched {
		return global
	}
	return ContextModeConfirm
}

// ProtectedClusterKeys returns the display/completion keys of the protected
// cluster list (e.g. "server=https://prod", "server_pattern=*.prod.example.com"),
// for `config list` and shell completion.
func (c *Config) ProtectedClusterKeys() []string {
	out := make([]string, 0, len(c.ProtectedClusters))
	for _, pc := range c.ProtectedClusters {
		out = append(out, pc.key())
	}
	return out
}

// AddProtectedCluster adds (or updates the mode of) a protected cluster entry.
// value is treated as an exact Server unless it contains a glob metacharacter
// (* ? [), in which case it is a ServerPattern. Dedupe is by the (Server|
// ServerPattern) value: re-adding an existing entry updates its Mode (returns
// true) or is a no-op if the mode is identical (returns false). An empty value or
// an invalid mode is rejected (returns false plus an error) so the config fails
// closed rather than silently dropping the intended protection.
func (c *Config) AddProtectedCluster(value, mode string) (changed bool, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, fmt.Errorf("protected cluster value is empty (want a server URL or a server pattern)")
	}
	if mode != "" && !validContextMode(mode) {
		return false, fmt.Errorf("invalid mode %q (want %q or %q)", mode, ContextModeConfirm, ContextModeBlock)
	}
	isPattern := strings.ContainsAny(value, "*?[")
	for i := range c.ProtectedClusters {
		pc := c.ProtectedClusters[i]
		if (isPattern && pc.ServerPattern == value) || (!isPattern && pc.Server == value) {
			if c.ProtectedClusters[i].Mode == mode {
				return false, nil
			}
			c.ProtectedClusters[i].Mode = mode
			return true, nil
		}
	}
	entry := ProtectedCluster{Mode: mode}
	if isPattern {
		entry.ServerPattern = value
	} else {
		entry.Server = value
	}
	c.ProtectedClusters = append(c.ProtectedClusters, entry)
	return true, nil
}

// RemoveProtectedCluster removes an entry identified by its Server or
// ServerPattern string. It also accepts the display key form ("server=..." /
// "server_pattern=...") so a value taken from ProtectedClusterKeys (e.g. shell
// completion) removes the entry it names. Returns false if nothing matched.
func (c *Config) RemoveProtectedCluster(value string) bool {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "server_pattern=")
	value = strings.TrimPrefix(value, "server=")
	for i := range c.ProtectedClusters {
		pc := c.ProtectedClusters[i]
		if pc.Server == value || pc.ServerPattern == value {
			c.ProtectedClusters = append(c.ProtectedClusters[:i], c.ProtectedClusters[i+1:]...)
			return true
		}
	}
	return false
}

// HasProtectedNamespaces reports whether any namespace protection is configured.
func (c *Config) HasProtectedNamespaces() bool {
	return len(c.ProtectedNamespaces) > 0
}

// IsNamespaceProtected checks if a namespace matches any protected pattern.
// It uses the same matcher as IsContextProtected, so context and namespace
// patterns can never disagree about what a glob means.
func (c *Config) IsNamespaceProtected(namespace string) bool {
	for _, pp := range c.ProtectedNamespaces {
		if matchGlob(pp.Pattern, namespace) {
			return true
		}
	}
	return false
}

// AddNamespace adds a namespace pattern (inheriting the global mode) if the exact
// pattern is not already present. Like AddContext it is a pure no-op on an
// existing pattern, never touching its mode. Use AddNamespaceWithMode to set one.
func (c *Config) AddNamespace(pattern string) bool {
	for i := range c.ProtectedNamespaces {
		if c.ProtectedNamespaces[i].Pattern == pattern {
			return false
		}
	}
	c.ProtectedNamespaces = append(c.ProtectedNamespaces, ProtectedPattern{Pattern: pattern})
	return true
}

// AddNamespaceWithMode adds or UPDATES a protected namespace pattern with an
// explicit per-pattern mode ("" = inherit, "confirm", or "block"). Semantics
// mirror AddContextWithMode: a new pattern or a mode change returns true, the
// same mode is a no-op, and an invalid mode is rejected (fail closed).
func (c *Config) AddNamespaceWithMode(pattern, mode string) bool {
	if mode != "" && !validNamespaceMode(mode) {
		return false
	}
	for i := range c.ProtectedNamespaces {
		if c.ProtectedNamespaces[i].Pattern == pattern {
			if c.ProtectedNamespaces[i].Mode == mode {
				return false
			}
			c.ProtectedNamespaces[i].Mode = mode
			return true
		}
	}
	c.ProtectedNamespaces = append(c.ProtectedNamespaces, ProtectedPattern{Pattern: pattern, Mode: mode})
	return true
}

// RemoveNamespace removes a namespace pattern from the protected list.
func (c *Config) RemoveNamespace(pattern string) bool {
	for i := range c.ProtectedNamespaces {
		if c.ProtectedNamespaces[i].Pattern == pattern {
			c.ProtectedNamespaces = append(c.ProtectedNamespaces[:i], c.ProtectedNamespaces[i+1:]...)
			return true
		}
	}
	return false
}

// SetContextMode sets the context protection mode if valid.
func (c *Config) SetContextMode(mode string) bool {
	if !validContextMode(mode) {
		return false
	}
	c.ContextMode = mode
	return true
}

// SetNamespaceMode sets the namespace protection mode if valid.
func (c *Config) SetNamespaceMode(mode string) bool {
	if !validNamespaceMode(mode) {
		return false
	}
	c.NamespaceMode = mode
	return true
}

// SetBlastRadiusMode sets the blast-radius policy if valid. The valid-value
// check is validBlastRadiusMode (config/validate.go), shared with Validate, so
// the setter and the validator can never disagree.
func (c *Config) SetBlastRadiusMode(mode string) bool {
	if !validBlastRadiusMode(mode) {
		return false
	}
	c.BlastRadius = mode
	return true
}

// ActorPolicy overrides the global context_mode / namespace_mode for a specific
// actor (matched by glob). An empty mode field means "inherit the global mode".
type ActorPolicy struct {
	// Actor is the actor name or glob pattern this policy applies to (e.g.
	// "claude-code", "ci-*").
	Actor string `yaml:"actor"`
	// ContextMode overrides context_mode for matching actors ("confirm"|"block"),
	// or "" to inherit the global context_mode.
	ContextMode string `yaml:"context_mode,omitempty"`
	// NamespaceMode overrides namespace_mode for matching actors, or "" to inherit.
	NamespaceMode string `yaml:"namespace_mode,omitempty"`
}

// effectiveContextMode / effectiveNamespaceMode return the configured global mode
// with the safe default filled in. Validate rejects an invalid value and
// ApplyDefaults fills the common case, but a config that skipped ApplyDefaults
// (or set only one field) must still resolve to a valid mode here.
func (c *Config) effectiveContextMode() string {
	if c.ContextMode == ContextModeBlock {
		return ContextModeBlock
	}
	return ContextModeConfirm
}

func (c *Config) effectiveNamespaceMode() string {
	if c.NamespaceMode == NamespaceModeBlock {
		return NamespaceModeBlock
	}
	return NamespaceModeConfirm
}

// EffectiveContextMode returns the protection mode that applies to a context: the
// MOST RESTRICTIVE mode among all protected patterns that match it. A matching
// pattern with an explicit Mode uses that mode; a matching pattern with Mode==""
// inherits the global context mode. "block" is more restrictive than "confirm",
// so the result is block if ANY matching pattern resolves to block. When no
// pattern matches, the global context mode is returned unchanged.
//
// The "most restrictive" is taken only AMONG matching patterns: an explicit
// `mode: confirm` on a matching pattern resolves to confirm even when the global
// context_mode is block — that is the purpose of a per-pattern override. The
// global mode is used solely as the inherited value for a no-mode pattern and as
// the fallback when nothing matches.
func (c *Config) EffectiveContextMode(context string) string {
	return mostRestrictiveMode(c.ProtectedContexts, context, c.effectiveContextMode())
}

// EffectiveNamespaceMode is EffectiveContextMode's namespace equivalent: the most
// restrictive per-pattern mode among protected namespace patterns matching the
// namespace, else the global namespace mode.
func (c *Config) EffectiveNamespaceMode(namespace string) string {
	return mostRestrictiveMode(c.ProtectedNamespaces, namespace, c.effectiveNamespaceMode())
}

// MostRestrictiveNamespaceMode returns the most restrictive per-pattern namespace
// mode across ALL configured namespace patterns. It is used when a command spans
// every namespace (--all-namespaces) or names a wide namespace target the guard
// cannot enumerate: such a command touches every protected namespace, so it must
// inherit the strongest mode any of them carries. block wins; otherwise confirm;
// the global namespace mode is the floor/fallback when no pattern is configured.
func (c *Config) MostRestrictiveNamespaceMode() string {
	global := c.effectiveNamespaceMode()
	matched := false
	for _, pp := range c.ProtectedNamespaces {
		matched = true
		mode := pp.Mode
		if mode == "" {
			mode = global
		}
		if mode == NamespaceModeBlock {
			return NamespaceModeBlock
		}
	}
	if !matched {
		return global
	}
	return NamespaceModeConfirm
}

// mostRestrictiveMode resolves the effective mode for target against patterns.
// global is BOTH the mode a matching no-mode pattern inherits AND the fallback
// when no pattern matches. Among matching patterns block beats confirm (most
// restrictive); a matching pattern's explicit mode is honored as-is (it may be
// confirm even when global is block — a per-pattern override). The mode constants
// share values across the context/namespace axes ("block"/"confirm"), so this one
// helper serves both.
func mostRestrictiveMode(patterns []ProtectedPattern, target, global string) string {
	matched := false
	for _, pp := range patterns {
		if !matchGlob(pp.Pattern, target) {
			continue
		}
		matched = true
		mode := pp.Mode
		if mode == "" {
			mode = global
		}
		// block is the most restrictive mode; once any matching pattern resolves to
		// block, the answer cannot get more restrictive, so return immediately.
		if mode == ContextModeBlock {
			return ContextModeBlock
		}
	}
	if !matched {
		return global
	}
	// At least one pattern matched and none resolved to block ⇒ confirm.
	return ContextModeConfirm
}

// EffectiveModesForActor returns the context_mode and namespace_mode that apply
// to the given actor for a specific context and namespace: the PER-PATTERN base
// modes (EffectiveContextMode / EffectiveNamespaceMode for that context/namespace),
// made STRICTER by any matching actor policy. Because block is the most
// restrictive mode and a policy can only upgrade confirm → block (never
// downgrade), a matching actor policy can tighten protection for a known agent
// label but never weaken it below the per-pattern/global posture — the correct
// stance for a self-asserted identity. An unset or unmatched actor yields exactly
// the per-pattern base modes.
//
// Note: the namespace argument is the run-in namespace; a command may also target
// a protected namespace by NAME or via --all-namespaces, whose governing mode the
// guard folds in separately (see guard.effectiveNamespaceModeForTarget). Actor
// tightening here is unconditional (block regardless of which namespace), so it
// composes correctly with that fold-in.
func (c *Config) EffectiveModesForActor(actor, context, namespace string) (contextMode, namespaceMode string) {
	contextMode = c.EffectiveContextMode(context)
	namespaceMode = c.EffectiveNamespaceMode(namespace)
	for _, ap := range c.ActorPolicies {
		if !matchGlob(ap.Actor, actor) {
			continue
		}
		if ap.ContextMode == ContextModeBlock {
			contextMode = ContextModeBlock
		}
		if ap.NamespaceMode == NamespaceModeBlock {
			namespaceMode = NamespaceModeBlock
		}
	}
	return contextMode, namespaceMode
}

// SetActorPolicy adds or replaces the policy for an exact actor pattern, setting
// its context and namespace modes. An empty mode string means "inherit the
// global mode". It returns false if the actor is empty or a supplied mode is
// invalid (the valid-value checks are shared with Validate).
func (c *Config) SetActorPolicy(actor, contextMode, namespaceMode string) bool {
	if strings.TrimSpace(actor) == "" {
		return false
	}
	if contextMode != "" && !validContextMode(contextMode) {
		return false
	}
	if namespaceMode != "" && !validNamespaceMode(namespaceMode) {
		return false
	}
	for i := range c.ActorPolicies {
		if c.ActorPolicies[i].Actor == actor {
			c.ActorPolicies[i].ContextMode = contextMode
			c.ActorPolicies[i].NamespaceMode = namespaceMode
			return true
		}
	}
	c.ActorPolicies = append(c.ActorPolicies, ActorPolicy{
		Actor: actor, ContextMode: contextMode, NamespaceMode: namespaceMode,
	})
	return true
}

// RemoveActorPolicy deletes the policy for an exact actor pattern, reporting
// whether one was present.
func (c *Config) RemoveActorPolicy(actor string) bool {
	for i := range c.ActorPolicies {
		if c.ActorPolicies[i].Actor == actor {
			c.ActorPolicies = append(c.ActorPolicies[:i], c.ActorPolicies[i+1:]...)
			return true
		}
	}
	return false
}

// resourceShortNames maps kubectl built-in short names to their canonical
// singular form, so that protecting "configmap" also blocks "cm". Best-effort:
// covers the common built-in resources. Secrets intentionally have no short
// name. CRD short names are not covered.
var resourceShortNames = map[string]string{
	"cm": "configmap", "svc": "service", "deploy": "deployment",
	"rs": "replicaset", "rc": "replicationcontroller", "sts": "statefulset",
	"ds": "daemonset", "cj": "cronjob", "po": "pod", "no": "node",
	"ns": "namespace", "pv": "persistentvolume", "pvc": "persistentvolumeclaim",
	"sa": "serviceaccount", "ing": "ingress", "netpol": "networkpolicy",
	"pdb": "poddisruptionbudget", "pc": "priorityclass", "sc": "storageclass",
}

// resourceCanonicalSet is the set of canonical resource names the built-in short
// names expand to (the values of resourceShortNames). It lets NormalizeResource
// recognize a name that is ALREADY canonical — including one that ends in "s"
// like "ingress"/"storageclass" — and not mangle it by blindly trimming the "s".
var resourceCanonicalSet = func() map[string]bool {
	m := make(map[string]bool, len(resourceShortNames))
	for _, v := range resourceShortNames {
		m[v] = true
	}
	return m
}()

// NormalizeResource canonicalizes a resource name for matching using the BUILT-IN
// short names only: lower-cased, stripped of any "/name" or ".group" suffix,
// expanded from a short name to its canonical form, and singularized. This makes
// "secret", "secrets", "Secret", and "cm"/"configmap" compare predictably.
//
// Runtime-discovered CRD short names are deliberately NOT applied here. They are
// applied only as an ADDITIVE alternative in IsResourceProtected, so discovery
// can never change the canonical form of a name and therefore can never remove a
// match that the built-ins produced (the "discovery only adds" invariant).
func NormalizeResource(name string) string {
	if i := strings.IndexAny(name, "/."); i >= 0 {
		name = name[:i]
	}
	name = strings.ToLower(name)
	if full, ok := resourceShortNames[name]; ok {
		return full
	}
	// A name that is already canonical (including "ingress"/"storageclass",
	// whose singular legitimately ends in "s") must not be stripped.
	if resourceCanonicalSet[name] {
		return name
	}
	// Singularize. Kubernetes plurals of the built-in kinds are regular "s"
	// (pods), "es" after s/x/z/ch (ingresses, storageclasses), or "ies" from a
	// trailing "y" (networkpolicies -> networkpolicy). Try each candidate and
	// return the first that lands on a known canonical form or short name, so a
	// user protecting the kind is matched by every form kubectl accepts.
	for _, singular := range singularCandidates(name) {
		if full, ok := resourceShortNames[singular]; ok {
			return full
		}
		if resourceCanonicalSet[singular] {
			return singular
		}
	}
	return strings.TrimSuffix(name, "s")
}

// singularCandidates returns the plausible singular forms of name, most-specific
// plural rule first, so the caller can accept the first that resolves to a known
// resource. It never mis-singularizes an unknown name because the caller only
// acts on a candidate that matches a built-in canonical/short form.
func singularCandidates(name string) []string {
	var out []string
	if s := strings.TrimSuffix(name, "ies"); s != name {
		out = append(out, s+"y") // networkpolicies -> networkpolicy
	}
	if s := strings.TrimSuffix(name, "es"); s != name {
		out = append(out, s) // ingresses -> ingress
	}
	if s := strings.TrimSuffix(name, "s"); s != name {
		out = append(out, s) // pods -> pod
	}
	return out
}

// discoveredExpand returns the canonical resource a discovered CRD short name
// maps to (e.g. "ss" -> "secretstore"), or "" if name is not a discovered short
// name. It checks the plain name and its singular form. It is the ONLY place the
// discovered map is consulted, and it is used purely to ADD matches.
func discoveredExpand(name string, discovered map[string]string) string {
	if len(discovered) == 0 {
		return ""
	}
	if i := strings.IndexAny(name, "/."); i >= 0 {
		name = name[:i]
	}
	name = strings.ToLower(name)
	if v, ok := discovered[name]; ok {
		return v
	}
	if s := strings.TrimSuffix(name, "s"); s != name {
		if v, ok := discovered[s]; ok {
			return v
		}
	}
	return ""
}

// IsResourceProtected reports whether candidate names a protected resource.
// Matching is case-insensitive and treats singular/plural/short-name forms as
// equivalent.
//
// Discovery is strictly ADDITIVE and cannot weaken protection: the base decision
// (nc == np) uses only the built-in normalization on BOTH sides, so anything
// protected without discovery stays protected. A discovered CRD short name only
// adds new ways to match — the candidate being a short name for the protected
// kind, the protected entry being a short name for the candidate's kind, or both
// being short names for the same kind. Because the discovered map never touches
// the base normalization, even a poisoned cache can only ever over-block.
func (c *Config) IsResourceProtected(candidate string) bool {
	if candidate == "" || len(c.ProtectedResources) == 0 {
		return false
	}
	nc := NormalizeResource(candidate)
	ncd := discoveredExpand(candidate, c.discovered)
	for _, p := range c.ProtectedResources {
		np := NormalizeResource(p)
		switch {
		case nc == np:
			return true
		case ncd != "" && ncd == np:
			return true
		}
		if npd := discoveredExpand(p, c.discovered); npd != "" {
			if npd == nc || (ncd != "" && npd == ncd) {
				return true
			}
		}
	}
	return false
}

// HasProtectedResources reports whether any resource protection is configured.
func (c *Config) HasProtectedResources() bool {
	return len(c.ProtectedResources) > 0
}

// AddResource adds a resource to the protected list if an equivalent entry is
// not already present. Returns false if it was already protected.
func (c *Config) AddResource(name string) bool {
	norm := NormalizeResource(name)
	for _, r := range c.ProtectedResources {
		if NormalizeResource(r) == norm {
			return false
		}
	}
	c.ProtectedResources = append(c.ProtectedResources, name)
	return true
}

// RemoveResource removes a resource (or its singular/plural/short-name
// equivalent) from the protected list. Returns false if it was not present.
func (c *Config) RemoveResource(name string) bool {
	norm := NormalizeResource(name)
	for i, r := range c.ProtectedResources {
		if NormalizeResource(r) == norm {
			c.ProtectedResources = append(c.ProtectedResources[:i], c.ProtectedResources[i+1:]...)
			return true
		}
	}
	return false
}

// SetConfirmMode sets the confirmation mode if the value is valid.
func (c *Config) SetConfirmMode(mode string) bool {
	if !validConfirmMode(mode) {
		return false
	}
	c.ConfirmMode = mode
	return true
}

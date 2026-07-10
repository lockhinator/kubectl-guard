// Package config handles loading and saving kubectl-guard configuration.
package config

import (
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
	// to its own human and re-run with --yes once approved.
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
	// InClusterAllow passes commands through in-cluster with NO namespace or
	// context gating — a full passthrough. (Applying namespace protection here
	// would be identical to InClusterNamespace, since context protection is
	// unevaluable in-cluster either way, which is why "allow" is distinct.)
	// Resource protection still applies (it is global and evaluated earlier), and
	// so does sensitive-access gating: sensitive verbs are gated on EVERY context,
	// which "allow" does not override. A deliberately-permissive opt-in for the
	// context/namespace axis only.
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

// Config represents the kubectl-guard configuration.
type Config struct {
	// ProtectedContexts are context name patterns (glob) that require
	// confirmation for state-altering commands.
	ProtectedContexts []string `yaml:"protected_contexts,omitempty"`

	// ProtectedResources are resource names (e.g. "secret") whose access is
	// blocked entirely on every context, regardless of verb. Singular, plural,
	// and short-name forms ("secret", "secrets", "cm") match the same things.
	ProtectedResources []string `yaml:"protected_resources,omitempty"`

	// ProtectedNamespaces are namespace name patterns (glob) that gate
	// state-altering commands when the target namespace matches. Composes with
	// protected contexts: a command is gated if either matches.
	ProtectedNamespaces []string `yaml:"protected_namespaces,omitempty"`

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

	// BlastRadius gates wide-scope / bulk mutations on EVERY context: "off"
	// (default), "gate" (confirm), or "block" (refuse). Triggers are a destructive
	// verb with --all, a label/field selector, --all-namespaces, a force delete
	// (--force / --grace-period=0), or `apply --prune`. A genuine --dry-run is not
	// gated (it changes nothing). See guard.BlastRadius for the classifier.
	BlastRadius string `yaml:"blast_radius,omitempty"`

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

	// discovered maps a runtime-discovered short name to its canonical resource
	// form (e.g. "ss" -> "secretstore"). It is populated by the guard from the
	// api-resources cache before matching and is NOT serialized. nil means "not
	// discovered / built-ins only".
	discovered map[string]string `yaml:"-"`
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

// Path returns the full path to the config file.
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, configFileName), nil
}

// AuditPath returns the configured audit log path, or the default.
func AuditPath(cfg *Config) (string, error) {
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
		return nil, err
	}

	cfg.ApplyDefaults()
	return &cfg, nil
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
	for _, pattern := range c.ProtectedContexts {
		if matchGlob(pattern, context) {
			return true
		}
	}
	return false
}

// AddContext adds a context to the protected list if not already present.
func (c *Config) AddContext(context string) bool {
	for _, ctx := range c.ProtectedContexts {
		if ctx == context {
			return false
		}
	}
	c.ProtectedContexts = append(c.ProtectedContexts, context)
	return true
}

// RemoveContext removes a context from the protected list.
func (c *Config) RemoveContext(context string) bool {
	for i, ctx := range c.ProtectedContexts {
		if ctx == context {
			c.ProtectedContexts = append(c.ProtectedContexts[:i], c.ProtectedContexts[i+1:]...)
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
	for _, pattern := range c.ProtectedNamespaces {
		if matchGlob(pattern, namespace) {
			return true
		}
	}
	return false
}

// AddNamespace adds a namespace pattern to the protected list if not present.
func (c *Config) AddNamespace(namespace string) bool {
	for _, ns := range c.ProtectedNamespaces {
		if ns == namespace {
			return false
		}
	}
	c.ProtectedNamespaces = append(c.ProtectedNamespaces, namespace)
	return true
}

// RemoveNamespace removes a namespace pattern from the protected list.
func (c *Config) RemoveNamespace(namespace string) bool {
	for i, ns := range c.ProtectedNamespaces {
		if ns == namespace {
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

// EffectiveModesForActor returns the context_mode and namespace_mode that apply
// to the given actor: the global modes, made STRICTER by any matching actor
// policy. Because block is the most restrictive mode and a policy can only
// upgrade confirm → block (never downgrade), a matching actor policy can tighten
// protection for a known agent label but never weaken it below the global
// posture — the correct stance for a self-asserted identity. An unset or
// unmatched actor yields exactly the global modes (unchanged behavior).
func (c *Config) EffectiveModesForActor(actor string) (contextMode, namespaceMode string) {
	contextMode = c.effectiveContextMode()
	namespaceMode = c.effectiveNamespaceMode()
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

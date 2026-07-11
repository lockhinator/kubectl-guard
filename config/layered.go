package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SystemConfigPath is the enforced system-baseline config location. It is a var
// ONLY so tests can point it at a temp dir; it is never derived from the
// environment (an env-overridable system path would defeat enforcement). The
// user layer path may be redirected by KUBECTL_GUARD_CONFIG, but this system
// path is fixed, so an enforced baseline always loads and merges as a floor.
var SystemConfigPath = "/etc/kubectl-guard/config.yaml"

// loadSystemConfig reads the system baseline from SystemConfigPath. It returns
// (nil, nil) when the file does not exist (system-less is valid), and an error
// on any other read failure or on invalid YAML — an unreadable/invalid ENFORCED
// floor must fail the decision core CLOSED rather than silently vanish.
func loadSystemConfig() (*Config, error) {
	data, err := os.ReadFile(SystemConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read enforced system config %s: %w", SystemConfigPath, err)
	}
	var sys Config
	if err := yaml.Unmarshal(data, &sys); err != nil {
		return nil, fmt.Errorf("system config %s is not valid YAML: %w", SystemConfigPath, err)
	}
	return &sys, nil
}

// loadUserConfigAt reads a user config from path. It returns (nil, nil) when the
// file does not exist (a missing user layer is not an error), and an error on
// invalid YAML (fail closed) so a corrupt user file cannot silently drop
// protection.
func loadUserConfigAt(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config file %s is not valid YAML: %w", path, err)
	}
	return &cfg, nil
}

// enforcedSystemActive is the cheap, fail-safe enforcement probe used by Path().
// It treats a present-but-unreadable/invalid system config as ENFORCED (so the
// env override is forbidden) — the decision core (LoadEffective) fails such a
// state closed anyway, and it is never correct to honor the env redirect when a
// system config exists but cannot be trusted.
func enforcedSystemActive() bool {
	_, enforced := EnforcedSystemConfig()
	return enforced
}

// EnforcedSystemConfig loads the system layer (best-effort) and reports it plus
// whether it is enforced. It is used by the env/bypass-forbidding checks, so it
// FAILS SAFE: a system config that exists but cannot be read or parsed is
// reported as enforced (returns nil, true) — a present-but-unreadable baseline
// must not leave the bypass/env escape hatches open. A genuinely absent system
// config returns (nil, false).
func EnforcedSystemConfig() (*Config, bool) {
	data, err := os.ReadFile(SystemConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false
		}
		return nil, true // exists but unreadable → fail safe (enforced)
	}
	var sys Config
	if err := yaml.Unmarshal(data, &sys); err != nil {
		return nil, true // exists but invalid → fail safe (enforced)
	}
	return &sys, sys.Enforced
}

// EffectiveExists reports whether EITHER the system baseline or the user config
// exists. It is for callers that only need existence (not the merged value).
func EffectiveExists() (bool, error) {
	sys, err := loadSystemConfig()
	if err != nil {
		return false, err
	}
	if sys != nil {
		return true, nil
	}
	return Exists()
}

// LoadEffective loads the SYSTEM baseline (if present) and the USER config and
// returns their most-restrictive merge — the config the DECISION path must use.
// exists is true if EITHER layer exists. When the system layer is enforced, the
// user config path ignores KUBECTL_GUARD_CONFIG (the user layer loads from the
// default HOME path). A missing user layer is not an error (system-only is
// valid); a missing system layer yields the user config unchanged (byte-identical
// to pre-#86 behavior).
func LoadEffective() (cfg *Config, exists bool, err error) {
	sys, err := loadSystemConfig()
	if err != nil {
		return nil, false, err
	}
	enforced := sys != nil && sys.Enforced

	userPath, err := userConfigPathForLoad(enforced)
	if err != nil {
		return nil, false, err
	}
	usr, err := loadUserConfigAt(userPath)
	if err != nil {
		return nil, false, err
	}

	// No system layer → the pre-#86 path, byte-identical: the user config with
	// defaults applied, or SetupRequired when neither layer exists.
	if sys == nil {
		if usr == nil {
			return nil, false, nil
		}
		usr.ApplyDefaults()
		return usr, true, nil
	}

	merged := Merge(sys, usr)
	merged.systemEnforced = enforced
	merged.systemLayer = sys
	if enforced {
		// The user must not be able to redirect or rotate-away an enforced audit
		// trail: the destination and retention are the system's (or the default when
		// the system leaves them unset — ApplyDefaults fills them below). AuditPath
		// already ignores KUBECTL_GUARD_AUDIT_LOG under enforcement; this closes the
		// user-config path (a user audit_log / audit_max_size_mb: 1 / audit_max_files:
		// 1 can no longer steer or truncate the enforced trail). Webhook/HMAC stay
		// merged (system-wins-if-set) so a user may still ADD an integrity sink.
		merged.AuditLog = sys.AuditLog
		merged.AuditMaxSizeMB = sys.AuditMaxSizeMB
		merged.AuditMaxFiles = sys.AuditMaxFiles
		if pinned := strings.TrimSpace(sys.AuditLog); pinned != "" {
			merged.auditLogPinned = pinned
		}
	}
	// Defaults fill only still-empty fields AFTER the merge, so a default can
	// never overwrite a merged (stricter) value.
	merged.ApplyDefaults()
	return merged, true, nil
}

// userConfigPathForLoad picks the user-layer path for LoadEffective: the default
// HOME path when enforced (KUBECTL_GUARD_CONFIG forbidden), else the normal
// Path() (which is itself enforcement-aware, so both branches agree under
// enforcement — the explicit branch documents intent and is robust if Path()'s
// policy ever changes).
func userConfigPathForLoad(enforced bool) (string, error) {
	if enforced {
		return defaultUserConfigPath()
	}
	return Path()
}

// Merge returns a NEW config that is the MOST-RESTRICTIVE combination of the
// system baseline and the user layer (user==nil means an empty user layer). The
// invariant, enforced field-by-field below and asserted by the property test, is
// that the result is AT LEAST AS STRICT as `system` on every protection axis: the
// user layer can only tighten, never weaken. Neither input is mutated.
func Merge(system, user *Config) *Config {
	if system == nil {
		system = &Config{}
	}
	if user == nil {
		user = &Config{}
	}
	m := &Config{}

	// --- UNION lists (dedupe; most-restrictive mode on a shared key) ---
	m.ProtectedContexts = mergeProtectedPatterns(system.ProtectedContexts, user.ProtectedContexts)
	m.ProtectedNamespaces = mergeProtectedPatterns(system.ProtectedNamespaces, user.ProtectedNamespaces)
	m.ProtectedClusters = mergeProtectedClusters(system.ProtectedClusters, user.ProtectedClusters)
	m.ProtectedResources = unionResources(system.ProtectedResources, user.ProtectedResources)
	m.SensitiveKinds = unionResources(system.SensitiveKinds, user.SensitiveKinds)
	m.ActorPolicies = mergeActorPolicies(system.ActorPolicies, user.ActorPolicies)

	// SensitiveVerbs has an empty-means-defaults trap: once non-empty it OVERRIDES
	// the built-in defaults. A naive union of (empty=defaults) with a narrow user
	// list would DROP the defaults. So: an empty user list inherits the system's
	// verbatim (honoring a system's deliberate narrowing); a non-empty user list
	// unions with the system's EFFECTIVE set (its list, or the defaults when it
	// relied on them), so the user can only ADD sensitive verbs, never remove one.
	m.SensitiveVerbs = mergeSensitiveVerbs(system.SensitiveVerbs, user.SensitiveVerbs)

	// --- MODE axes: stricter wins (see the per-axis orderings) ---
	m.ContextMode = mergeMode(system.ContextMode, user.ContextMode, ContextModeConfirm, orderContextMode)
	m.NamespaceMode = mergeMode(system.NamespaceMode, user.NamespaceMode, NamespaceModeConfirm, orderNamespaceMode)
	m.ConfirmMode = mergeMode(system.ConfirmMode, user.ConfirmMode, ConfirmModeSimple, orderConfirmMode)
	m.AuditMode = mergeMode(system.AuditMode, user.AuditMode, AuditModeAll, orderAuditMode)
	m.SensitiveAccess = mergeMode(system.SensitiveAccess, user.SensitiveAccess, SensitiveAccessOff, orderSensitiveAccess)
	m.SensitiveKind = mergeMode(system.SensitiveKind, user.SensitiveKind, SensitiveKindOff, orderSensitiveKind)
	m.BlastRadius = mergeMode(system.BlastRadius, user.BlastRadius, BlastRadiusOff, orderBlastRadius)
	m.UnknownVerb = mergeMode(system.UnknownVerb, user.UnknownVerb, UnknownVerbAllow, orderUnknownVerb)
	m.InCluster = mergeMode(system.InCluster, user.InCluster, InClusterNamespace, orderInCluster)
	// RedactOutput: "structured" is the more-protective value (it engages
	// redaction), so it wins the merge. It is deliberately NOT in WeakensProtection
	// — redaction is best-effort defense-in-depth, NOT a containment boundary, so
	// toggling it is not a protection change the weakening-confirmation gate cares
	// about (a user can still turn it on/off freely in their own layer, but a system
	// baseline that turns it on floors the user at on).
	m.RedactOutput = mergeMode(system.RedactOutput, user.RedactOutput, RedactOutputOff, orderRedactOutput)

	// --- OR (tightening booleans: either true wins) ---
	m.BlockImpersonation = system.BlockImpersonation || user.BlockImpersonation
	m.RequireConfirmWeakening = system.RequireConfirmWeakening || user.RequireConfirmWeakening
	m.StrictConfigPerms = system.StrictConfigPerms || user.StrictConfigPerms
	m.RequireJustification = system.RequireJustification || user.RequireJustification
	m.ReadOnly = system.ReadOnly || user.ReadOnly
	m.AuditSyslog = system.AuditSyslog || user.AuditSyslog
	m.DiffBeforeConfirm = system.DiffBeforeConfirm || user.DiffBeforeConfirm
	m.PreviewBeforeConfirm = system.PreviewBeforeConfirm || user.PreviewBeforeConfirm

	// --- AUDIT SINK / INTEGRITY: system wins if set (user cannot redirect an
	// enforced audit away) ---
	m.AuditLog = firstNonEmpty(system.AuditLog, user.AuditLog)
	m.AuditWebhookURL = firstNonEmpty(system.AuditWebhookURL, user.AuditWebhookURL)
	m.AuditHMACKeyFile = firstNonEmpty(system.AuditHMACKeyFile, user.AuditHMACKeyFile)
	m.AuditMaxSizeMB = firstNonZero(system.AuditMaxSizeMB, user.AuditMaxSizeMB)
	m.AuditMaxFiles = firstNonZero(system.AuditMaxFiles, user.AuditMaxFiles)

	// --- COMMAND OVERRIDES: dangerous unions; a `safe` override may NOT apply to
	// any verb marked dangerous by either layer ---
	m.CommandOverrides = mergeCommandOverrides(system.CommandOverrides, user.CommandOverrides)

	// --- DISCOVERY / MISC ---
	// Discovery only ever ADDS short names (more matching = stricter), so true
	// wins: an explicit true on either layer forces discovery on; else an explicit
	// false is respected; else the default (nil ⇒ on).
	m.DiscoverShortNames = mergeDiscover(system.DiscoverShortNames, user.DiscoverShortNames)
	// Actor is the LOCAL identity for audit stamping, not a protection axis: the
	// user's wins if set, else the system's.
	m.Actor = firstNonEmpty(user.Actor, system.Actor)
	// ConfirmTimeoutSeconds is a UX timeout (an admin cap), not a security axis:
	// the system's wins when positive, else the user's.
	m.ConfirmTimeoutSeconds = firstNonZero(system.ConfirmTimeoutSeconds, user.ConfirmTimeoutSeconds)

	// Enforced is not a user-facing merged value; LoadEffective sets
	// merged.systemEnforced from it. discovered is populated at runtime.
	return m
}

// Mode-strictness orderings, weakest → strictest. mergeMode resolves an empty
// value to the axis default (which may sit anywhere in the order — e.g. in_cluster
// defaults to the MIDDLE "namespace", audit defaults to the STRICTEST "all"),
// then the higher-indexed (stricter) value wins.
var (
	orderContextMode     = []string{ContextModeConfirm, ContextModeBlock}
	orderNamespaceMode   = []string{NamespaceModeConfirm, NamespaceModeBlock}
	orderConfirmMode     = []string{ConfirmModeSimple, ConfirmModeAgentRelay, ConfirmModeTypeName}
	orderAuditMode       = []string{AuditModeOff, AuditModeGated, AuditModeAll}
	orderSensitiveAccess = []string{SensitiveAccessOff, SensitiveAccessGate, SensitiveAccessBlock}
	orderSensitiveKind   = []string{SensitiveKindOff, SensitiveKindConfirm, SensitiveKindBlock}
	orderBlastRadius     = []string{BlastRadiusOff, BlastRadiusGate, BlastRadiusBlock}
	orderUnknownVerb     = []string{UnknownVerbAllow, UnknownVerbGate, UnknownVerbDeny}
	orderInCluster       = []string{InClusterAllow, InClusterNamespace, InClusterDeny}
	orderRedactOutput    = []string{RedactOutputOff, RedactOutputStructured}
)

// mergeMode combines a system and user mode value. The floor is the system's
// EXPLICIT value, or the axis default when the system is silent; the user may
// only TIGHTEN above the floor (the stricter, higher-indexed value in order
// wins), never weaken below it. Two properties fall out:
//   - An admin's EXPLICIT relaxation is honored when the user is silent: system
//     `audit_mode: off` + user silent → off (not the strict default `all`). This
//     is the fix for the "admin cannot relax the baseline" defect.
//   - A user can never drop an axis below the system floor, and — because the
//     floor for a SILENT system axis is the default — a user cannot relax an axis
//     whose default is stricter than the user's value (e.g. cannot set
//     `in_cluster: allow` under a silent system, whose default `namespace` is
//     stricter). A system config's presence thus floors every axis at least at
//     its default, which is the safe (most-restrictive) direction.
//
// A value not in order (an invalid config value) ranks -1 and never wins over a
// valid one; Validate rejects invalid merged values, failing the decision closed.
func mergeMode(sysVal, usrVal, def string, order []string) string {
	floor := orDefault(sysVal, def)
	if usrVal == "" {
		return floor
	}
	if indexOfStr(order, usrVal) > indexOfStr(order, floor) {
		return usrVal
	}
	return floor
}

// strictestPatternMode returns the most-restrictive of two per-pattern protection
// modes for the SAME pattern/cluster/actor. "" means "inherit the global mode",
// which — because the merged global is itself the stricter of the two layers'
// globals (≥ confirm) — is AT LEAST as strict as an explicit "confirm". So the
// ordering is block > inherit("") > confirm: an explicit user confirm can never
// override a system inherit (which may resolve to block) or a system block.
func strictestPatternMode(a, b string) string {
	if a == ContextModeBlock || b == ContextModeBlock {
		return ContextModeBlock
	}
	if a == "" || b == "" {
		return ""
	}
	return ContextModeConfirm
}

// mergeProtectedPatterns unions two protected-pattern lists, deduped by exact
// Pattern, taking the most-restrictive per-pattern mode on a shared pattern.
// System entries are added first so provenance/order is stable.
func mergeProtectedPatterns(sys, usr []ProtectedPattern) []ProtectedPattern {
	out := make([]ProtectedPattern, 0, len(sys)+len(usr))
	idx := map[string]int{}
	add := func(list []ProtectedPattern) {
		for _, pp := range list {
			if i, ok := idx[pp.Pattern]; ok {
				out[i].Mode = strictestPatternMode(out[i].Mode, pp.Mode)
				continue
			}
			idx[pp.Pattern] = len(out)
			out = append(out, ProtectedPattern{Pattern: pp.Pattern, Mode: pp.Mode})
		}
	}
	add(sys)
	add(usr)
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergeProtectedClusters unions two protected-cluster lists, deduped by
// identifier() (Server or ServerPattern), taking the most-restrictive mode on a
// shared identifier.
func mergeProtectedClusters(sys, usr []ProtectedCluster) []ProtectedCluster {
	out := make([]ProtectedCluster, 0, len(sys)+len(usr))
	idx := map[string]int{}
	add := func(list []ProtectedCluster) {
		for _, pc := range list {
			id := pc.identifier()
			if i, ok := idx[id]; ok {
				out[i].Mode = strictestPatternMode(out[i].Mode, pc.Mode)
				continue
			}
			idx[id] = len(out)
			out = append(out, ProtectedCluster{Server: pc.Server, ServerPattern: pc.ServerPattern, Mode: pc.Mode})
		}
	}
	add(sys)
	add(usr)
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergeActorPolicies unions two actor-policy lists by Actor, tightening each mode
// axis (block wins). A user actor policy may only make a system one stricter.
func mergeActorPolicies(sys, usr []ActorPolicy) []ActorPolicy {
	out := make([]ActorPolicy, 0, len(sys)+len(usr))
	idx := map[string]int{}
	add := func(list []ActorPolicy) {
		for _, ap := range list {
			if i, ok := idx[ap.Actor]; ok {
				out[i].ContextMode = strictestPatternMode(out[i].ContextMode, ap.ContextMode)
				out[i].NamespaceMode = strictestPatternMode(out[i].NamespaceMode, ap.NamespaceMode)
				continue
			}
			idx[ap.Actor] = len(out)
			out = append(out, ActorPolicy{Actor: ap.Actor, ContextMode: ap.ContextMode, NamespaceMode: ap.NamespaceMode})
		}
	}
	add(sys)
	add(usr)
	if len(out) == 0 {
		return nil
	}
	return out
}

// unionResources unions two resource/kind name lists, deduped by NormalizeResource
// (so "secret" and "secrets" collapse) while keeping the first spelling. Union
// only ever adds protection.
func unionResources(sys, usr []string) []string {
	out := make([]string, 0, len(sys)+len(usr))
	seen := map[string]bool{}
	add := func(list []string) {
		for _, r := range list {
			n := NormalizeResource(r)
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, r)
		}
	}
	add(sys)
	add(usr)
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergeSensitiveVerbs merges the sensitive-access verb sets. See the call site in
// Merge for the empty-means-defaults rationale.
func mergeSensitiveVerbs(sys, usr []string) []string {
	if len(usr) == 0 {
		if len(sys) == 0 {
			return nil
		}
		return append([]string(nil), sys...)
	}
	base := sys
	if len(base) == 0 {
		base = defaultSensitiveVerbs
	}
	return unionFold(base, usr)
}

// mergeCommandOverrides merges the safe/dangerous verb overrides preserving the
// floor invariant. A `safe` override is a pure WEAKENING knob: it downgrades a
// verb the guard would otherwise treat as state-altering (whether by the user's
// explicit list OR by the guard's BUILT-IN classification) to a pass-through
// read. So only the SYSTEM layer's `safe` overrides survive the merge — a USER
// `safe` override is dropped entirely. Dropping it is what closes the built-in-
// dangerous bypass: a user `safe: [delete]` can no longer make `delete` skip the
// context/namespace gate under a system baseline (the merge cannot enumerate the
// guard's built-in state-altering set from this package, so it cannot subtract it
// — dropping user-safe is the correct, complete fix). The `dangerous`
// (state-altering + unsafe-safe) overrides UNION from both layers, since a
// dangerous override only ever tightens; the system's own `safe` overrides are
// still honored (the admin owns the floor) minus anything either layer marked
// dangerous.
func mergeCommandOverrides(sys, usr CommandOverrides) CommandOverrides {
	dangerous := unionFold(
		append(append([]string(nil), sys.StateAltering...), sys.UnsafeSafe...),
		append(append([]string(nil), usr.StateAltering...), usr.UnsafeSafe...),
	)
	safe := subtractFold(sys.Safe, dangerous)
	out := CommandOverrides{}
	if len(safe) > 0 {
		out.Safe = safe
	}
	if len(dangerous) > 0 {
		out.StateAltering = dangerous
	}
	return out
}

// mergeDiscover merges the discover_short_names tri-state with the SAME
// floor-done-right semantics as mergeMode: the floor is the system's EXPLICIT
// value, or the default (ON) when the system is silent, and the user may only
// tighten to ON. Discovery only ADDS matches (a protected CRD's discovered short
// name / irregular plural), so ON is the stricter direction — a user
// `discover_short_names: false` must NOT be able to turn discovery OFF below a
// silent system's default-on floor and thereby reach a protected CRD by its short
// name. Only an admin's EXPLICIT false relaxes it (and a user may re-enable).
func mergeDiscover(s, u *bool) *bool {
	systemOn := s == nil || *s // silent system floors at the default (ON)
	if systemOn || (u != nil && *u) {
		t := true
		return &t
	}
	f := false
	return &f
}

// unionFold unions string lists, deduped case-insensitively (whitespace-trimmed),
// keeping the first spelling seen.
func unionFold(lists ...[]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, list := range lists {
		for _, v := range list {
			key := strings.ToLower(strings.TrimSpace(v))
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, v)
		}
	}
	return out
}

// subtractFold returns list with every case-insensitive match of any entry in
// remove dropped.
func subtractFold(list, remove []string) []string {
	if len(remove) == 0 {
		return list
	}
	drop := map[string]bool{}
	for _, r := range remove {
		drop[strings.ToLower(strings.TrimSpace(r))] = true
	}
	var out []string
	for _, v := range list {
		if drop[strings.ToLower(strings.TrimSpace(v))] {
			continue
		}
		out = append(out, v)
	}
	return out
}

// orDefault returns v when non-empty, else def.
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// indexOfStr returns the index of v in list, or -1 if absent.
func indexOfStr(list []string, v string) int {
	for i, s := range list {
		if s == v {
			return i
		}
	}
	return -1
}

// firstNonEmpty returns a if non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// firstNonZero returns a if non-zero, else b.
func firstNonZero(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

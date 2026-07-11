package config

import (
	"os"
	"path/filepath"
	"testing"
)

// boolPtr returns a *bool for the discover_short_names tri-state.
func boolPtr(b bool) *bool { return &b }

// maximallyStrictSystem builds an enforced system baseline that turns EVERY
// protection axis to its strictest setting. The property test asserts that
// merging any user layer under it never loosens any of these.
func maximallyStrictSystem() *Config {
	return &Config{
		Enforced:                true,
		ProtectedContexts:       []ProtectedPattern{{Pattern: "prod-*", Mode: ContextModeBlock}},
		ProtectedNamespaces:     []ProtectedPattern{{Pattern: "kube-system", Mode: NamespaceModeBlock}},
		ProtectedClusters:       []ProtectedCluster{{Server: "https://prod.example.com", Mode: ContextModeBlock}},
		ProtectedResources:      []string{"secret"},
		SensitiveKinds:          []string{"node"},
		SensitiveKind:           SensitiveKindBlock,
		SensitiveAccess:         SensitiveAccessBlock,
		BlastRadius:             BlastRadiusBlock,
		UnknownVerb:             UnknownVerbDeny,
		InCluster:               InClusterDeny,
		ContextMode:             ContextModeBlock,
		NamespaceMode:           NamespaceModeBlock,
		ConfirmMode:             ConfirmModeTypeName,
		AuditMode:               AuditModeAll,
		AuditLog:                "/var/log/kubectl-guard/audit.log",
		AuditWebhookURL:         "https://siem.example.com/ingest",
		AuditHMACKeyFile:        "/etc/kubectl-guard/hmac.key",
		AuditMaxSizeMB:          50,
		AuditMaxFiles:           9,
		BlockImpersonation:      true,
		DiffBeforeConfirm:       true,
		PreviewBeforeConfirm:    true,
		RequireConfirmWeakening: true,
		StrictConfigPerms:       true,
		RequireJustification:    true,
		ReadOnly:                true,
		AuditSyslog:             true,
		DiscoverShortNames:      boolPtr(true),
		ConfirmTimeoutSeconds:   30,
		CommandOverrides:        CommandOverrides{StateAltering: []string{"customdanger"}},
		ActorPolicies:           []ActorPolicy{{Actor: "ci-*", ContextMode: ContextModeBlock, NamespaceMode: NamespaceModeBlock}},
	}
}

// assertAtLeastAsStrictAsMaxSystem asserts merged holds every strict property of
// maximallyStrictSystem — the security invariant of Merge.
func assertAtLeastAsStrictAsMaxSystem(t *testing.T, merged *Config) {
	t.Helper()
	// Ensure env vars do not interfere with ReadOnlyActive/StrictPerms.
	t.Setenv(EnvReadOnly, "")
	t.Setenv(EnvStrict, "")

	if got := merged.EffectiveContextMode("prod-1"); got != ContextModeBlock {
		t.Errorf("EffectiveContextMode(prod-1) = %q, want block", got)
	}
	if !merged.IsContextProtected("prod-1") {
		t.Error("prod-1 must stay context-protected")
	}
	if got := merged.EffectiveNamespaceMode("kube-system"); got != NamespaceModeBlock {
		t.Errorf("EffectiveNamespaceMode(kube-system) = %q, want block", got)
	}
	if !merged.IsNamespaceProtected("kube-system") {
		t.Error("kube-system must stay namespace-protected")
	}
	if !merged.IsClusterProtected("https://prod.example.com") {
		t.Error("prod cluster must stay protected")
	}
	if got := merged.EffectiveClusterMode("https://prod.example.com"); got != ContextModeBlock {
		t.Errorf("EffectiveClusterMode = %q, want block", got)
	}
	if !merged.IsResourceProtected("secret") {
		t.Error("secret must stay resource-protected")
	}
	if !merged.IsSensitiveKind("node") {
		t.Error("node must stay a sensitive kind")
	}
	if got := merged.SensitiveKindMode(); got != SensitiveKindBlock {
		t.Errorf("SensitiveKindMode = %q, want block", got)
	}
	if got := merged.SensitiveAccessMode(); got != SensitiveAccessBlock {
		t.Errorf("SensitiveAccessMode = %q, want block", got)
	}
	if got := merged.BlastRadiusMode(); got != BlastRadiusBlock {
		t.Errorf("BlastRadiusMode = %q, want block", got)
	}
	if got := merged.UnknownVerbMode(); got != UnknownVerbDeny {
		t.Errorf("UnknownVerbMode = %q, want deny", got)
	}
	if got := merged.InClusterMode(); got != InClusterDeny {
		t.Errorf("InClusterMode = %q, want deny", got)
	}
	if merged.AuditMode != AuditModeAll {
		t.Errorf("AuditMode = %q, want all", merged.AuditMode)
	}
	if merged.ConfirmMode != ConfirmModeTypeName {
		t.Errorf("ConfirmMode = %q, want type-name", merged.ConfirmMode)
	}
	for name, got := range map[string]bool{
		"BlockImpersonation":      merged.BlockImpersonation,
		"DiffBeforeConfirm":       merged.DiffBeforeConfirm,
		"PreviewBeforeConfirm":    merged.PreviewBeforeConfirm,
		"RequireConfirmWeakening": merged.RequireConfirmWeakening,
		"StrictConfigPerms":       merged.StrictConfigPerms,
		"RequireJustification":    merged.RequireJustification,
		"ReadOnly":                merged.ReadOnly,
		"AuditSyslog":             merged.AuditSyslog,
	} {
		if !got {
			t.Errorf("%s must stay true after merge", name)
		}
	}
	if !merged.ReadOnlyActive() {
		t.Error("ReadOnlyActive must stay true")
	}
	if !merged.StrictPerms() {
		t.Error("StrictPerms must stay true")
	}
	// Audit sink integrity: system's pinned values win, user cannot redirect.
	if merged.AuditLog != "/var/log/kubectl-guard/audit.log" {
		t.Errorf("AuditLog = %q, want the system's", merged.AuditLog)
	}
	if merged.AuditWebhookURL != "https://siem.example.com/ingest" {
		t.Errorf("AuditWebhookURL = %q, want the system's", merged.AuditWebhookURL)
	}
	if merged.AuditHMACKeyFile != "/etc/kubectl-guard/hmac.key" {
		t.Errorf("AuditHMACKeyFile = %q, want the system's", merged.AuditHMACKeyFile)
	}
	// A system-dangerous verb can never be marked safe by the user.
	if got := merged.ClassifyOverride("customdanger"); got != ClassStateAltering {
		t.Errorf("ClassifyOverride(customdanger) = %v, want ClassStateAltering", got)
	}
	// Discovery stays on (more matching).
	if !merged.ShouldDiscoverShortNames() {
		t.Error("ShouldDiscoverShortNames must stay true")
	}
	// Actor policy still tightens ci-* to block.
	cm, nm := merged.EffectiveModesForActor("ci-runner", "staging", "default")
	if cm != ContextModeBlock || nm != NamespaceModeBlock {
		t.Errorf("EffectiveModesForActor(ci-runner) = (%q,%q), want (block,block)", cm, nm)
	}
}

// TestMergeInvariant is THE property test: a maximally-strict enforced system
// config, merged with (a) an empty user layer and (b) a user layer that tries to
// weaken EVERY axis, must in both cases remain at least as strict as the system.
func TestMergeInvariant(t *testing.T) {
	t.Run("empty user layer preserves every strict axis", func(t *testing.T) {
		sys := maximallyStrictSystem()
		merged := Merge(sys, nil)
		merged.ApplyDefaults()
		assertAtLeastAsStrictAsMaxSystem(t, merged)
	})

	t.Run("user layer trying to weaken every axis cannot loosen anything", func(t *testing.T) {
		sys := maximallyStrictSystem()
		weakeningUser := &Config{
			// Try to downgrade every mode.
			ContextMode:     ContextModeConfirm,
			NamespaceMode:   NamespaceModeConfirm,
			ConfirmMode:     ConfirmModeSimple,
			AuditMode:       AuditModeOff,
			SensitiveAccess: SensitiveAccessOff,
			SensitiveKind:   SensitiveKindOff,
			BlastRadius:     BlastRadiusOff,
			UnknownVerb:     UnknownVerbAllow,
			InCluster:       InClusterAllow,
			// Try to empty every protected list (they are simply absent here).
			// Try to flip every tightening bool off (absent = false).
			// Try to redirect the audit sink away.
			AuditLog:         "/tmp/attacker.log",
			AuditWebhookURL:  "https://evil.example.com",
			AuditHMACKeyFile: "/tmp/attacker.key",
			// Try to mark the system-dangerous verb safe, and add a per-pattern
			// confirm override for the prod-* block pattern.
			CommandOverrides:  CommandOverrides{Safe: []string{"customdanger"}},
			ProtectedContexts: []ProtectedPattern{{Pattern: "prod-*", Mode: ContextModeConfirm}},
			// Try to force discovery off.
			DiscoverShortNames: boolPtr(false),
			// Try to relax the actor policy to confirm.
			ActorPolicies: []ActorPolicy{{Actor: "ci-*", ContextMode: ContextModeConfirm, NamespaceMode: ContextModeConfirm}},
		}
		merged := Merge(sys, weakeningUser)
		merged.ApplyDefaults()
		assertAtLeastAsStrictAsMaxSystem(t, merged)
	})
}

// TestMergeUnionLists covers list unioning, dedupe, and most-restrictive mode on
// a shared pattern.
func TestMergeUnionLists(t *testing.T) {
	sys := &Config{
		ProtectedContexts:  []ProtectedPattern{{Pattern: "prod-*", Mode: ContextModeBlock}, {Pattern: "shared"}},
		ProtectedResources: []string{"secret"},
		SensitiveKinds:     []string{"node"},
	}
	usr := &Config{
		// staging-* is new; shared collides (system inherit vs user confirm →
		// inherit wins as it may resolve to a stricter global); prod-* collides
		// (system block vs user confirm → block wins).
		ProtectedContexts:  []ProtectedPattern{{Pattern: "staging-*"}, {Pattern: "shared", Mode: ContextModeConfirm}, {Pattern: "prod-*", Mode: ContextModeConfirm}},
		ProtectedResources: []string{"secrets", "configmap"}, // "secrets" dedupes with "secret"
		SensitiveKinds:     []string{"nodes", "namespace"},   // "nodes" dedupes with "node"
	}
	m := Merge(sys, usr)

	if len(m.ProtectedContexts) != 3 {
		t.Fatalf("merged contexts = %v, want 3 (prod-*, shared, staging-*)", m.ProtectedContexts)
	}
	byPat := map[string]string{}
	for _, pp := range m.ProtectedContexts {
		byPat[pp.Pattern] = pp.Mode
	}
	if byPat["prod-*"] != ContextModeBlock {
		t.Errorf("prod-* mode = %q, want block (most-restrictive of block/confirm)", byPat["prod-*"])
	}
	if byPat["shared"] != "" {
		t.Errorf("shared mode = %q, want \"\" (inherit beats explicit confirm)", byPat["shared"])
	}
	if len(m.ProtectedResources) != 2 {
		t.Errorf("resources = %v, want 2 (secret, configmap after dedupe)", m.ProtectedResources)
	}
	if len(m.SensitiveKinds) != 2 {
		t.Errorf("sensitive kinds = %v, want 2 (node, namespace after dedupe)", m.SensitiveKinds)
	}
}

// TestMergeModeAxes checks that each mode axis picks the stricter value
// regardless of which layer holds it.
func TestMergeModeAxes(t *testing.T) {
	cases := []struct {
		name     string
		set      func(c *Config, v string)
		get      func(c *Config) string
		sys, usr string
		want     string
	}{
		{"context block>confirm", func(c *Config, v string) { c.ContextMode = v }, func(c *Config) string { return c.ContextMode }, ContextModeConfirm, ContextModeBlock, ContextModeBlock},
		{"context user-weaker", func(c *Config, v string) { c.ContextMode = v }, func(c *Config) string { return c.ContextMode }, ContextModeBlock, ContextModeConfirm, ContextModeBlock},
		{"audit all>gated>off (user off)", func(c *Config, v string) { c.AuditMode = v }, func(c *Config) string { return c.AuditMode }, AuditModeGated, AuditModeOff, AuditModeGated},
		{"audit user-all wins", func(c *Config, v string) { c.AuditMode = v }, func(c *Config) string { return c.AuditMode }, AuditModeGated, AuditModeAll, AuditModeAll},
		{"sensitive block>gate>off", func(c *Config, v string) { c.SensitiveAccess = v }, func(c *Config) string { return c.SensitiveAccess }, SensitiveAccessGate, SensitiveAccessOff, SensitiveAccessGate},
		{"unknownverb deny>gate>allow", func(c *Config, v string) { c.UnknownVerb = v }, func(c *Config) string { return c.UnknownVerb }, UnknownVerbGate, UnknownVerbAllow, UnknownVerbGate},
		{"incluster deny>namespace>allow (user allow)", func(c *Config, v string) { c.InCluster = v }, func(c *Config) string { return c.InCluster }, InClusterNamespace, InClusterAllow, InClusterNamespace},
		{"incluster user-deny wins", func(c *Config, v string) { c.InCluster = v }, func(c *Config) string { return c.InCluster }, InClusterAllow, InClusterDeny, InClusterDeny},
		{"confirmmode type-name>simple", func(c *Config, v string) { c.ConfirmMode = v }, func(c *Config) string { return c.ConfirmMode }, ConfirmModeSimple, ConfirmModeTypeName, ConfirmModeTypeName},
		{"blast block>gate>off", func(c *Config, v string) { c.BlastRadius = v }, func(c *Config) string { return c.BlastRadius }, BlastRadiusGate, BlastRadiusOff, BlastRadiusGate},
		{"sensitivekind block>confirm>off", func(c *Config, v string) { c.SensitiveKind = v }, func(c *Config) string { return c.SensitiveKind }, SensitiveKindConfirm, SensitiveKindOff, SensitiveKindConfirm},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, u := &Config{}, &Config{}
			tc.set(s, tc.sys)
			tc.set(u, tc.usr)
			m := Merge(s, u)
			if got := tc.get(m); got != tc.want {
				t.Errorf("merged = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMergeInClusterEmptyDefault verifies the tricky axis where the default
// ("namespace") sits in the MIDDLE: an empty layer resolves to namespace, which
// must beat a user "allow".
func TestMergeInClusterEmptyDefault(t *testing.T) {
	m := Merge(&Config{}, &Config{InCluster: InClusterAllow})
	if got := m.InClusterMode(); got != InClusterNamespace {
		t.Errorf("InClusterMode = %q, want namespace (empty system default must beat user allow)", got)
	}
}

// TestMergeAdminCanRelaxExplicitAxis: an admin's EXPLICIT relaxation of an axis
// (below its built-in default) is honored when the user is silent — the floor is
// the system's explicit value, not the default. Regression for the mergeMode
// admin-relax defect.
func TestMergeAdminCanRelaxExplicitAxis(t *testing.T) {
	// audit_mode default is "all" (strictest); the admin explicitly relaxes to off.
	m := Merge(&Config{AuditMode: AuditModeOff}, &Config{})
	if got := m.AuditMode; got != AuditModeOff {
		t.Errorf("AuditMode = %q, want off (admin's explicit relaxation honored when user silent)", got)
	}
	// in_cluster default is "namespace" (middle); admin explicitly relaxes to allow.
	m2 := Merge(&Config{InCluster: InClusterAllow}, &Config{})
	if got := m2.InClusterMode(); got != InClusterAllow {
		t.Errorf("InClusterMode = %q, want allow (admin's explicit relaxation honored)", got)
	}
	// But the user can still TIGHTEN the admin's relaxation.
	m3 := Merge(&Config{AuditMode: AuditModeOff}, &Config{AuditMode: AuditModeAll})
	if got := m3.AuditMode; got != AuditModeAll {
		t.Errorf("AuditMode = %q, want all (user tightens the admin's relaxation)", got)
	}
	// And a user CANNOT relax an axis the system is SILENT on below its default.
	m4 := Merge(&Config{}, &Config{InCluster: InClusterAllow})
	if got := m4.InClusterMode(); got != InClusterNamespace {
		t.Errorf("InClusterMode = %q, want namespace (silent system floors at default; user cannot relax)", got)
	}
}

// TestMergeBoolsOR checks tightening booleans OR (either true wins).
func TestMergeBoolsOR(t *testing.T) {
	m := Merge(&Config{ReadOnly: true, BlockImpersonation: false}, &Config{ReadOnly: false, BlockImpersonation: true})
	if !m.ReadOnly {
		t.Error("ReadOnly must be true when the system sets it (user false cannot clear it)")
	}
	if !m.BlockImpersonation {
		t.Error("BlockImpersonation must be true when the user adds it")
	}
}

// TestMergeAuditSinkSystemWins checks the audit sink integrity fields.
func TestMergeAuditSinkSystemWins(t *testing.T) {
	sys := &Config{AuditLog: "/sys.log", AuditMaxSizeMB: 10, AuditMaxFiles: 3}
	usr := &Config{AuditLog: "/usr.log", AuditMaxSizeMB: 999, AuditMaxFiles: 99}
	m := Merge(sys, usr)
	if m.AuditLog != "/sys.log" {
		t.Errorf("AuditLog = %q, want the system's", m.AuditLog)
	}
	if m.AuditMaxSizeMB != 10 || m.AuditMaxFiles != 3 {
		t.Errorf("audit rotation = (%d,%d), want (10,3) from system", m.AuditMaxSizeMB, m.AuditMaxFiles)
	}
	// System unset → user's value is used.
	m2 := Merge(&Config{}, usr)
	if m2.AuditLog != "/usr.log" {
		t.Errorf("AuditLog = %q, want the user's when system unset", m2.AuditLog)
	}
}

// TestMergeCommandOverrides checks that a USER `safe` override never survives the
// merge — a `safe` override is a pure weakening knob (it downgrades a verb to a
// pass-through read), and the merge cannot enumerate the guard's BUILT-IN
// state-altering set, so a user `safe: [delete]` must not be able to mark a
// built-in-dangerous verb safe and slip the context/namespace gate. Only the
// SYSTEM layer's `safe` overrides survive (minus anything either layer marked
// dangerous). Dangerous overrides union from both layers (a user may tighten).
func TestMergeCommandOverrides(t *testing.T) {
	sys := &Config{CommandOverrides: CommandOverrides{StateAltering: []string{"danger"}, Safe: []string{"sysread"}}}
	usr := &Config{CommandOverrides: CommandOverrides{Safe: []string{"danger", "logs", "delete"}, StateAltering: []string{"plugincmd"}}}
	m := Merge(sys, usr)
	// A user safe override of a system-dangerous verb: still dangerous.
	if got := m.ClassifyOverride("danger"); got != ClassStateAltering {
		t.Errorf("danger = %v, want ClassStateAltering (user safe cannot override system-dangerous)", got)
	}
	// A user safe override of a BUILT-IN-dangerous verb (delete): dropped entirely,
	// so the guard's built-in classification (state-altering) governs — the floor holds.
	if got := m.ClassifyOverride("delete"); got == ClassSafe {
		t.Errorf("delete = ClassSafe, want NOT safe (a user safe override of a built-in-dangerous verb must be dropped)")
	}
	// Any user safe override is dropped, even for a genuinely-safe verb.
	if got := m.ClassifyOverride("logs"); got == ClassSafe {
		t.Errorf("logs = ClassSafe, want dropped (user safe overrides do not survive a system baseline)")
	}
	// The system's own safe override survives.
	if got := m.ClassifyOverride("sysread"); got != ClassSafe {
		t.Errorf("sysread = %v, want ClassSafe (a system safe override survives)", got)
	}
	// A user dangerous override tightens (survives).
	if got := m.ClassifyOverride("plugincmd"); got != ClassStateAltering {
		t.Errorf("plugincmd = %v, want ClassStateAltering (user may tighten)", got)
	}
}

// TestMergeSensitiveVerbsDefaultsTrap verifies the empty-means-defaults trap:
// a user narrowing the sensitive verbs cannot drop the system's effective set.
func TestMergeSensitiveVerbsDefaultsTrap(t *testing.T) {
	// System relies on defaults (empty); user provides a single verb. Merge must
	// NOT drop the defaults down to the user's one verb.
	m := Merge(&Config{}, &Config{SensitiveVerbs: []string{"exec"}})
	for _, v := range defaultSensitiveVerbs {
		if !m.IsSensitiveVerb(v) {
			t.Errorf("default sensitive verb %q was dropped by a narrowing user list", v)
		}
	}
	// Empty user inherits system verbatim (respecting a deliberate narrowing).
	m2 := Merge(&Config{SensitiveVerbs: []string{"exec"}}, &Config{})
	if m2.IsSensitiveVerb("cp") {
		t.Error("empty user must inherit the system's narrowed verb set, not re-expand defaults")
	}
	if !m2.IsSensitiveVerb("exec") {
		t.Error("system's exec must survive")
	}
}

// TestMergeDiscoverShortNames covers the tri-state discovery merge.
func TestMergeDiscoverShortNames(t *testing.T) {
	// System false + user true → on (user tightens / adds matching).
	if m := Merge(&Config{DiscoverShortNames: boolPtr(false)}, &Config{DiscoverShortNames: boolPtr(true)}); !m.ShouldDiscoverShortNames() {
		t.Error("explicit true on either layer must win")
	}
	// Both false → off.
	if m := Merge(&Config{DiscoverShortNames: boolPtr(false)}, &Config{DiscoverShortNames: boolPtr(false)}); m.ShouldDiscoverShortNames() {
		t.Error("both explicit false → off")
	}
	// Both unset → default on.
	if m := Merge(&Config{}, &Config{}); !m.ShouldDiscoverShortNames() {
		t.Error("both unset → default on")
	}
	// FLOOR: system SILENT + user false → still ON. A user cannot disable CRD
	// short-name discovery below a silent system's default-on floor and thereby
	// reach a protected CRD by its short name. (Security re-review finding.)
	if m := Merge(&Config{}, &Config{DiscoverShortNames: boolPtr(false)}); !m.ShouldDiscoverShortNames() {
		t.Error("silent system + user false must stay ON (floor at default); user cannot disable discovery")
	}
	// Admin EXPLICIT false (relaxation) + user silent → off (admin relax honored).
	if m := Merge(&Config{DiscoverShortNames: boolPtr(false)}, &Config{}); m.ShouldDiscoverShortNames() {
		t.Error("admin explicit false + user silent → off (admin relaxation honored)")
	}
}

// TestMergeDoesNotMutateInputs guards against Merge aliasing/mutating its inputs.
func TestMergeDoesNotMutateInputs(t *testing.T) {
	sys := &Config{ProtectedContexts: []ProtectedPattern{{Pattern: "prod-*", Mode: ContextModeBlock}}, ContextMode: ContextModeBlock}
	usr := &Config{ProtectedContexts: []ProtectedPattern{{Pattern: "prod-*", Mode: ContextModeConfirm}}, ContextMode: ContextModeConfirm}
	m := Merge(sys, usr)
	m.ProtectedContexts[0].Mode = "tampered"
	if sys.ProtectedContexts[0].Mode != ContextModeBlock {
		t.Error("Merge mutated the system input's slice")
	}
	if usr.ProtectedContexts[0].Mode != ContextModeConfirm {
		t.Error("Merge mutated the user input's slice")
	}
}

// --- LoadEffective / layered loader tests (use SystemConfigPath + HOME) ---

// withSystemConfig points SystemConfigPath at a temp file with the given content
// (empty content = no file) and restores it after the test.
func withSystemConfig(t *testing.T, content string) {
	t.Helper()
	old := SystemConfigPath
	t.Cleanup(func() { SystemConfigPath = old })
	p := filepath.Join(t.TempDir(), "system.yaml")
	if content != "" {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	SystemConfigPath = p
}

// TestLoadEffectiveNoSystemLayer: with no system file, LoadEffective returns the
// user config unchanged (regression: byte-identical to the pre-#86 path).
func TestLoadEffectiveNoSystemLayer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvConfig, "")
	withSystemConfig(t, "") // absent

	// No user config either → SetupRequired (exists=false).
	cfg, exists, err := LoadEffective()
	if err != nil || exists || cfg != nil {
		t.Fatalf("no layers: got (%v,%v,%v), want (nil,false,nil)", cfg, exists, err)
	}

	// User config present → returned unchanged, not enforced.
	if err := os.WriteFile(filepath.Join(home, configFileName), []byte("protected_contexts:\n  - prod\ncontext_mode: confirm\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, exists, err = LoadEffective()
	if err != nil || !exists {
		t.Fatalf("user-only: got exists=%v err=%v", exists, err)
	}
	if cfg.SystemEnforced() {
		t.Error("user-only config must not report SystemEnforced")
	}
	if !cfg.IsContextProtected("prod") || cfg.ContextMode != ContextModeConfirm {
		t.Error("user-only config must be returned unchanged")
	}
}

// TestLoadEffectiveMergesFloor: a system layer is merged as a floor under the
// user config even when the user tries to weaken it.
func TestLoadEffectiveMergesFloor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvConfig, "")
	withSystemConfig(t, "enforced: true\ncontext_mode: block\nprotected_contexts:\n  - prod-*\naudit_log: /var/log/kg.log\n")
	// User tries to weaken to confirm and empty lists.
	if err := os.WriteFile(filepath.Join(home, configFileName), []byte("context_mode: confirm\nprotected_contexts: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, exists, err := LoadEffective()
	if err != nil || !exists {
		t.Fatalf("got exists=%v err=%v", exists, err)
	}
	if !cfg.SystemEnforced() {
		t.Error("merged config must report SystemEnforced")
	}
	if !cfg.IsContextProtected("prod-1") {
		t.Error("system's protected context must survive the user's empty list")
	}
	if got := cfg.EffectiveContextMode("prod-1"); got != ContextModeBlock {
		t.Errorf("context mode = %q, want block (user cannot downgrade)", got)
	}
	if pinned, ok := cfg.PinnedAuditLog(); !ok || pinned != "/var/log/kg.log" {
		t.Errorf("PinnedAuditLog = (%q,%v), want (/var/log/kg.log,true)", pinned, ok)
	}
}

// TestLoadEffectiveEnforcedIgnoresConfigEnv: under an enforced baseline,
// KUBECTL_GUARD_CONFIG is ignored so the user layer loads from the default HOME
// path (not the attacker-chosen empty file).
func TestLoadEffectiveEnforcedIgnoresConfigEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withSystemConfig(t, "enforced: true\ncontext_mode: block\nprotected_contexts:\n  - prod-*\n")
	// A real user config at the default path adds staging protection.
	if err := os.WriteFile(filepath.Join(home, configFileName), []byte("protected_contexts:\n  - staging-*\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The env points at an EMPTY config that would drop everything if honored.
	empty := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(empty, []byte("protected_contexts: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvConfig, empty)

	cfg, _, err := LoadEffective()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IsContextProtected("prod-1") {
		t.Error("system floor must apply regardless of KUBECTL_GUARD_CONFIG")
	}
	if !cfg.IsContextProtected("staging-1") {
		t.Error("the DEFAULT-path user config must be read (env redirect ignored under enforcement)")
	}
	// Path() must also ignore the env under enforcement.
	got, _ := Path()
	if want := filepath.Join(home, configFileName); got != want {
		t.Errorf("Path() = %q, want %q (env ignored under enforcement)", got, want)
	}
}

// TestLoadEffectiveInvalidSystemFailsClosed: an unparseable ENFORCED floor must
// return an error so the decision core fails closed.
func TestLoadEffectiveInvalidSystemFailsClosed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(EnvConfig, "")
	withSystemConfig(t, ":::not valid yaml:::[\n")
	if _, _, err := LoadEffective(); err == nil {
		t.Error("invalid system config must return an error (fail closed)")
	}
}

// TestAuditPathPinnedIgnoresEnv: an enforced merged config ignores
// KUBECTL_GUARD_AUDIT_LOG and uses the pinned/default destination.
func TestAuditPathPinnedIgnoresEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvAuditLog, "/tmp/attacker-audit.log")

	// Enforced with a pinned audit_log → pinned path, env ignored.
	pinned := &Config{AuditLog: "/var/log/pinned.log", systemEnforced: true, auditLogPinned: "/var/log/pinned.log"}
	if got, _ := AuditPath(pinned); got != "/var/log/pinned.log" {
		t.Errorf("AuditPath(enforced+pinned) = %q, want the pinned path (env ignored)", got)
	}
	// Enforced with NO audit_log → default path, env STILL ignored.
	enforcedNoLog := &Config{systemEnforced: true}
	want := filepath.Join(home, auditFileName)
	if got, _ := AuditPath(enforcedNoLog); got != want {
		t.Errorf("AuditPath(enforced,no audit_log) = %q, want default %q (env ignored)", got, want)
	}
	// NOT enforced → env still wins (regression: unchanged behavior).
	if got, _ := AuditPath(&Config{}); got != "/tmp/attacker-audit.log" {
		t.Errorf("AuditPath(not enforced) = %q, want the env override", got)
	}
}

// TestEnforcedSystemConfigFailSafe: a present-but-unreadable/invalid system
// config is reported as enforced (fail safe), an absent one is not.
func TestEnforcedSystemConfigFailSafe(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	withSystemConfig(t, "") // absent
	if _, enforced := EnforcedSystemConfig(); enforced {
		t.Error("absent system config must not be enforced")
	}
	withSystemConfig(t, ":::bad yaml:::[\n")
	if _, enforced := EnforcedSystemConfig(); !enforced {
		t.Error("present-but-invalid system config must fail safe to enforced")
	}
	withSystemConfig(t, "enforced: false\ncontext_mode: block\n")
	if _, enforced := EnforcedSystemConfig(); enforced {
		t.Error("a readable non-enforced system config must report not-enforced")
	}
}

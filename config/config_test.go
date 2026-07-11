package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsContextProtected(t *testing.T) {
	tests := []struct {
		name      string
		patterns  []string
		context   string
		protected bool
	}{
		{
			name:      "exact match",
			patterns:  []string{"prod-cluster"},
			context:   "prod-cluster",
			protected: true,
		},
		{
			name:      "no match",
			patterns:  []string{"prod-cluster"},
			context:   "staging",
			protected: false,
		},
		{
			name:      "wildcard suffix",
			patterns:  []string{"prod-*"},
			context:   "prod-us-east-1",
			protected: true,
		},
		{
			name:      "wildcard prefix",
			patterns:  []string{"*-production"},
			context:   "us-east-production",
			protected: true,
		},
		{
			name:      "wildcard no match",
			patterns:  []string{"prod-*"},
			context:   "staging-us-east-1",
			protected: false,
		},
		{
			name:      "multiple patterns first match",
			patterns:  []string{"prod-*", "staging-*"},
			context:   "prod-cluster",
			protected: true,
		},
		{
			name:      "multiple patterns second match",
			patterns:  []string{"prod-*", "staging-*"},
			context:   "staging-cluster",
			protected: true,
		},
		{
			name:      "empty patterns",
			patterns:  []string{},
			context:   "prod-cluster",
			protected: false,
		},
		{
			name:      "complex glob",
			patterns:  []string{"arn:aws:eks:*:*:cluster/prod-*"},
			context:   "arn:aws:eks:us-east-1:123456789:cluster/prod-main",
			protected: true,
		},
		// #30: '*' spans '/', so a path-shaped context name is matched. Under
		// the previous filepath.Match implementation these were NOT protected.
		{
			name:      "wildcard crosses slash",
			patterns:  []string{"prod-*"},
			context:   "prod-us/east/1",
			protected: true,
		},
		{
			name:      "wildcard spans whole path-shaped name",
			patterns:  []string{"prod*"},
			context:   "prod/us/east/1",
			protected: true,
		},
		{
			name:      "contains-anywhere crosses slash",
			patterns:  []string{"*prod*"},
			context:   "team-a/prod/cluster",
			protected: true,
		},
		{
			name:      "single star protects every context",
			patterns:  []string{"*"},
			context:   "any/thing:at-all",
			protected: true,
		},
		// The literal part of a pattern is still required to match literally.
		{
			name:      "literal prefix still enforced",
			patterns:  []string{"prod-*"},
			context:   "prod/us/east/1",
			protected: false,
		},
		// A malformed pattern degrades to a literal instead of silently
		// protecting nothing (see TestMatchGlobDoesNotFailOpen). Reporting the
		// typo to the user is config validation's job (#26).
		{
			name:      "malformed pattern does not match as a class",
			patterns:  []string{"prod-[abc"},
			context:   "prod-a",
			protected: false,
		},
		{
			name:      "malformed pattern matches itself literally",
			patterns:  []string{"prod-["},
			context:   "prod-[",
			protected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{ProtectedContexts: Patterns(tt.patterns...)}
			got := cfg.IsContextProtected(tt.context)
			if got != tt.protected {
				t.Errorf("IsContextProtected(%q) = %v, want %v", tt.context, got, tt.protected)
			}
		})
	}
}

func TestAddContext(t *testing.T) {
	cfg := &Config{ProtectedContexts: Patterns("existing")}

	// Add new context
	if !cfg.AddContext("new-context") {
		t.Error("AddContext returned false for new context")
	}
	if len(cfg.ProtectedContexts) != 2 {
		t.Errorf("Expected 2 contexts, got %d", len(cfg.ProtectedContexts))
	}

	// Add duplicate
	if cfg.AddContext("new-context") {
		t.Error("AddContext returned true for duplicate context")
	}
	if len(cfg.ProtectedContexts) != 2 {
		t.Errorf("Expected 2 contexts after duplicate, got %d", len(cfg.ProtectedContexts))
	}
}

func TestRemoveContext(t *testing.T) {
	cfg := &Config{ProtectedContexts: Patterns("first", "second", "third")}

	// Remove existing
	if !cfg.RemoveContext("second") {
		t.Error("RemoveContext returned false for existing context")
	}
	if len(cfg.ProtectedContexts) != 2 {
		t.Errorf("Expected 2 contexts, got %d", len(cfg.ProtectedContexts))
	}

	// Remove non-existing
	if cfg.RemoveContext("nonexistent") {
		t.Error("RemoveContext returned true for non-existing context")
	}
}

func TestSaveAndLoad(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "kubectl-guard-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Override home directory for test
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	// Test Exists when no config
	exists, err := Exists()
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("Exists returned true when config should not exist")
	}

	// Test Save
	cfg := &Config{
		ProtectedContexts: Patterns("prod-cluster", "prod-*"),
	}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}

	// Verify file exists
	exists, err = Exists()
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("Exists returned false after Save")
	}

	// Test Load
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.ProtectedContexts) != 2 {
		t.Errorf("Expected 2 contexts, got %d", len(loaded.ProtectedContexts))
	}
	if loaded.ProtectedContexts[0].Pattern != "prod-cluster" {
		t.Errorf("Expected first context 'prod-cluster', got %q", loaded.ProtectedContexts[0].Pattern)
	}

	// Verify file content has header
	path := filepath.Join(tmpDir, configFileName)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content[:1]) != "#" {
		t.Error("Config file should start with comment header")
	}
}

func TestPath(t *testing.T) {
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) {
		t.Error("Path should return absolute path")
	}
	if filepath.Base(path) != configFileName {
		t.Errorf("Expected filename %q, got %q", configFileName, filepath.Base(path))
	}
}

func TestNormalizeResource(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"secret", "secret"},
		{"secrets", "secret"},
		{"Secret", "secret"},
		{"secret/mysecret", "secret"},
		{"secrets.v1", "secret"},
		{"configmap", "configmap"},
		{"configmaps", "configmap"},
		// short names expand to canonical singular
		{"cm", "configmap"},
		{"cms", "configmap"},
		{"svc", "service"},
		{"ds", "daemonset"}, // trailing-s short name must not be singularized first
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := NormalizeResource(tt.in); got != tt.want {
				t.Errorf("NormalizeResource(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsResourceProtected(t *testing.T) {
	cfg := &Config{ProtectedResources: []string{"secret"}}

	tests := []struct {
		candidate string
		want      bool
	}{
		{"secret", true},
		{"secrets", true},
		{"Secret", true},
		{"secret/mysecret", true},
		{"configmap", false},
		{"pod", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.candidate, func(t *testing.T) {
			if got := cfg.IsResourceProtected(tt.candidate); got != tt.want {
				t.Errorf("IsResourceProtected(%q) = %v, want %v", tt.candidate, got, tt.want)
			}
		})
	}
}

func TestAddRemoveResource(t *testing.T) {
	cfg := &Config{}
	if !cfg.AddResource("secret") {
		t.Error("AddResource should return true for new resource")
	}
	if cfg.AddResource("secrets") {
		t.Error("AddResource should return false for equivalent plural")
	}
	if len(cfg.ProtectedResources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(cfg.ProtectedResources))
	}
	if !cfg.RemoveResource("secrets") {
		t.Error("RemoveResource should return true for equivalent plural")
	}
	if len(cfg.ProtectedResources) != 0 {
		t.Errorf("expected 0 resources, got %d", len(cfg.ProtectedResources))
	}
	if cfg.RemoveResource("secret") {
		t.Error("RemoveResource should return false when absent")
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyDefaults()
	if cfg.ConfirmMode != ConfirmModeSimple {
		t.Errorf("expected default confirm mode %q, got %q", ConfirmModeSimple, cfg.ConfirmMode)
	}
	if !cfg.SetConfirmMode(ConfirmModeTypeName) {
		t.Error("SetConfirmMode should accept type-name")
	}
	if cfg.ConfirmMode != ConfirmModeTypeName {
		t.Errorf("expected type-name, got %q", cfg.ConfirmMode)
	}
	if !cfg.SetConfirmMode(ConfirmModeAgentRelay) {
		t.Error("SetConfirmMode should accept agent-relay")
	}
	if cfg.ConfirmMode != ConfirmModeAgentRelay {
		t.Errorf("expected agent-relay, got %q", cfg.ConfirmMode)
	}
	if cfg.SetConfirmMode("bogus") {
		t.Error("SetConfirmMode should reject invalid mode")
	}
}

func TestAuditPath(t *testing.T) {
	// Default path under home.
	p, err := AuditPath(nil)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p) != auditFileName {
		t.Errorf("expected %q, got %q", auditFileName, filepath.Base(p))
	}
	// Explicit override.
	p, _ = AuditPath(&Config{AuditLog: "/tmp/custom-audit.log"})
	if p != "/tmp/custom-audit.log" {
		t.Errorf("expected custom path, got %q", p)
	}
}

func TestApplyDefaultsAuditMode(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyDefaults()
	if cfg.AuditMode != AuditModeAll {
		t.Errorf("expected default audit mode %q, got %q", AuditModeAll, cfg.AuditMode)
	}
}

func TestSetAuditMode(t *testing.T) {
	cfg := &Config{}
	for _, valid := range []string{AuditModeAll, AuditModeGated, AuditModeOff} {
		if !cfg.SetAuditMode(valid) {
			t.Errorf("SetAuditMode(%q) should return true", valid)
		}
		if cfg.AuditMode != valid {
			t.Errorf("expected %q, got %q", valid, cfg.AuditMode)
		}
	}
	if cfg.SetAuditMode("bogus") {
		t.Error("SetAuditMode should reject invalid mode")
	}
}

func TestShouldAudit(t *testing.T) {
	tests := []struct {
		mode    string
		outcome string
		want    bool
	}{
		// "all" logs everything
		{AuditModeAll, "allowed", true},
		{AuditModeAll, "confirmed", true},
		{AuditModeAll, "aborted", true},
		{AuditModeAll, "blocked", true},
		{AuditModeAll, "denied", true},

		// "gated" logs only interventions (not allowed passthrough)
		{AuditModeGated, "allowed", false},
		{AuditModeGated, "confirmed", true},
		{AuditModeGated, "aborted", true},
		{AuditModeGated, "blocked", true},
		{AuditModeGated, "denied", true},

		// "off" logs nothing
		{AuditModeOff, "allowed", false},
		{AuditModeOff, "confirmed", false},
		{AuditModeOff, "blocked", false},
	}
	for _, tt := range tests {
		t.Run(tt.mode+"_"+tt.outcome, func(t *testing.T) {
			cfg := &Config{AuditMode: tt.mode}
			if got := cfg.ShouldAudit(tt.outcome); got != tt.want {
				t.Errorf("ShouldAudit(%q) in mode %q = %v, want %v", tt.outcome, tt.mode, got, tt.want)
			}
		})
	}
}

func TestSaveIsAtomic(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "kubectl-guard-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Override home directory for test
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tmpDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	// Write initial config
	cfg := &Config{
		ProtectedContexts: Patterns("prod-cluster"),
	}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}

	// Read the initial content
	path := filepath.Join(tmpDir, configFileName)
	originalContent, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Make directory read-only to simulate write failure
	if err := os.Chmod(tmpDir, 0500); err != nil {
		t.Fatal(err)
	}

	// Attempt to save a modified config (should fail)
	cfg2 := &Config{
		ProtectedContexts: Patterns("prod-cluster", "staging-cluster"),
	}
	err = Save(cfg2)
	if err == nil {
		t.Error("Save should fail when directory is read-only")
	}

	// Restore directory permissions for cleanup
	if err := os.Chmod(tmpDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Verify original config is unchanged
	currentContent, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(currentContent) != string(originalContent) {
		t.Error("Original config was modified after failed save")
	}

	// Verify no temp files remain
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".kubectl-guard-") && strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("Temp file remains after failed save: %s", entry.Name())
		}
	}
}

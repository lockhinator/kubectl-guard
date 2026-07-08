package config

import (
	"os"
	"path/filepath"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{ProtectedContexts: tt.patterns}
			got := cfg.IsContextProtected(tt.context)
			if got != tt.protected {
				t.Errorf("IsContextProtected(%q) = %v, want %v", tt.context, got, tt.protected)
			}
		})
	}
}

func TestAddContext(t *testing.T) {
	cfg := &Config{ProtectedContexts: []string{"existing"}}

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
	cfg := &Config{ProtectedContexts: []string{"first", "second", "third"}}

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
	defer os.RemoveAll(tmpDir)

	// Override home directory for test
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

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
		ProtectedContexts: []string{"prod-cluster", "prod-*"},
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
	if loaded.ProtectedContexts[0] != "prod-cluster" {
		t.Errorf("Expected first context 'prod-cluster', got %q", loaded.ProtectedContexts[0])
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

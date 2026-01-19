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

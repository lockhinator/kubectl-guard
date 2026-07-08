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
	ConfirmModeSimple   = "simple"     // y/N prompt (default)
	ConfirmModeTypeName = "type-name"  // must type the context name exactly
)

const (
	configFileName = ".kubectl-guard.yaml"
	auditFileName  = ".kubectl-guard-audit.log"
)

// Config represents the kubectl-guard configuration.
type Config struct {
	// ProtectedContexts are context name patterns (glob) that require
	// confirmation for state-altering commands.
	ProtectedContexts []string `yaml:"protected_contexts,omitempty"`

	// ProtectedResources are resource names (e.g. "secret") whose access is
	// blocked entirely on every context, regardless of verb. Singular and
	// plural forms ("secret", "secrets") match the same things.
	ProtectedResources []string `yaml:"protected_resources,omitempty"`

	// ConfirmMode controls the confirmation prompt for protected contexts.
	// "simple" (default) is a y/N prompt; "type-name" requires the user to
	// type the context name exactly.
	ConfirmMode string `yaml:"confirm_mode,omitempty"`

	// AuditLog is the path to the audit log file. When empty it defaults to
	// ~/.kubectl-guard-audit.log.
	AuditLog string `yaml:"audit_log,omitempty"`
}

// ApplyDefaults fills in zero-value fields with sensible defaults.
func (c *Config) ApplyDefaults() {
	if c.ConfirmMode == "" {
		c.ConfirmMode = ConfirmModeSimple
	}
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

// Save writes the config to disk.
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
	return os.WriteFile(path, []byte(header+string(data)), 0600)
}

// IsContextProtected checks if a context matches any protected pattern.
func (c *Config) IsContextProtected(context string) bool {
	for _, pattern := range c.ProtectedContexts {
		if matched, _ := filepath.Match(pattern, context); matched {
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

// NormalizeResource canonicalizes a resource name for matching: lower-cased,
// stripped of any "/name" or ".group" suffix, and with a trailing "s" removed
// so that singular and plural forms ("secret", "secrets") compare equal.
func NormalizeResource(name string) string {
	if i := strings.IndexAny(name, "/."); i >= 0 {
		name = name[:i]
	}
	return strings.ToLower(strings.TrimSuffix(name, "s"))
}

// IsResourceProtected reports whether candidate names a protected resource.
// Matching is case-insensitive and treats singular/plural as equivalent.
func (c *Config) IsResourceProtected(candidate string) bool {
	if candidate == "" || len(c.ProtectedResources) == 0 {
		return false
	}
	lc := strings.ToLower(candidate)
	nc := NormalizeResource(candidate)
	for _, p := range c.ProtectedResources {
		if lc == strings.ToLower(p) || nc == NormalizeResource(p) {
			return true
		}
	}
	return false
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

// RemoveResource removes a resource (or its singular/plural equivalent) from
// the protected list. Returns false if it was not present.
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
	switch mode {
	case ConfirmModeSimple, ConfirmModeTypeName:
		c.ConfirmMode = mode
		return true
	}
	return false
}

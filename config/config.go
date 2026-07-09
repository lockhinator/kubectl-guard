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

	// Actor is a static default identity for who drove a command (e.g.
	// "ci-deploy"), stamped into audit entries when KUBECTL_GUARD_ACTOR is
	// unset. Empty falls back to the OS username.
	Actor string `yaml:"actor,omitempty"`

	// BlockImpersonation, when true, denies any command carrying --as / --as-group
	// / --as-uid on a protected context. Impersonation is a common
	// privilege-escalation and audit-evasion vector. Off by default.
	BlockImpersonation bool `yaml:"block_impersonation,omitempty"`
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

// SetAuditMode sets the audit mode if the value is valid.
func (c *Config) SetAuditMode(mode string) bool {
	switch mode {
	case AuditModeAll, AuditModeGated, AuditModeOff:
		c.AuditMode = mode
		return true
	}
	return false
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

// HasProtectedNamespaces reports whether any namespace protection is configured.
func (c *Config) HasProtectedNamespaces() bool {
	return len(c.ProtectedNamespaces) > 0
}

// IsNamespaceProtected checks if a namespace matches any protected pattern.
func (c *Config) IsNamespaceProtected(namespace string) bool {
	for _, pattern := range c.ProtectedNamespaces {
		if matched, _ := filepath.Match(pattern, namespace); matched {
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
	switch mode {
	case ContextModeConfirm, ContextModeBlock:
		c.ContextMode = mode
		return true
	}
	return false
}

// SetNamespaceMode sets the namespace protection mode if valid.
func (c *Config) SetNamespaceMode(mode string) bool {
	switch mode {
	case NamespaceModeConfirm, NamespaceModeBlock:
		c.NamespaceMode = mode
		return true
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

// NormalizeResource canonicalizes a resource name for matching: lower-cased,
// stripped of any "/name" or ".group" suffix, singularized, and expanded from
// short name to canonical form. This makes "secret", "secrets", "Secret", and
// "cm"/"configmap" compare predictably.
func NormalizeResource(name string) string {
	if i := strings.IndexAny(name, "/."); i >= 0 {
		name = name[:i]
	}
	name = strings.ToLower(name)
	if full, ok := resourceShortNames[name]; ok {
		return full
	}
	singular := strings.TrimSuffix(name, "s")
	if full, ok := resourceShortNames[singular]; ok {
		return full
	}
	return singular
}

// IsResourceProtected reports whether candidate names a protected resource.
// Matching is case-insensitive and treats singular/plural/short-name forms as
// equivalent.
func (c *Config) IsResourceProtected(candidate string) bool {
	if candidate == "" || len(c.ProtectedResources) == 0 {
		return false
	}
	nc := NormalizeResource(candidate)
	for _, p := range c.ProtectedResources {
		if nc == NormalizeResource(p) {
			return true
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
	switch mode {
	case ConfirmModeSimple, ConfirmModeTypeName:
		c.ConfirmMode = mode
		return true
	}
	return false
}

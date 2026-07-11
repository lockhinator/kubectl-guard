package guard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// writeRawConfig writes a literal YAML config into an isolated HOME, bypassing
// config.Save (which only ever writes valid values). Returns a cleanup func.
func writeRawConfig(t *testing.T, yaml string) func() {
	t.Helper()
	tmp := t.TempDir()
	orig := os.Getenv("HOME")
	_ = os.Setenv("HOME", tmp)
	path := filepath.Join(tmp, ".kubectl-guard.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	return func() { _ = os.Setenv("HOME", orig) }
}

// TestInvalidConfigFailsClosed is the security property of #26: a config with an
// invalid known-field value must make the guard refuse EVERY command, so an
// unnoticed typo can never leave the guard running with protection weaker than
// the user configured. This covers reads too — nothing runs until it's fixed.
func TestInvalidConfigFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		// context_mode: blck silently downgraded "block" to "confirm" before #26.
		{"bad context_mode", "protected_contexts: [prod-*]\ncontext_mode: blck\n"},
		{"bad confirm_mode", "protected_contexts: [prod-*]\nconfirm_mode: typname\n"},
		{"bad audit_mode", "protected_contexts: [prod-*]\naudit_mode: sometimes\n"},
		{"bad namespace_mode", "protected_namespaces: [kube-system]\nnamespace_mode: hard\n"},
		{"unterminated glob", "protected_contexts: ['prod-[']\n"},
		{"empty resource", "protected_resources: ['']\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cleanup := writeRawConfig(t, tc.yaml)
			defer cleanup()

			// Even a read must be denied while the config is invalid.
			for _, args := range [][]string{
				{"get", "pods"},
				{"delete", "pod", "nginx"},
			} {
				res, _, _, err := checkWith(args, staticContext("prod-1"))
				if res != Deny {
					t.Errorf("checkWith(%v) = %v, want Deny (invalid config must fail closed)", args, res)
				}
				if err == nil {
					t.Errorf("checkWith(%v): expected an error describing the invalid config", args)
				}
			}
		})
	}
}

// TestValidConfigDoesNotFailClosed: the fail-closed path must not fire for a
// valid config — including every mode at its non-default value and globs with
// classes/escapes. A false positive here would break every command.
func TestValidConfigDoesNotFailClosed(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts:   config.Patterns("prod-*", "arn:aws:eks:*:*:cluster/prod-[a-z]"),
		ProtectedNamespaces: config.Patterns("kube-system"),
		ProtectedResources:  []string{"secret"},
		ConfirmMode:         config.ConfirmModeTypeName,
		AuditMode:           config.AuditModeGated,
		ContextMode:         config.ContextModeBlock,
		NamespaceMode:       config.NamespaceModeBlock,
	})
	defer cleanup()

	// A safe read on an unprotected context passes through.
	if res, _, _, _ := checkWith([]string{"get", "pods"}, staticContext("dev")); res != Allow {
		t.Errorf("valid config, read on unprotected context = %v, want Allow", res)
	}
	// The configured block mode still takes effect (not downgraded, not denied).
	if res, _, _, _ := checkWith([]string{"delete", "pod", "x"}, staticContext("prod-1")); res != Blocked {
		t.Errorf("valid block-mode config on protected context = %v, want Blocked", res)
	}
}

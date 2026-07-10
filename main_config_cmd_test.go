package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// runConfigInProc drives runConfigCommand() in-process with os.Args set to the
// given config subcommand. Unlike the subprocess integration tests, this
// exercises main.go's config-command surface under coverage instrumentation, so
// the branches actually count. HOME is isolated by the caller via t.Setenv.
func runConfigInProc(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	oldArgs := os.Args
	// runConfigCommand consumes os.Args[2:], matching the real invocation
	// `kubectl-guard config <subcommand> ...`, so prepend both leading tokens.
	os.Args = append([]string{"kubectl-guard", "config"}, args...)
	oldStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatal(pipeErr)
	}
	os.Stdout = w
	err = runConfigCommand()
	_ = w.Close()
	os.Stdout = oldStdout
	os.Args = oldArgs
	b, _ := io.ReadAll(r)
	return string(b), err
}

// loadCfg reads the on-disk config in the isolated HOME (defaults applied).
func loadCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.ApplyDefaults()
	return cfg
}

// TestConfigCommandsInProc exercises the runConfigCommand surface end to end,
// in-process, so a regression in any config subcommand is caught and main-package
// coverage reflects the config CLI. Covers #32 (main at 0%).
func TestConfigCommandsInProc(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Ensure no env override leaks in from the developer's shell.
	t.Setenv("KUBECTL_GUARD_CONFIG", "")
	t.Setenv("KUBECTL_GUARD_AUDIT_LOG", "")

	// path prints the resolved config path.
	if out, err := runConfigInProc(t, "path"); err != nil {
		t.Fatalf("config path: %v", err)
	} else if !strings.Contains(out, ".kubectl-guard.yaml") {
		t.Errorf("path output = %q, want it to contain the config filename", out)
	}

	// list with no config is a clean no-op.
	if _, err := runConfigInProc(t, "list"); err != nil {
		t.Fatalf("config list (no config): %v", err)
	}

	// Protected-list mutations round-trip through disk.
	mustRun(t, "add-context", "prod-*")
	if got := loadCfg(t).ProtectedContexts; len(got) != 1 || got[0] != "prod-*" {
		t.Fatalf("ProtectedContexts = %v, want [prod-*]", got)
	}
	mustRun(t, "add-resource", "secret")
	if got := loadCfg(t).ProtectedResources; len(got) != 1 || got[0] != "secret" {
		t.Fatalf("ProtectedResources = %v, want [secret]", got)
	}
	mustRun(t, "add-namespace", "kube-system")
	if got := loadCfg(t).ProtectedNamespaces; len(got) != 1 || got[0] != "kube-system" {
		t.Fatalf("ProtectedNamespaces = %v, want [kube-system]", got)
	}

	// Mode setters: valid values persist; invalid values error without writing.
	modeCases := []struct {
		sub, valid, invalid, getter string
	}{
		{"confirm-mode", "type-name", "nonsense", "confirmMode"},
		{"context-mode", "block", "nope", "contextMode"},
		{"namespace-mode", "block", "nope", "namespaceMode"},
		{"blast-radius", "gate", "loud", "blastRadius"},
		{"audit-mode", "gated", "sometimes", "auditMode"},
		{"unknown-verb", "deny", "maybe", "unknownVerb"},
	}
	for _, mc := range modeCases {
		mustRun(t, mc.sub, mc.valid)
		if _, err := runConfigInProc(t, mc.sub, mc.invalid); err == nil {
			t.Errorf("%s %s: expected error for invalid mode", mc.sub, mc.invalid)
		}
	}
	cfg := loadCfg(t)
	if cfg.ConfirmMode != "type-name" || cfg.ContextMode != "block" ||
		cfg.NamespaceMode != "block" || cfg.BlastRadius != "gate" ||
		cfg.AuditMode != "gated" || cfg.UnknownVerb != "deny" {
		t.Fatalf("mode setters did not persist: %+v", cfg)
	}

	// Audit rotation / webhook / syslog / weakening toggles.
	mustRun(t, "audit-rotation", "5", "3")
	if cfg = loadCfg(t); cfg.AuditMaxSizeMB != 5 || cfg.AuditMaxFiles != 3 {
		t.Errorf("audit-rotation not persisted: size=%d files=%d", cfg.AuditMaxSizeMB, cfg.AuditMaxFiles)
	}
	if _, err := runConfigInProc(t, "audit-rotation", "notanumber"); err == nil {
		t.Errorf("audit-rotation: expected error for non-numeric size")
	}
	mustRun(t, "audit-webhook", "https://example.test/hook")
	if loadCfg(t).AuditWebhookURL != "https://example.test/hook" {
		t.Errorf("audit-webhook not persisted")
	}
	if _, err := runConfigInProc(t, "audit-webhook", "not-a-url"); err == nil {
		t.Errorf("audit-webhook: expected error for invalid URL")
	}
	mustRun(t, "audit-webhook", "off")
	if loadCfg(t).AuditWebhookURL != "" {
		t.Errorf("audit-webhook off did not clear the URL")
	}
	mustRun(t, "audit-syslog", "on")
	if !loadCfg(t).AuditSyslog {
		t.Errorf("audit-syslog on not persisted")
	}

	// Command overrides: safe / dangerous / remove.
	mustRun(t, "command-override", "safe", "mycmd")
	mustRun(t, "command-override", "dangerous", "logs")
	if _, err := runConfigInProc(t, "command-override", "bogus", "x"); err == nil {
		t.Errorf("command-override: expected error for unknown action")
	}
	mustRun(t, "command-override", "remove", "mycmd")

	// Actor policies: set, list, remove.
	mustRun(t, "actor-policy", "ci-bot", "block", "block")
	if got := loadCfg(t).ActorPolicies; len(got) != 1 || got[0].Actor != "ci-bot" {
		t.Fatalf("actor policy not persisted: %v", got)
	}
	if _, err := runConfigInProc(t, "actor-policy"); err != nil {
		t.Errorf("actor-policy list: %v", err)
	}
	mustRun(t, "actor-policy", "remove", "ci-bot")
	if len(loadCfg(t).ActorPolicies) != 0 {
		t.Errorf("actor-policy remove did not delete the policy")
	}

	// list now renders a populated config without error.
	if out, err := runConfigInProc(t, "list"); err != nil {
		t.Fatalf("config list (populated): %v", err)
	} else if !strings.Contains(out, "prod-*") {
		t.Errorf("list output missing protected context, got %q", out)
	}

	// audit prints the log path and recent entries; the mutations above each
	// wrote a config-change entry, so the output must actually contain them (not
	// merely return nil) — otherwise a silent "stopped printing" regression slips.
	if out, err := runConfigInProc(t, "audit"); err != nil {
		t.Fatalf("config audit: %v", err)
	} else if !strings.Contains(out, "config-change") {
		t.Errorf("config audit did not print recorded entries, got %q", out)
	}

	// Removals round-trip too (weakening, but confirm-weakening is off).
	mustRun(t, "remove-context", "prod-*")
	mustRun(t, "remove-resource", "secret")
	mustRun(t, "remove-namespace", "kube-system")
	final := loadCfg(t)
	if len(final.ProtectedContexts) != 0 || len(final.ProtectedResources) != 0 || len(final.ProtectedNamespaces) != 0 {
		t.Errorf("removals did not clear protected lists: %+v", final)
	}
}

// mustRun runs a config subcommand in-process and fails the test on error.
func mustRun(t *testing.T, args ...string) {
	t.Helper()
	if _, err := runConfigInProc(t, args...); err != nil {
		t.Fatalf("config %s: %v", strings.Join(args, " "), err)
	}
}

// runConfigStdin is runConfigInProc with os.Stdin redirected to feed the
// weakening-confirmation prompt in saveConfig.
func runConfigStdin(t *testing.T, stdin string, args ...string) error {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdin := os.Stdin
	os.Stdin = r
	go func() {
		_, _ = w.WriteString(stdin)
		_ = w.Close()
	}()
	_, cmdErr := runConfigInProc(t, args...)
	os.Stdin = oldStdin
	_ = r.Close()
	return cmdErr
}

// TestConfirmWeakeningGate covers saveConfig's protection-weakening gate: with
// require_confirm_weakening on, a weakening change aborts on "no" and applies on
// "yes". #32.
func TestConfirmWeakeningGate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KUBECTL_GUARD_CONFIG", "")
	t.Setenv("KUBECTL_GUARD_AUDIT_LOG", "")

	// Establish protection, then enable the weakening gate. Enabling it is not
	// itself a weakening, so it does not prompt.
	mustRun(t, "add-context", "prod-*")
	mustRun(t, "confirm-weakening", "on")
	if !loadCfg(t).RequireConfirmWeakening {
		t.Fatalf("confirm-weakening on not persisted")
	}

	// Removing a protected context weakens protection: "no" aborts, config unchanged.
	if err := runConfigStdin(t, "n\n", "remove-context", "prod-*"); err == nil {
		t.Errorf("expected weakening removal to abort on 'no'")
	}
	if got := loadCfg(t).ProtectedContexts; len(got) != 1 {
		t.Errorf("declined weakening still mutated config: %v", got)
	}

	// "yes" applies the weakening.
	if err := runConfigStdin(t, "y\n", "remove-context", "prod-*"); err != nil {
		t.Errorf("confirmed weakening removal errored: %v", err)
	}
	if got := loadCfg(t).ProtectedContexts; len(got) != 0 {
		t.Errorf("confirmed weakening did not mutate config: %v", got)
	}
}

// TestConfigInitInProc covers the non-interactive `config init` path.
func TestConfigInitInProc(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KUBECTL_GUARD_CONFIG", "")
	t.Setenv("KUBECTL_GUARD_AUDIT_LOG", "")

	if _, err := runConfigInProc(t, "init",
		"--protected-contexts", "prod-*,staging-*",
		"--protected-resources", "secret",
		"--confirm-mode", "type-name"); err != nil {
		t.Fatalf("config init: %v", err)
	}
	cfg := loadCfg(t)
	if len(cfg.ProtectedContexts) != 2 {
		t.Errorf("init: ProtectedContexts = %v, want 2 entries", cfg.ProtectedContexts)
	}
	if cfg.ConfirmMode != "type-name" {
		t.Errorf("init: ConfirmMode = %q, want type-name", cfg.ConfirmMode)
	}
}

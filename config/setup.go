package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/lockhinator/kubectl-guard/ui"
)

// Environment variables for headless / non-interactive first-run configuration.
// When the config file does not exist and these are set, the guard writes the
// initial config from them instead of launching the interactive wizard.
const (
	EnvProtectedContexts = "KUBECTL_GUARD_PROTECTED_CONTEXTS"
	EnvProtectedResources = "KUBECTL_GUARD_PROTECTED_RESOURCES"
	EnvConfirmMode        = "KUBECTL_GUARD_CONFIRM_MODE"
	EnvNoPrompt           = "KUBECTL_GUARD_NO_PROMPT"
	EnvConfirm            = "KUBECTL_GUARD_CONFIRM"  // audited auto-confirm of RequireConfirmation
	EnvBypass             = "KUBECTL_GUARD_BYPASS"   // audited full bypass (discouraged)
)

// InitFromEnv builds a Config from the KUBECTL_GUARD_* environment variables.
// It returns the config and ok=true when at least one protection value
// (protected contexts or resources) was provided, so callers can distinguish
// "bootstrap from env" from "nothing specified". confirm_mode is applied as a
// modifier when valid but does not by itself suppress the wizard (it is
// meaningless without something to protect). Empty tokens are skipped.
func InitFromEnv() (cfg *Config, ok bool) {
	cfg = &Config{}
	cfg.ProtectedContexts = append(cfg.ProtectedContexts, splitCSV(os.Getenv(EnvProtectedContexts))...)
	cfg.ProtectedResources = append(cfg.ProtectedResources, splitCSV(os.Getenv(EnvProtectedResources))...)
	if m := strings.TrimSpace(os.Getenv(EnvConfirmMode)); m == ConfirmModeSimple || m == ConfirmModeTypeName {
		cfg.ConfirmMode = m
	}
	cfg.ApplyDefaults()
	return cfg, len(cfg.ProtectedContexts) > 0 || len(cfg.ProtectedResources) > 0
}

// InitFromFlags builds a Config from explicit flag values (comma-separated,
// like the env vars). It powers `config init`. Empty strings are ignored.
func InitFromFlags(protectedContexts, protectedResources, confirmMode string) *Config {
	cfg := &Config{}
	cfg.ProtectedContexts = append(cfg.ProtectedContexts, splitCSV(protectedContexts)...)
	cfg.ProtectedResources = append(cfg.ProtectedResources, splitCSV(protectedResources)...)
	if m := strings.TrimSpace(confirmMode); m == ConfirmModeSimple || m == ConfirmModeTypeName {
		cfg.ConfirmMode = m
	}
	cfg.ApplyDefaults()
	return cfg
}

// splitCSV splits a comma-separated env/flag value, trimming whitespace and
// dropping empty tokens.
func splitCSV(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// RunSetup runs the first-time setup wizard with the given context names.
// Returns true if setup completed successfully, false if user quit.
func RunSetup(contextNames []string) bool {
	if len(contextNames) == 0 {
		ui.PrintWarning("No kubectl contexts found.")
		ui.PrintInfo("Configure kubectl first, then re-run your command.")
		return false
	}

	// Build multi-select items
	items := make([]ui.MultiSelectItem, len(contextNames))
	for i, name := range contextNames {
		items[i] = ui.MultiSelectItem{
			Name:     name,
			Selected: false,
		}
	}

	// Run multi-select
	selected, confirmed := ui.MultiSelect(items)
	if !confirmed {
		fmt.Println("Setup cancelled.")
		return false
	}

	// Build config from selections
	cfg := &Config{
		ProtectedContexts: make([]string, 0),
	}
	for _, item := range selected {
		if item.Selected {
			cfg.ProtectedContexts = append(cfg.ProtectedContexts, item.Name)
		}
	}

	// Save config
	if err := Save(cfg); err != nil {
		ui.PrintWarning("Failed to save config: " + err.Error())
		return false
	}

	// Print summary
	path, _ := Path()
	ui.PrintSuccess("Saved to " + path)

	if len(cfg.ProtectedContexts) > 0 {
		ui.PrintInfo("Protected: " + strings.Join(cfg.ProtectedContexts, ", "))
	} else {
		ui.PrintInfo("No contexts protected.")
	}

	fmt.Println()
	ui.PrintInfo("Re-run your command to continue.")

	return true
}

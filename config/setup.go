package config

import (
	"fmt"
	"strings"

	"github.com/cameronlockhart/kubectl-guard/ui"
)

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

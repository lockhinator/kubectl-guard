package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/cameronlockhart/kubectl-guard/config"
	"github.com/cameronlockhart/kubectl-guard/guard"
	"github.com/cameronlockhart/kubectl-guard/ui"
	"github.com/spf13/cobra"
)

var version = "dev"

// guardConfigSubcommands are the kubectl-guard "config" subcommands. Any other
// "config <subcommand>" (e.g. "config use-context", "config view") is a kubectl
// command and must be forwarded through the guard rather than intercepted.
var guardConfigSubcommands = map[string]bool{
	"setup":           true,
	"list":            true,
	"add":             true,
	"remove":          true,
	"add-context":     true,
	"remove-context":  true,
	"add-resource":    true,
	"remove-resource": true,
	"confirm-mode":    true,
	"audit":           true,
	"path":            true,
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "config":
			// Only intercept kubectl-guard's own config subcommands; forward
			// kubectl's own "config ..." commands (use-context, view, ...) to
			// the guard so they are protected too.
			if len(os.Args) > 2 && guardConfigSubcommands[os.Args[2]] {
				return runConfigCommand()
			}
			return runGuard(os.Args[1:])
		case "--version", "-v":
			fmt.Printf("kubectl-guard %s\n", version)
			return nil
		case "--help", "-h":
			printHelp()
			return nil
		}
	}

	// Otherwise, forward to kubectl with protection
	return runGuard(os.Args[1:])
}

func runGuard(args []string) error {
	result, ctx, err := guard.Check(args)
	if err != nil {
		// On error, still try to run kubectl
		return guard.ExecKubectl(args)
	}

	switch result {
	case guard.SetupRequired:
		contexts, err := guard.GetAllContexts()
		if err != nil {
			ui.PrintWarning("Could not get kubectl contexts: " + err.Error())
			ui.PrintInfo("Make sure kubectl is installed and configured.")
			return nil
		}
		contextNames := make([]string, len(contexts))
		for i, c := range contexts {
			contextNames[i] = c.Name
		}
		config.RunSetup(contextNames)
		return nil

	case guard.Blocked:
		cfg, _ := guard.LoadConfig()
		cmdDesc := guard.GetCommandDescription(args)
		ui.PrintWarning(fmt.Sprintf("Blocked: %s targets a protected resource (context: %s)", cmdDesc, ctx))
		_ = guard.AppendAudit(cfg, guard.AuditEntry{
			Context: ctx,
			Command: strings.Join(args, " "),
			Outcome: "blocked",
			Reason:  "protected-resource",
		})
		os.Exit(1)

	case guard.RequireConfirmation:
		cfg, _ := guard.LoadConfig()
		cmdDesc := guard.GetCommandDescription(args)
		message := fmt.Sprintf("%s on protected context: %s", cmdDesc, ctx)

		confirmed := false
		if cfg != nil && cfg.ConfirmMode == config.ConfirmModeTypeName {
			confirmed = ui.ConfirmWithName(message, ctx)
		} else {
			confirmed = ui.Confirm(message)
		}

		if confirmed {
			_ = guard.AppendAudit(cfg, guard.AuditEntry{
				Context: ctx,
				Command: strings.Join(args, " "),
				Outcome: "confirmed",
			})
			return guard.ExecKubectl(args)
		}

		_ = guard.AppendAudit(cfg, guard.AuditEntry{
			Context: ctx,
			Command: strings.Join(args, " "),
			Outcome: "aborted",
		})
		fmt.Println("Aborted.")
		os.Exit(1)

	case guard.Allow:
		return guard.ExecKubectl(args)
	}

	return nil
}

func runConfigCommand() error {
	rootCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage kubectl-guard configuration",
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "setup",
		Short: "Run the setup wizard",
		RunE: func(cmd *cobra.Command, args []string) error {
			contexts, err := guard.GetAllContexts()
			if err != nil {
				return fmt.Errorf("could not get kubectl contexts: %w", err)
			}
			contextNames := make([]string, len(contexts))
			for i, c := range contexts {
				contextNames[i] = c.Name
			}
			config.RunSetup(contextNames)
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List protected contexts and resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			return printConfig()
		},
	})

	// add / add-context
	addContext := &cobra.Command{
		Use:   "add-context <pattern>",
		Short: "Add a context/pattern to the protected list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return mutateConfig(func(cfg *config.Config) bool { return cfg.AddContext(args[0]) }, "Added context: "+args[0], "Context already protected: "+args[0])
		},
	}
	rootCmd.AddCommand(addContext)
	// "add" is an alias for add-context (backwards compatible).
	rootCmd.AddCommand(&cobra.Command{
		Use:               "add <pattern>",
		Short:             "Alias for add-context",
		Args:              cobra.ExactArgs(1),
		Hidden:            true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return mutateConfig(func(cfg *config.Config) bool { return cfg.AddContext(args[0]) }, "Added context: "+args[0], "Context already protected: "+args[0])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "remove-context <pattern>",
		Short: "Remove a context/pattern from the protected list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return mutateConfig(func(cfg *config.Config) bool { return cfg.RemoveContext(args[0]) }, "Removed context: "+args[0], "Context not in protected list: "+args[0])
		},
	})
	// "remove" alias for remove-context.
	rootCmd.AddCommand(&cobra.Command{
		Use:               "remove <pattern>",
		Short:             "Alias for remove-context",
		Args:              cobra.ExactArgs(1),
		Hidden:            true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return mutateConfig(func(cfg *config.Config) bool { return cfg.RemoveContext(args[0]) }, "Removed context: "+args[0], "Context not in protected list: "+args[0])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "add-resource <name>",
		Short: "Add a resource to block on every context (e.g. secret)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return mutateConfig(func(cfg *config.Config) bool { return cfg.AddResource(args[0]) }, "Blocked resource: "+args[0], "Resource already protected: "+args[0])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "remove-resource <name>",
		Short: "Remove a resource from the blocked list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return mutateConfig(func(cfg *config.Config) bool { return cfg.RemoveResource(args[0]) }, "Unblocked resource: "+args[0], "Resource not in protected list: "+args[0])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "confirm-mode [simple|type-name]",
		Short: "Show or set the confirmation mode for protected contexts",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				ui.PrintInfo("Confirm mode: " + cfg.ConfirmMode)
				return nil
			}
			if !cfg.SetConfirmMode(args[0]) {
				return fmt.Errorf("invalid mode %q (want %q or %q)", args[0], config.ConfirmModeSimple, config.ConfirmModeTypeName)
			}
			if err := config.Save(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Confirm mode set: " + cfg.ConfirmMode)
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "audit",
		Short: "Show the audit log path and recent entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			path, err := config.AuditPath(cfg)
			if err != nil {
				return err
			}
			ui.PrintInfo("Audit log: " + path)
			data, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					ui.PrintInfo("No audit entries yet.")
					return nil
				}
				return err
			}
			lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
			start := 0
			if len(lines) > 10 {
				start = len(lines) - 10
			}
			ui.PrintInfo(fmt.Sprintf("Last %d entries:", len(lines)-start))
			for _, l := range lines[start:] {
				fmt.Println("  " + l)
			}
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "path",
		Short: "Print the config file path",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := config.Path()
			if err != nil {
				return err
			}
			fmt.Println(path)
			return nil
		},
	})

	// Parse args starting from "config"
	rootCmd.SetArgs(os.Args[2:])
	return rootCmd.Execute()
}

// mutateConfig loads (or creates) the config, applies fn, saves on change, and
// prints the appropriate message.
func mutateConfig(fn func(*config.Config) bool, addedMsg, existsMsg string) error {
	cfg, err := loadOrCreateConfig()
	if err != nil {
		return err
	}
	if fn(cfg) {
		if err := config.Save(cfg); err != nil {
			return err
		}
		ui.PrintSuccess(addedMsg)
	} else {
		ui.PrintInfo(existsMsg)
	}
	return nil
}

func printConfig() error {
	exists, err := config.Exists()
	if err != nil {
		return err
	}
	if !exists {
		ui.PrintInfo("No configuration found. Run 'kubectl-guard config setup' to configure.")
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ui.PrintInfo("Protected contexts:")
	if len(cfg.ProtectedContexts) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, ctx := range cfg.ProtectedContexts {
			fmt.Printf("  - %s\n", ctx)
		}
	}

	ui.PrintInfo("Protected resources (blocked everywhere):")
	if len(cfg.ProtectedResources) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, r := range cfg.ProtectedResources {
			fmt.Printf("  - %s\n", r)
		}
	}

	ui.PrintInfo("Confirm mode: " + cfg.ConfirmMode)

	auditPath, _ := config.AuditPath(cfg)
	ui.PrintInfo("Audit log: " + auditPath)

	return nil
}

func loadOrCreateConfig() (*config.Config, error) {
	exists, err := config.Exists()
	if err != nil {
		return nil, err
	}
	if exists {
		cfg, err := config.Load()
		if err != nil {
			return nil, err
		}
		cfg.ApplyDefaults()
		return cfg, nil
	}
	return &config.Config{ProtectedContexts: []string{}}, nil
}

func printHelp() {
	help := `kubectl-guard - Protect production clusters and sensitive resources from accidental commands

Usage:
  kubectl-guard [kubectl args...]     Run kubectl with protection
  kubectl-guard config <subcommand>   Manage configuration
  kubectl-guard --version             Print version
  kubectl-guard --help                Print this help

Protection model:
  - Protected CONTEXTS: state-altering commands require confirmation.
  - Protected RESOURCES: any command touching the resource is blocked
    everywhere (reads included), e.g. block all secret access.
  - The --context / --kubeconfig flags are honored, so you cannot bypass the
    guard by pointing at a protected context explicitly.

Config subcommands:
  setup                      Run the setup wizard
  list                       Show protected contexts, resources, and modes
  add-context <pattern>      Protect matching contexts (glob)
  remove-context <pattern>   Stop protecting matching contexts
  add-resource <name>        Block a resource everywhere (e.g. secret)
  remove-resource <name>     Stop blocking a resource
  confirm-mode [simple|type-name]
                             Show or set the confirmation prompt style
                             (type-name requires typing the context name)
  audit                      Show the audit log path and recent entries
  path                       Print the config file path

Examples:
  # Protect production contexts
  kubectl-guard config add-context 'prod-*'

  # Block all secret access on every cluster
  kubectl-guard config add-resource secret

  # Require typing the context name to confirm dangerous commands
  kubectl-guard config confirm-mode type-name

  # Forward kubectl normally (alias recommended)
  alias kubectl='kubectl-guard'
  kubectl delete pod nginx    # Prompts on protected contexts

Environment:
  Config file: ~/.kubectl-guard.yaml
  Audit log:   ~/.kubectl-guard-audit.log
`
	fmt.Print(strings.TrimSpace(help) + "\n")
}

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

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Check if we're being called with a subcommand (config, version, etc.)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "config":
			return runConfigCommand()
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

	case guard.RequireConfirmation:
		cmdDesc := guard.GetCommandDescription(args)
		message := fmt.Sprintf("%s on protected context: %s", cmdDesc, ctx)
		if ui.Confirm(message) {
			return guard.ExecKubectl(args)
		}
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
		Short: "List protected contexts",
		RunE: func(cmd *cobra.Command, args []string) error {
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

			if len(cfg.ProtectedContexts) == 0 {
				ui.PrintInfo("No protected contexts.")
				return nil
			}

			ui.PrintInfo("Protected contexts:")
			for _, ctx := range cfg.ProtectedContexts {
				fmt.Printf("  - %s\n", ctx)
			}
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "add <context>",
		Short: "Add a context to the protected list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}

			if cfg.AddContext(args[0]) {
				if err := config.Save(cfg); err != nil {
					return err
				}
				ui.PrintSuccess("Added: " + args[0])
			} else {
				ui.PrintInfo("Context already protected: " + args[0])
			}
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "remove <context>",
		Short: "Remove a context from the protected list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			exists, err := config.Exists()
			if err != nil {
				return err
			}
			if !exists {
				ui.PrintInfo("No configuration found.")
				return nil
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			if cfg.RemoveContext(args[0]) {
				if err := config.Save(cfg); err != nil {
					return err
				}
				ui.PrintSuccess("Removed: " + args[0])
			} else {
				ui.PrintInfo("Context not in protected list: " + args[0])
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

func loadOrCreateConfig() (*config.Config, error) {
	exists, err := config.Exists()
	if err != nil {
		return nil, err
	}
	if exists {
		return config.Load()
	}
	return &config.Config{ProtectedContexts: []string{}}, nil
}

func printHelp() {
	help := `kubectl-guard - Protect production clusters from accidental commands

Usage:
  kubectl-guard [kubectl args...]     Run kubectl with protection
  kubectl-guard config <subcommand>   Manage configuration
  kubectl-guard --version             Print version
  kubectl-guard --help                Print this help

Config subcommands:
  setup       Run the setup wizard
  list        List protected contexts
  add <ctx>   Add a context to the protected list
  remove <ctx> Remove a context from the protected list
  path        Print the config file path

Examples:
  # First run triggers setup wizard
  kubectl-guard get pods

  # Run kubectl commands normally (alias recommended)
  alias kubectl='kubectl-guard'
  kubectl delete pod nginx   # Prompts for confirmation on protected contexts

  # Manage configuration
  kubectl-guard config list
  kubectl-guard config add prod-*
  kubectl-guard config remove staging

Environment:
  Config file: ~/.kubectl-guard.yaml
`
	fmt.Print(strings.TrimSpace(help) + "\n")
}

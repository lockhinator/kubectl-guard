package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/lockhinator/kubectl-guard/config"
	"github.com/lockhinator/kubectl-guard/guard"
	"github.com/lockhinator/kubectl-guard/ui"
	"github.com/spf13/cobra"
)

// version is injected at build time by GoReleaser (-X main.version=X).
// Defaults to "dev" for local builds.
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
	"audit-mode":     true,
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
		case "--version", "-V":
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
	// --json is a guard-only flag: parse and strip it before anything reaches
	// kubectl or Check, so it is never forwarded to kubectl.
	forwarded, jsonMode := guard.StripGuardFlags(args)

	result, ctx, cfg, err := guard.Check(forwarded)
	cmdStr := strings.Join(forwarded, " ")

	// emitDecision writes the structured JSON decision object to stderr. Used
	// only in --json mode for non-Allow results; for Allow nothing is emitted so
	// kubectl's stdout stays clean for the agent.
	emitDecision := func() {
		jr := guard.JSONForResult(result, ctx, cmdStr, forwarded, err)
		b, mErr := json.Marshal(jr)
		if mErr != nil {
			return
		}
		fmt.Fprintln(os.Stderr, string(b))
	}

	switch result {
	case guard.Deny:
		if jsonMode {
			emitDecision()
		} else {
			msg := "the guard cannot verify this command is safe"
			if err != nil {
				msg = err.Error()
			}
			ui.PrintWarning("Refusing to run: " + msg)
			ui.PrintInfo("Fix the issue above, or run kubectl directly if you understand the risk.")
		}
		// cfg is non-nil when context resolution failed but config loaded; log it.
		if cfg != nil {
			_ = guard.AppendAudit(cfg, guard.AuditEntry{
				Context: ctx,
				Command: cmdStr,
				Outcome: guard.OutcomeDenied,
			})
		}
		os.Exit(guard.ExitDenied)

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
		if jsonMode {
			emitDecision()
		} else {
			cmdDesc := guard.GetCommandDescription(forwarded)
			ui.PrintWarning(fmt.Sprintf("Blocked: %s targets a protected resource (context: %s)", cmdDesc, ctx))
			if guard.HasUninspectableSource(forwarded) {
				ui.PrintInfo("Command reads from stdin/URL/kustomize, which cannot be inspected; blocked as a precaution.")
			}
		}
		_ = guard.AppendAudit(cfg, guard.AuditEntry{
			Context: ctx,
			Command: cmdStr,
			Outcome: guard.OutcomeBlocked,
			Reason:  "protected-resource",
		})
		os.Exit(guard.ExitBlocked)

	case guard.RequireConfirmation:
		if jsonMode {
			// An agent framework cannot answer an interactive prompt; abort
			// immediately with structured output instead of blocking on stdin.
			emitDecision()
			_ = guard.AppendAudit(cfg, guard.AuditEntry{
				Context: ctx,
				Command: cmdStr,
				Outcome: guard.OutcomeAborted,
			})
			os.Exit(guard.ExitNeedsConfirm)
		}

		cmdDesc := guard.GetCommandDescription(forwarded)
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
				Command: cmdStr,
				Outcome: guard.OutcomeConfirmed,
			})
			return guard.ExecKubectl(forwarded)
		}

		_ = guard.AppendAudit(cfg, guard.AuditEntry{
			Context: ctx,
			Command: cmdStr,
			Outcome: guard.OutcomeAborted,
		})
		fmt.Fprintln(os.Stderr, "Aborted.")
		os.Exit(guard.ExitNeedsConfirm)

	case guard.Allow:
		// Log BEFORE ExecKubectl: syscall.Exec replaces this process, so
		// anything after the call never runs.
		_ = guard.AppendAudit(cfg, guard.AuditEntry{
			Context: ctx,
			Command: cmdStr,
			Outcome: guard.OutcomeAllowed,
		})
		return guard.ExecKubectl(forwarded)
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

	// add-context / add (alias) / remove-context / remove (alias) /
	// add-resource / remove-resource all share one shape.
	addCmd := func(use, short string, fn func(*config.Config, string) bool, doneTmpl, noopTmpl string, hidden bool) {
		rootCmd.AddCommand(&cobra.Command{
			Use:   use,
			Short: short,
			Args:  cobra.ExactArgs(1),
			Hidden: hidden,
			RunE: func(_ *cobra.Command, a []string) error {
				return mutateConfig(func(c *config.Config) bool { return fn(c, a[0]) }, fmt.Sprintf(doneTmpl, a[0]), fmt.Sprintf(noopTmpl, a[0]))
			},
		})
	}
	addCmd("add-context <pattern>", "Add a context/pattern to the protected list", (*config.Config).AddContext, "Added context: %s", "Context already protected: %s", false)
	addCmd("add <pattern>", "Alias for add-context", (*config.Config).AddContext, "Added context: %s", "Context already protected: %s", true)
	addCmd("remove-context <pattern>", "Remove a context/pattern from the protected list", (*config.Config).RemoveContext, "Removed context: %s", "Context not in protected list: %s", false)
	addCmd("remove <pattern>", "Alias for remove-context", (*config.Config).RemoveContext, "Removed context: %s", "Context not in protected list: %s", true)
	addCmd("add-resource <name>", "Add a resource to block on every context (e.g. secret)", (*config.Config).AddResource, "Blocked resource: %s", "Resource already protected: %s", false)
	addCmd("remove-resource <name>", "Remove a resource from the blocked list", (*config.Config).RemoveResource, "Unblocked resource: %s", "Resource not in protected list: %s", false)

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
		Use:   "audit-mode [all|gated|off]",
		Short: "Show or set what the audit log records",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				ui.PrintInfo("Audit mode: " + cfg.AuditMode)
				return nil
			}
			if !cfg.SetAuditMode(args[0]) {
				return fmt.Errorf("invalid mode %q (want %q, %q, or %q)", args[0], config.AuditModeAll, config.AuditModeGated, config.AuditModeOff)
			}
			if err := config.Save(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Audit mode set: " + cfg.AuditMode)
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
func mutateConfig(fn func(*config.Config) bool, done, noop string) error {
	cfg, err := loadOrCreateConfig()
	if err != nil {
		return err
	}
	if fn(cfg) {
		if err := config.Save(cfg); err != nil {
			return err
		}
		ui.PrintSuccess(done)
	} else {
		ui.PrintInfo(noop)
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
	cfg := &config.Config{ProtectedContexts: []string{}}
	cfg.ApplyDefaults()
	return cfg, nil
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

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
	"init":            true,
	"list":            true,
	"add":             true,
	"remove":          true,
	"add-context":     true,
	"remove-context":  true,
	"add-resource":    true,
	"remove-resource": true,
	"add-namespace":   true,
	"remove-namespace": true,
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
	// KUBECTL_GUARD_BYPASS is a full, audited escape hatch: it disables the
	// guard for this invocation entirely (the command runs against the real
	// kubectl). It is discouraged — prefer --yes for gated commands — but
	// documented for cases where protection must be dropped wholesale (e.g. an
	// emergency deploy). It is logged as "bypassed" so the audit trail records
	// exactly what happened and who (actor) did it.
	if boolEnv(config.EnvBypass) {
		return runBypass(os.Args[1:])
	}

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
		case "doctor":
			return runDoctor()
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

// runDoctor reports whether PATH-shadowing interception is active and where
// the real kubectl lives. Output is human-readable and routed to stderr to
// keep stdout clean (consistent with the guard's other user-facing messages).
func runDoctor() error {
	r := guard.Doctor()

	ui.PrintInfo("guard binary:  " + orUnknown(r.GuardPath))

	ui.PrintInfo("kubectl on PATH (in order):")
	if len(r.KubectlOnPath) == 0 {
		fmt.Fprintln(os.Stderr, "  (none - kubectl is not on PATH)")
	} else {
		for _, p := range r.KubectlOnPath {
			fmt.Fprintf(os.Stderr, "  - %s\n", p)
		}
	}

	if r.Intercepted {
		ui.PrintSuccess("interception: ACTIVE - kubectl resolves to the guard")
	} else {
		ui.PrintWarning("interception: INACTIVE - kubectl does NOT resolve to the guard")
		ui.PrintInfo("Run 'make install-shim' and prepend the shim directory to PATH to intercept non-interactive/agent calls.")
	}

	if r.RealKubectlPath != "" {
		ui.PrintInfo("real kubectl:  " + r.RealKubectlPath)
	} else if r.Err != nil {
		ui.PrintWarning("could not resolve the real kubectl: " + r.Err.Error())
	}

	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

// runBypass executes the command against the real kubectl with the guard fully
// disabled, after writing a loud "bypassed" audit entry (best-effort). It is
// the KUBECTL_GUARD_BYPASS escape hatch.
func runBypass(args []string) error {
	ui.PrintWarning("KUBECTL_GUARD_BYPASS set: guard disabled for this invocation (audited).")
	// Best-effort audit: if a config exists, log the bypass so it's traceable.
	// Attribute impersonation/token like the main path so the bypass record
	// still shows who it ran as.
	if exists, err := config.Exists(); err == nil && exists {
		if cfg, err := config.Load(); err == nil {
			e := guard.AuditEntry{
				Command: strings.Join(args, " "),
				Outcome: guard.OutcomeBypassed,
				Reason:  "KUBECTL_GUARD_BYPASS",
			}
			p := guard.ParseArgs(args)
			if p.AsUser != "" {
				e.Impersonate = p.AsUser
			}
			if p.HasToken {
				e.Token = true
			}
			_ = guard.AppendAudit(cfg, e)
		}
	}
	return guard.ExecKubectl(args)
}

// boolEnv reports whether the env var is set to a truthy value (1, t, true,
// yes, y, case-insensitive). Empty/unset is false.
func boolEnv(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "t", "true", "yes", "y":
		return true
	}
	return false
}

func runGuard(args []string) error {
	// --json is a guard-only flag: parse and strip it before anything reaches
	// kubectl or Check, so it is never forwarded to kubectl.
	forwarded, jsonMode := guard.StripGuardFlags(args)
	// --no-prompt is also guard-only (headless bootstrap); strip it too.
	forwarded, noPrompt := guard.StripNoPrompt(forwarded)
	if !noPrompt {
		noPrompt = boolEnv(config.EnvNoPrompt)
	}
	// --yes is a guard-only audited auto-confirm of RequireConfirmation.
	forwarded, yesFlag := guard.StripYes(forwarded)

	result, ctx, cfg, err := guard.Check(forwarded)
	cmdStr := strings.Join(forwarded, " ")

	// Parse once to attribute impersonation (--as) and credential overrides
	// (--token) in the audit log, so the record shows who a command ran AS,
	// not just who invoked the guard.
	parsed := guard.ParseArgs(forwarded)

	// audit writes an attributed audit entry for this invocation. It is a
	// thin wrapper so every decision path records impersonation/token the same
	// way. cfg may be nil (Deny before config load); in that case it is a no-op.
	audit := func(outcome, reason string) {
		if cfg == nil {
			return
		}
		e := guard.AuditEntry{
			Context: ctx,
			Command: cmdStr,
			Outcome: outcome,
			Reason:  reason,
		}
		if parsed.AsUser != "" {
			e.Impersonate = parsed.AsUser
		}
		if parsed.HasToken {
			e.Token = true
		}
		_ = guard.AppendAudit(cfg, e)
	}

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
		audit(guard.OutcomeDenied, "")
		os.Exit(guard.ExitDenied)

	case guard.SetupRequired:
		// Headless / non-interactive bootstrap: prefer env-var config, then
		// --no-prompt, before falling back to the interactive wizard. This lets
		// agents and CI configure the guard without a TTY.
		if envCfg, ok := config.InitFromEnv(); ok {
			if err := config.Save(envCfg); err != nil {
				ui.PrintWarning("Failed to save config from environment: " + err.Error())
				return nil
			}
			if p, perr := config.Path(); perr == nil {
				ui.PrintInfo("Wrote initial config from KUBECTL_GUARD_* env vars: " + p)
			}
			// Proceed to run the command against the freshly written config.
			return runGuard(args)
		}
		if noPrompt {
			empty := &config.Config{}
			empty.ApplyDefaults()
			if err := config.Save(empty); err != nil {
				ui.PrintWarning("Failed to save config: " + err.Error())
				return nil
			}
			ui.PrintWarning("--no-prompt set with no env config: wrote an empty config (no protection) and proceeding.")
			return runGuard(args)
		}
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
		audit(guard.OutcomeBlocked, "protected-resource")
		os.Exit(guard.ExitBlocked)

	case guard.RequireConfirmation:
		// Audited escape hatch: --yes / KUBECTL_GUARD_CONFIRM=yes auto-confirms
		// RequireConfirmation (state-altering on a protected context) as if the
		// user typed yes, but logs it as a distinct "auto-confirmed" outcome so
		// the audit trail records the bypass. Protected-resource Blocks are NOT
		// affected by this (they stay a hard block in their own branch).
		autoConfirm := yesFlag || boolEnv(config.EnvConfirm)
		if autoConfirm {
			if !jsonMode {
				ui.PrintWarning("Auto-confirming gated command (--yes / KUBECTL_GUARD_CONFIRM=yes); logged as auto-confirmed.")
			}
			audit(guard.OutcomeAutoConfirmed, "yes-flag")
			return guard.ExecKubectl(forwarded)
		}

		if jsonMode {
			// An agent framework cannot answer an interactive prompt; abort
			// immediately with structured output instead of blocking on stdin.
			emitDecision()
			audit(guard.OutcomeAborted, "")
			os.Exit(guard.ExitNeedsConfirm)
		}

		cmdDesc := guard.GetCommandDescription(forwarded)
		// Describe what is protected so the user knows why they're confirming.
		// Namespace protection (#19) may trigger gating even on an unprotected
		// context, so the message reflects whichever applies.
		reason := "protected context"
		target := ctx
		if parsed.AllNamespaces {
			reason = "protected namespace"
			target = "all namespaces"
		} else if parsed.HasNamespace && parsed.Namespace != "" {
			reason = "protected namespace"
			target = parsed.Namespace
		}
		message := fmt.Sprintf("%s on %s: %s", cmdDesc, reason, target)

		confirmed := false
		if cfg != nil && cfg.ConfirmMode == config.ConfirmModeTypeName {
			confirmed = ui.ConfirmWithName(message, target)
		} else {
			confirmed = ui.Confirm(message)
		}

		if confirmed {
			audit(guard.OutcomeConfirmed, "")
			return guard.ExecKubectl(forwarded)
		}

		audit(guard.OutcomeAborted, "")
		fmt.Fprintln(os.Stderr, "Aborted.")
		os.Exit(guard.ExitNeedsConfirm)

	case guard.Allow:
		// Log BEFORE ExecKubectl: syscall.Exec replaces this process, so
		// anything after the call never runs.
		audit(guard.OutcomeAllowed, "")
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

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write a config non-interactively (headless / CI / agents)",
		RunE: func(cmd *cobra.Command, args []string) error {
			contexts, _ := cmd.Flags().GetString("protected-contexts")
			resources, _ := cmd.Flags().GetString("protected-resources")
			confirm, _ := cmd.Flags().GetString("confirm-mode")
			cfg := config.InitFromFlags(contexts, resources, confirm)
			if err := config.Save(cfg); err != nil {
				return err
			}
			path, err := config.Path()
			if err != nil {
				return err
			}
			ui.PrintSuccess("Wrote config: " + path)
			if len(cfg.ProtectedContexts) > 0 {
				ui.PrintInfo("Protected contexts: " + strings.Join(cfg.ProtectedContexts, ", "))
			}
			if len(cfg.ProtectedResources) > 0 {
				ui.PrintInfo("Protected resources: " + strings.Join(cfg.ProtectedResources, ", "))
			}
			if len(cfg.ProtectedNamespaces) > 0 {
				ui.PrintInfo("Protected namespaces: " + strings.Join(cfg.ProtectedNamespaces, ", "))
			}
			ui.PrintInfo("Confirm mode: " + cfg.ConfirmMode)
			return nil
		},
	}
	initCmd.Flags().String("protected-contexts", "", "comma-separated context patterns to protect (e.g. 'prod-*,prod-cluster')")
	initCmd.Flags().String("protected-resources", "", "comma-separated resources to block on every context (e.g. 'secret')")
	initCmd.Flags().String("confirm-mode", "", "confirmation mode for protected contexts (simple|type-name)")
	rootCmd.AddCommand(initCmd)


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
	addCmd("add-namespace <pattern>", "Add a namespace/pattern to the protected list (e.g. kube-system, prod-*)", (*config.Config).AddNamespace, "Protected namespace: %s", "Namespace already protected: %s", false)
	addCmd("remove-namespace <pattern>", "Remove a namespace/pattern from the protected list", (*config.Config).RemoveNamespace, "Removed namespace: %s", "Namespace not in protected list: %s", false)

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

	ui.PrintInfo("Protected namespaces:")
	if len(cfg.ProtectedNamespaces) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, ns := range cfg.ProtectedNamespaces {
			fmt.Printf("  - %s\n", ns)
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

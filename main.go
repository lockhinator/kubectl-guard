package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

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
	"setup":                 true,
	"init":                  true,
	"list":                  true,
	"add":                   true,
	"remove":                true,
	"add-context":           true,
	"remove-context":        true,
	"add-cluster":           true,
	"remove-cluster":        true,
	"add-resource":          true,
	"remove-resource":       true,
	"add-namespace":         true,
	"remove-namespace":      true,
	"confirm-mode":          true,
	"context-mode":          true,
	"namespace-mode":        true,
	"blast-radius":          true,
	"sensitive-kind":        true,
	"add-sensitive-kind":    true,
	"remove-sensitive-kind": true,
	"actor-policy":          true,
	"audit-mode":            true,
	"audit-rotation":        true,
	"audit-webhook":         true,
	"audit-syslog":          true,
	"command-override":      true,
	"unknown-verb":          true,
	"confirm-weakening":     true,
	"require-justification": true,
	"audit":                 true,
	"path":                  true,
	"validate":              true,
}

func main() {
	if err := run(); err != nil {
		reportError(err)
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
			return runDoctor(os.Args[2:])
		case "uninstall":
			return runUninstall(os.Args[2:])
		case "freeze":
			return runFreeze(true)
		case "unfreeze":
			return runFreeze(false)
		case "explain":
			return runExplain(os.Args[2:])
		case "completion", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
			// `completion <shell>` generates the guard's own completion script;
			// `__complete`/`__completeNoDesc` are cobra's hidden runtime requests the
			// sourced script issues. Only handle these when invoked by our own name.
			// When invoked as the `kubectl` shim, these belong to KUBECTL's native
			// (also cobra-based) completion — hijacking `kubectl __complete ...` would
			// break the user's real kubectl tab-completion — so fall through to the
			// normal guard path exactly as before this feature existed.
			if invokedAsGuard() {
				return runRootCompletion()
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

// runDoctor reports whether PATH-shadowing interception is active and where
// the real kubectl lives. Output is human-readable and routed to stderr to
// keep stdout clean (consistent with the guard's other user-facing messages).
// doctorCheck is one health check in the doctor report.
type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail
	Detail string `json:"detail,omitempty"`
}

// doctorReport is the full doctor result: the checks, the effective protection
// posture, and whether every check passed (no fail).
type doctorReport struct {
	Checks  []doctorCheck     `json:"checks"`
	Posture map[string]string `json:"posture"`
	Healthy bool              `json:"healthy"`
}

// runDoctor answers "is the guard actually protecting me?" It runs a battery of
// checks (kubectl reachable, interception, config valid + permissions, audit log
// writable, current context resolvable), reports the effective posture, and exits
// 0 only if no check FAILED. --json emits the structured report.
func runDoctor(args []string) error {
	// --require-interception promotes an inactive PATH-shadow from a warning to a
	// hard failure, so CI/monitoring can gate on it. Off by default because an
	// alias install is legitimate and invisible to the process (a shell alias is
	// not a PATH entry) — but an environment with neither a shim NOR an alias
	// leaves the guard out of an agent's call path, so a strict deployment wants
	// this to fail closed.
	requireInterception := hasFlag(args, "--require-interception")
	report := buildDoctorReport(requireInterception)

	if jsonRequested(args) {
		b, err := json.Marshal(report)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		if !report.Healthy {
			os.Exit(1)
		}
		return nil
	}

	for _, c := range report.Checks {
		line := c.Name
		if c.Detail != "" {
			line += ": " + c.Detail
		}
		switch c.Status {
		case "ok":
			ui.PrintSuccess(line)
		case "warn":
			ui.PrintWarning(line)
		default:
			fmt.Fprintln(os.Stderr, "✗ "+line)
		}
	}
	if len(report.Posture) > 0 {
		ui.PrintInfo("")
		ui.PrintInfo("Effective posture:")
		for _, k := range doctorPostureKeys {
			if v, ok := report.Posture[k]; ok {
				fmt.Fprintf(os.Stderr, "  %-20s %s\n", k+":", v)
			}
		}
	}
	if !report.Healthy {
		ui.PrintWarning("doctor found one or more failed checks.")
		os.Exit(1)
	}
	return nil
}

// doctorPostureKeys fixes the display order of the posture map.
var doctorPostureKeys = []string{
	"protected_contexts", "protected_namespaces", "protected_resources",
	"sensitive_kinds", "context_mode", "namespace_mode", "confirm_mode",
	"blast_radius", "sensitive_access", "unknown_verb", "audit_mode", "read_only",
}

// buildDoctorReport runs every doctor check and assembles the posture. When
// requireInterception is set, an inactive PATH-shadow is a FAIL (not a warn).
func buildDoctorReport(requireInterception bool) doctorReport {
	var checks []doctorCheck
	add := func(name, status, detail string) {
		checks = append(checks, doctorCheck{Name: name, Status: status, Detail: detail})
	}

	// kubectl reachability + PATH-shadowing interception.
	d := guard.Doctor()
	if d.RealKubectlPath != "" {
		add("kubectl reachable", "ok", d.RealKubectlPath)
	} else {
		add("kubectl reachable", "fail", "kubectl not found on PATH — install it or fix PATH")
	}
	if d.Intercepted {
		add("interception active", "ok", "kubectl resolves to the guard (PATH-shadowing)")
	} else {
		status := "warn"
		if requireInterception {
			status = "fail"
		}
		add("interception active", status, "kubectl does not resolve to the guard; only an alias/shim protects use — run 'make install-shim' to protect non-interactive/agent calls")
	}

	// Config: exists, loads, valid.
	var cfg *config.Config
	exists, existsErr := config.Exists()
	switch {
	case existsErr != nil:
		add("config readable", "fail", "cannot stat config: "+existsErr.Error())
	case !exists:
		add("config readable", "warn", "no config file — the guard is unconfigured (run 'kubectl-guard config init')")
	default:
		c, err := config.Load()
		if err != nil {
			add("config valid", "fail", err.Error())
		} else {
			c.ApplyDefaults()
			if problems := c.Validate(); len(problems) > 0 {
				add("config valid", "fail", "invalid: "+strings.Join(problems, "; "))
			} else {
				cfg = c
				add("config valid", "ok", "loaded and valid")
			}
		}
	}

	// Config permissions (tamper signal, #34).
	if insecure, detail, err := config.InsecureConfigPerms(); err == nil && insecure {
		status := "warn"
		if cfg != nil && cfg.StrictPerms() {
			status = "fail"
		}
		add("config permissions", status, detail)
	} else if exists {
		add("config permissions", "ok", "not group/world-writable")
	}

	// Audit log writability.
	if auditPath, err := config.AuditPath(cfg); err != nil {
		add("audit log writable", "fail", err.Error())
	} else if werr := auditWritable(auditPath); werr != nil {
		add("audit log writable", "fail", auditPath+": "+werr.Error())
	} else {
		add("audit log writable", "ok", auditPath)
	}

	// Current context resolvable (fail closed if protected contexts are set).
	ctx, ctxErr := guard.GetCurrentContext()
	switch {
	case ctxErr == nil && ctx != "":
		add("current context resolvable", "ok", ctx)
	case cfg != nil && len(cfg.ProtectedContexts) > 0:
		add("current context resolvable", "fail", "cannot resolve the current context; with protected contexts configured, every command fails closed until this is fixed")
	default:
		add("current context resolvable", "warn", "no current context resolved (no protected contexts, so reads still pass)")
	}

	healthy := true
	for _, c := range checks {
		if c.Status == "fail" {
			healthy = false
		}
	}
	return doctorReport{Checks: checks, Posture: doctorPosture(cfg), Healthy: healthy}
}

// doctorPosture summarizes the effective protection posture for the report.
func doctorPosture(cfg *config.Config) map[string]string {
	if cfg == nil {
		return nil
	}
	p := map[string]string{}
	if len(cfg.ProtectedContexts) > 0 {
		var parts []string
		for _, pp := range cfg.ProtectedContexts {
			parts = append(parts, formatPattern(pp))
		}
		p["protected_contexts"] = strings.Join(parts, ", ")
	}
	if len(cfg.ProtectedNamespaces) > 0 {
		var parts []string
		for _, pp := range cfg.ProtectedNamespaces {
			parts = append(parts, formatPattern(pp))
		}
		p["protected_namespaces"] = strings.Join(parts, ", ")
	}
	if len(cfg.ProtectedClusters) > 0 {
		var parts []string
		for _, pc := range cfg.ProtectedClusters {
			parts = append(parts, formatClusterKey(pc))
		}
		p["protected_clusters"] = strings.Join(parts, ", ")
	}
	if len(cfg.ProtectedResources) > 0 {
		p["protected_resources"] = strings.Join(cfg.ProtectedResources, ", ")
	}
	if cfg.HasSensitiveKinds() {
		p["sensitive_kinds"] = strings.Join(cfg.SensitiveKinds, ", ") + " (" + cfg.SensitiveKindMode() + ")"
	}
	p["context_mode"] = orDefault(cfg.ContextMode, config.ContextModeConfirm)
	p["namespace_mode"] = orDefault(cfg.NamespaceMode, config.NamespaceModeConfirm)
	p["confirm_mode"] = orDefault(cfg.ConfirmMode, config.ConfirmModeSimple)
	p["blast_radius"] = cfg.BlastRadiusMode()
	p["sensitive_access"] = cfg.SensitiveAccessMode()
	p["unknown_verb"] = cfg.UnknownVerbMode()
	p["audit_mode"] = orDefault(cfg.AuditMode, config.AuditModeAll)
	if cfg.ReadOnly {
		p["read_only"] = "ON (freeze)"
	}
	return p
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// auditWritable reports whether the audit log path can be written without
// actually creating the log: it probes an existing file with an append open, or
// the parent directory with a temp file it removes.
func auditWritable(path string) error {
	if _, err := os.Stat(path); err == nil {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		return f.Close()
	}
	// Probe the parent dir with a UNIQUE temp file (os.CreateTemp uses O_EXCL and
	// won't follow a pre-planted symlink to create a file at an attacker-chosen
	// path, and its unique name avoids a fixed-name collision between concurrent
	// doctor runs).
	f, err := os.CreateTemp(filepath.Dir(path), ".kubectl-guard-doctor-probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// runExplain answers "would this command be gated, and why?" by running the
// guard's real decision logic (guard.Check) without exec'ing kubectl, prompting,
// or auditing — a policy preflight for agents and humans. Output goes to stdout;
// --json emits the runtime JSONResult shape so agents parse one schema.
//
//	kubectl-guard explain [--json] -- <kubectl args...>
func runExplain(args []string) error {
	forwarded, jsonMode := guard.StripGuardFlags(args)
	// Strip a single leading "--" separating explain's flags from the command.
	if len(forwarded) > 0 && forwarded[0] == "--" {
		forwarded = forwarded[1:]
	}
	if len(forwarded) == 0 {
		return fmt.Errorf("usage: kubectl-guard explain [--json] -- <kubectl args...>")
	}

	res := guard.Explain(forwarded)
	cmdStr := strings.Join(guard.RedactArgs(forwarded), " ")

	if jsonMode {
		b, err := json.Marshal(res.JSONResult(cmdStr))
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("decision:  %s\n", res.Decision)
	fmt.Printf("reason:    %s\n", res.Reason)
	fmt.Printf("verb:      %s (%s)\n", nonEmpty(res.Verb, "(none)"), res.Class)
	if res.Context != "" {
		fmt.Printf("context:   %s\n", res.Context)
	}
	if res.Namespace != "" {
		fmt.Printf("namespace: %s\n", res.Namespace)
	}
	if res.Resource != "" {
		fmt.Printf("resource:  %s\n", res.Resource)
	}
	return nil
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// runAuditVerify checks the tamper-evident audit chain and reports whether it is
// intact or names the first broken line. Exits non-zero on a broken chain so CI /
// monitoring can gate on it.
func runAuditVerify(cfg *config.Config, path string) error {
	// The HMAC key file is the root of trust for tamper-evidence: if any other
	// user can read it they can forge valid entries. Warn on loose permissions.
	if cfg != nil && cfg.AuditHMACKeyFile != "" {
		if info, err := os.Stat(cfg.AuditHMACKeyFile); err == nil && info.Mode().Perm()&0o077 != 0 {
			ui.PrintWarning(fmt.Sprintf("HMAC key file %s is group/world-accessible (mode %#o); the tamper-evidence guarantee depends on it being secret — chmod 600 it.", cfg.AuditHMACKeyFile, uint32(info.Mode().Perm())))
		}
	}
	res, err := guard.VerifyAuditLog(path, guard.AuditKey(cfg))
	if err != nil {
		if os.IsNotExist(err) {
			ui.PrintInfo("No audit log to verify.")
			return nil
		}
		return err
	}
	ui.PrintInfo("Audit log: " + path)
	ui.PrintInfo(fmt.Sprintf("Entries: %d (%d chained, %d legacy/unchained)", res.Total, res.Chained, res.Legacy))
	if !res.Intact {
		ui.PrintWarning(fmt.Sprintf("Audit chain BROKEN at line %d: %s", res.BreakLine, res.BreakReason))
		os.Exit(1)
	}
	if res.Chained == 0 {
		if res.Legacy > 0 {
			// Every append since v1.0 writes a hash, so a log with only unchained
			// lines is either genuinely pre-v1.0 OR had every hash stripped to erase
			// history — indistinguishable from the file alone. Fail closed: integrity
			// cannot be confirmed. (Tail truncation of a chained log is separately
			// undetectable without an off-box tip anchor — see the shipping sinks.)
			ui.PrintWarning("Log has only UNCHAINED entries and no tamper-evident ones: either it predates v1.0 or every hash was stripped to erase history — integrity CANNOT be confirmed. Run any kubectl-guard command to start the chain, then re-verify.")
			os.Exit(1)
		}
		ui.PrintInfo("Audit log is empty; nothing to verify.")
		return nil
	}
	ui.PrintSuccess("Audit chain is INTACT.")
	return nil
}

// runFreeze toggles global read-only / freeze mode (the incident panic button).
// Enabling it strengthens protection; disabling it (unfreeze) weakens protection,
// so the change routes through saveConfig — audited, and gated by
// require_confirm_weakening on unfreeze.
func runFreeze(on bool) error {
	cfg, err := loadOrCreateConfig()
	if err != nil {
		return err
	}
	cfg.ReadOnly = on
	if err := saveConfig(cfg); err != nil {
		return err
	}
	if on {
		ui.PrintSuccess("Read-only mode ENABLED (freeze): everything except known-safe reads is now blocked, everywhere (including unclassified plugin verbs). Reads still pass. Run 'kubectl-guard unfreeze' to lift.")
	} else {
		ui.PrintSuccess("Read-only mode DISABLED (unfreeze): state-altering commands are gated normally again.")
	}
	return nil
}

// runUninstall reverses the PATH-shadowing install: it removes the `kubectl`
// shim symlink and the `kubectl-guard` binary copy from the shim directory,
// prints the exact PATH line to strip from the user's shell rc (pointing at the
// rc file that contains it, read-only), and verifies interception is now
// inactive by reusing the doctor's PATH inspection. It is idempotent — a missing
// shim is reported, not an error. --purge additionally removes the config file
// and audit log after a confirmation (skipped with --yes). --shim-dir overrides
// the default shim location for non-standard installs.
func runUninstall(args []string) error {
	purge := hasFlag(args, "--purge")
	assumeYes := hasFlag(args, "--yes") || hasFlag(args, "-y")

	defaultShimDir, err := guard.DefaultShimDir()
	if err != nil {
		return fmt.Errorf("cannot determine the shim directory: %w", err)
	}
	shimDir, custom, err := flagValue(args, "--shim-dir")
	if err != nil {
		return err
	}
	if !custom {
		shimDir = defaultShimDir
	}
	// trusted marks the dir as unambiguously the guard's own shim location (the
	// default), which lets removeShim delete a kubectl-guard binary COPY there. A
	// custom --shim-dir is not trusted, so the binary is only removed when a
	// kubectl shim symlink is found beside it — a mistargeted path at a real bin
	// dir cannot silently delete the primary kubectl-guard binary. Compare cleaned
	// paths so a non-canonical default (trailing slash, /./) still reads as trusted.
	trusted := filepath.Clean(shimDir) == filepath.Clean(defaultShimDir)

	res, err := removeShim(shimDir, trusted)
	if err != nil {
		return err
	}
	if res.removedKubectl || res.removedGuard {
		ui.PrintSuccess("Removed the kubectl-guard shim from " + shimDir)
	} else {
		ui.PrintInfo("No kubectl-guard shim found in " + shimDir + " (nothing to remove).")
	}
	if res.skippedKubectl != "" {
		ui.PrintWarning(res.skippedKubectl)
	}
	if res.skippedGuard != "" {
		ui.PrintWarning(res.skippedGuard)
	}

	// The installer prepends the shim dir to PATH; tell the user the exact line
	// to remove and — read-only — point at the rc file(s) that reference it.
	pathLine := fmt.Sprintf("export PATH=%q", shimDir+":$PATH")
	ui.PrintInfo("")
	ui.PrintInfo("Remove this line from your shell config (~/.zshrc, ~/.bashrc) if present, then reload your shell:")
	fmt.Fprintln(os.Stderr, "  "+pathLine)
	if hits := shellConfigsContaining(shimDir); len(hits) > 0 {
		ui.PrintInfo("The shim directory is referenced in:")
		for _, h := range hits {
			fmt.Fprintln(os.Stderr, "  "+h)
		}
	}

	if purge {
		if err := purgeGuardFiles(assumeYes); err != nil {
			return err
		}
	}

	// Verify interception is now inactive. PATH is unchanged in this process, but
	// the shim files are gone, so the first kubectl on PATH now resolves to the
	// real binary (or none). A still-active result means another shim precedes it
	// on PATH or the current shell has not been reloaded.
	d := guard.Doctor()
	ui.PrintInfo("")
	switch {
	case d.Intercepted:
		ui.PrintWarning("Interception still ACTIVE — another kubectl shim is earlier on PATH, or this shell has not reloaded its PATH. Run 'kubectl-guard doctor' after reloading your shell.")
	case d.RealKubectlPath != "" && looksLikeGuardShim(d.RealKubectlPath):
		// Doctor only recognizes THIS binary's inode as "the guard"; a SEPARATE
		// kubectl-guard install earlier on PATH would otherwise be mislabeled as
		// the real kubectl. Catch that so we don't falsely claim protection is off.
		ui.PrintWarning("This shim is removed, but another kubectl-guard shim is still earlier on PATH (" + d.RealKubectlPath + "). Interception is STILL ACTIVE via that install — remove it too, then run 'kubectl-guard doctor' to confirm.")
	default:
		suffix := "."
		if d.RealKubectlPath != "" {
			suffix = " (" + d.RealKubectlPath + ")."
		}
		ui.PrintSuccess("Interception is now INACTIVE; kubectl resolves to the real binary" + suffix)
	}
	return nil
}

// looksLikeGuardShim reports whether the kubectl at path is itself a
// kubectl-guard shim (a symlink whose resolved target is a kubectl-guard
// binary). It catches a SECOND guard install left earlier on PATH, which
// guard.Doctor — comparing only against the running binary's inode — would
// otherwise mistake for the real kubectl.
func looksLikeGuardShim(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	return strings.Contains(filepath.Base(resolved), "kubectl-guard")
}

// shimRemoval records what removeShim actually deleted, so runUninstall can
// report accurately and stay idempotent.
type shimRemoval struct {
	removedKubectl bool
	removedGuard   bool
	removedDir     bool
	skippedKubectl string // non-empty when a kubectl was intentionally left in place
	skippedGuard   string // non-empty when a kubectl-guard binary was intentionally left in place
}

// removeShim deletes the guard's PATH-shadowing shim from dir: the `kubectl`
// symlink (ONLY when it is a symlink — a real kubectl regular file is never
// deleted, so a mistargeted --shim-dir cannot wipe the user's kubectl) and the
// `kubectl-guard` binary, then the dir itself if it is left empty (via
// os.Remove, which refuses a non-empty directory — the shim is never removed
// recursively). Missing files are not an error.
//
// The kubectl-guard binary is removed only when the dir is trusted (the default
// shim dir), the binary is a symlink, or a kubectl shim symlink was just removed
// beside it. This mirrors the kubectl guarantee: a mistargeted custom --shim-dir
// at a real bin dir (e.g. /usr/local/bin, $HOME/go/bin) will NOT silently delete
// the primary kubectl-guard binary that lives there.
func removeShim(dir string, trusted bool) (shimRemoval, error) {
	var res shimRemoval

	kubectlPath := filepath.Join(dir, "kubectl")
	if info, err := os.Lstat(kubectlPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(kubectlPath); err != nil {
				return res, fmt.Errorf("removing shim symlink %s: %w", kubectlPath, err)
			}
			res.removedKubectl = true
		} else {
			res.skippedKubectl = fmt.Sprintf("%s is a regular file, not the guard's symlink — left untouched (delete it yourself if it is a stale shim).", kubectlPath)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return res, fmt.Errorf("inspecting %s: %w", kubectlPath, err)
	}

	guardPath := filepath.Join(dir, "kubectl-guard")
	if info, err := os.Lstat(guardPath); err == nil {
		isSymlink := info.Mode()&os.ModeSymlink != 0
		if trusted || isSymlink || res.removedKubectl {
			if err := os.Remove(guardPath); err != nil {
				return res, fmt.Errorf("removing shim binary %s: %w", guardPath, err)
			}
			res.removedGuard = true
		} else {
			res.skippedGuard = fmt.Sprintf("%s left untouched: --shim-dir is not the default shim dir and no kubectl shim was found beside it, so this may be a real kubectl-guard binary (delete it yourself if it is a stale shim).", guardPath)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return res, fmt.Errorf("inspecting %s: %w", guardPath, err)
	}

	if res.removedKubectl || res.removedGuard {
		if err := os.Remove(dir); err == nil {
			res.removedDir = true
		}
	}
	return res, nil
}

// purgeGuardFiles removes the config file, the audit log, its rotated archives
// (<log>.N) and lock file after a confirmation (skipped when assumeYes). Missing
// files are not an error. Powers `uninstall --purge`. Before deleting, it writes
// a final audit record so a configured off-box sink (audit webhook) still
// captures that the trail was destroyed.
func purgeGuardFiles(assumeYes bool) error {
	cfgPath, err := config.Path()
	if err != nil {
		return err
	}
	var cfg *config.Config
	if exists, _ := config.Exists(); exists {
		cfg, _ = config.Load()
	}
	auditPath, _ := config.AuditPath(cfg)

	// auditFiles enumerates the audit log plus its rotated archives and lock file,
	// so --purge does not claim to have wiped the trail while leaving <log>.1..N
	// (or a stale <log>.lock) behind.
	auditFiles := func() []string {
		if auditPath == "" {
			return nil
		}
		out := []string{auditPath, auditPath + ".lock"}
		return append(out, auditArchives(auditPath)...)
	}

	// Existing files, for the confirmation preview.
	var existing []string
	for _, p := range append([]string{cfgPath}, auditFiles()...) {
		if _, err := os.Lstat(p); err == nil {
			existing = append(existing, p)
		}
	}
	if len(existing) == 0 {
		ui.PrintInfo("--purge: no config or audit files to remove.")
		return nil
	}

	ui.PrintWarning("--purge will permanently delete:")
	for _, p := range existing {
		fmt.Fprintln(os.Stderr, "  - "+p)
	}
	if !assumeYes {
		if ui.Confirm("Delete these files?", 0) != ui.ConfirmApproved {
			ui.PrintInfo("Purge aborted; config and audit files left in place.")
			return nil
		}
	}

	// Record the purge in the audit chain BEFORE deleting it. If auditing is off
	// this is a no-op (no local write, no recreation); if a webhook sink is
	// configured, the destruction is captured off-box. Deletion below re-globs the
	// audit files so an entry that (re)created or rotated the log is still removed.
	if cfg != nil {
		_ = guard.AppendAudit(cfg, guard.AuditEntry{
			Command: "uninstall --purge",
			Outcome: guard.OutcomeConfigChange,
			Reason:  "removing config and audit log (uninstall --purge)",
		})
	}

	for _, p := range append([]string{cfgPath}, auditFiles()...) {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("removing %s: %w", p, err)
		}
	}
	ui.PrintSuccess("Removed the files listed above.")
	return nil
}

// auditArchives returns the rotated audit archives (<path>.N, numeric suffix)
// for the audit log at path, mirroring the guard's own rotation naming so
// --purge removes the whole chain, not just the live log. The <path>.lock file
// (non-numeric suffix) is intentionally not matched here — it is handled
// separately.
func auditArchives(path string) []string {
	matches, _ := filepath.Glob(path + ".*")
	var out []string
	for _, m := range matches {
		suffix := strings.TrimPrefix(m, path+".")
		if _, err := strconv.Atoi(suffix); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// shellConfigsContaining returns the shell rc files under $HOME that reference
// needle (the shim directory), so uninstall can point the user at the exact file
// whose PATH line to strip. It is strictly read-only — it never edits them.
func shellConfigsContaining(needle string) []string {
	home, err := os.UserHomeDir()
	if err != nil || needle == "" {
		return nil
	}
	var hits []string
	for _, name := range []string{".zshrc", ".bashrc", ".bash_profile", ".profile"} {
		data, err := os.ReadFile(filepath.Join(home, name))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), needle) {
			hits = append(hits, filepath.Join(home, name))
		}
	}
	return hits
}

// flagValue returns the value of a `--name value` or `--name=value` flag in
// args, stopping at the "--" separator. found reports whether the flag was
// present at all; err is non-nil when the flag was given without a usable value
// (trailing, empty, or immediately followed by another flag) so a forgotten
// value errors loudly instead of silently falling back to a default or eating
// the next flag as a path.
func flagValue(args []string, name string) (value string, found bool, err error) {
	for i, a := range args {
		if a == "--" {
			return "", false, nil
		}
		if a == name {
			if i+1 >= len(args) {
				return "", true, fmt.Errorf("%s requires a directory argument", name)
			}
			v := args[i+1]
			if v == "--" || strings.HasPrefix(v, "-") {
				return "", true, fmt.Errorf("%s requires a directory argument (got %q)", name, v)
			}
			return v, true, nil
		}
		if strings.HasPrefix(a, name+"=") {
			v := strings.TrimPrefix(a, name+"=")
			if v == "" {
				return "", true, fmt.Errorf("%s requires a non-empty directory argument", name)
			}
			return v, true, nil
		}
	}
	return "", false, nil
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
				Command: guard.RedactCommand(args),
				Outcome: guard.OutcomeBypassed,
				Reason:  "KUBECTL_GUARD_BYPASS",
			}
			p := guard.ParseArgs(args)
			if imp := p.ImpersonationString(); imp != "" {
				e.Impersonate = imp
			}
			if p.HasToken {
				e.Token = true
			}
			_ = guard.AppendAudit(cfg, e)
		}
	}
	return execKubectl(args)
}

// execKubectl hands off to the real kubectl and only returns if the process
// replacement never happened. The one failure worth translating is "kubectl is
// not on PATH": ExecKubectl surfaces a raw Go lookup error (exec.ErrNotFound
// from RealKubectlPath, or ENOENT if the binary vanished between resolution and
// syscall.Exec), which is opaque noise for a tool whose whole job is wrapping
// kubectl. Turn it into an actionable message and exit non-zero; any other exec
// error propagates unchanged to the top-level handler.
func execKubectl(args []string) error {
	err := guard.ExecKubectl(args)
	if err != nil && (errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)) {
		ui.PrintWarning("kubectl not found on PATH. Install kubectl (https://kubernetes.io/docs/tasks/tools/) or fix your PATH.")
		os.Exit(1)
	}
	return err
}

// reportError is the single sink for errors that reach the top level. It writes
// to stderr in one consistent shape — "kubectl-guard: error: <msg>" for humans,
// or a structured {"error": "..."} object when --json was requested — instead of
// cobra's usage dump, a raw Go error, or the old bare "Error: ..." prefix. It
// never prints usage; flag-parse errors surface usage via the cobra
// FlagErrorFunc (guardFlagErrorFunc) before the error reaches here.
func reportError(err error) {
	if err == nil {
		return
	}
	msg := strings.TrimSpace(err.Error())
	if jsonRequested(os.Args[1:]) {
		if b, mErr := json.Marshal(map[string]string{"error": msg}); mErr == nil {
			fmt.Fprintln(os.Stderr, string(b))
			return
		}
	}
	fmt.Fprintln(os.Stderr, "kubectl-guard: error: "+msg)
}

// jsonRequested reports whether JSON mode was requested at the top level. It
// delegates to guard.StripGuardFlags so it honors every accepted form
// (--json, --json=true, --json=false) and the "--" separator EXACTLY as the
// decision path does — a hand-rolled scan drifted from it (missed --json=true).
func jsonRequested(args []string) bool {
	_, jsonMode := guard.StripGuardFlags(args)
	return jsonMode
}

// hasFlag reports whether flag appears in args before the "--" separator.
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == flag {
			return true
		}
	}
	return false
}

// guardFlagErrorFunc prints usage for a flag-parse error (the one error class
// where usage is genuinely helpful) and returns the error so reportError still
// emits the consistent message. RunE errors get no usage dump. In --json mode the
// human usage text is suppressed so it cannot pollute the structured error line
// an agent parses from stderr.
func guardFlagErrorFunc(c *cobra.Command, err error) error {
	if !jsonRequested(os.Args[1:]) {
		fmt.Fprintln(os.Stderr, strings.TrimRight(c.UsageString(), "\n"))
	}
	return err
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
	// --reason is a guard-only free-text justification for a gated command
	// (require_justification). Parsed/stripped here so it never reaches kubectl.
	forwarded, reasonFlag, hasReason := guard.StripReason(forwarded)

	result, ctx, cfg, err := guard.Check(forwarded)

	// Tamper signal: a group/world-writable config can be rewritten by another
	// user to disable protection. Strict mode already fails closed inside Check
	// (Deny); here we surface the non-strict WARNING once, before any hand-off to
	// kubectl (syscall.Exec leaves no chance to print afterward). Suppressed in
	// --json mode so the machine-readable stderr contract for agents stays clean.
	if !jsonMode {
		if insecure, detail, permErr := config.InsecureConfigPerms(); permErr == nil && insecure && (cfg == nil || !cfg.StrictPerms()) {
			ui.PrintWarning(detail + "; protection may have been tampered with. Secure it (chmod 600 the file, 700 its directory), or set strict_config_perms / KUBECTL_GUARD_STRICT to fail closed.")
		}
	}

	// Secret-bearing values (--token, --from-literal=k=v, --patch bodies, key
	// material, ...) are redacted once, here. Every surface that DISPLAYS the
	// command — the audit log, --json output, and user-facing messages — derives
	// from `redacted`; every surface that DECIDES (protection matching, namespace
	// resolution) keeps using `forwarded`, and kubectl is exec'd with `forwarded`.
	//
	// Message and JSON builders take the redacted slice, not just the joined
	// string: they surface individual tokens (the resource name, the command
	// description), and a raw token would bypass the redactor entirely.
	redacted := guard.RedactArgs(forwarded)
	cmdStr := strings.Join(redacted, " ")

	// Parse once to attribute impersonation (--as) and credential overrides
	// (--token) in the audit log, so the record shows who a command ran AS,
	// not just who invoked the guard.
	parsed := guard.ParseArgs(forwarded)

	// justification holds the free-text reason a human/agent supplied to approve a
	// gated command (require_justification, or a provided --reason). Set at
	// confirm/auto-confirm time and recorded on the audit entry via the closure.
	var justification string

	// audit writes an attributed audit entry for this invocation. It is a
	// thin wrapper so every decision path records impersonation/token the same
	// way. cfg may be nil (Deny before config load); in that case it is a no-op.
	audit := func(outcome, reason string) {
		if cfg == nil {
			return
		}
		e := guard.AuditEntry{
			Context:       ctx,
			Command:       cmdStr,
			Outcome:       outcome,
			Reason:        reason,
			Justification: justification,
		}
		if imp := parsed.ImpersonationString(); imp != "" {
			e.Impersonate = imp
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
		jr := guard.JSONForResult(result, ctx, cmdStr, redacted, err)
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
				// The command did not run and no config was written; surface a
				// non-zero exit rather than a misleading success.
				return fmt.Errorf("failed to save config from environment: %w", err)
			}
			if p, perr := config.Path(); perr == nil {
				ui.PrintInfo("Wrote initial config from KUBECTL_GUARD_* env vars: " + p)
			}
			// Proceed to run the command against the freshly written config.
			return runGuard(args)
		}
		// Headless first run with nothing to go on. The bootstrap mode decides the
		// posture; it defaults to "deny" so an unconfigured guard never silently
		// establishes a no-protection posture and persists it to disk. (Before
		// v0.5.0 this branch always wrote an empty config, after which every later
		// invocation found a valid — but unprotected — config and never prompted
		// again. The guard became a no-op and nobody noticed.)
		bootstrapMode, validMode := config.BootstrapMode()
		// Only warn about an unrecognized value on the headless path, where the
		// bootstrap mode actually governs; interactively it is irrelevant.
		if !validMode && noPrompt {
			ui.PrintWarning(fmt.Sprintf("Unrecognized %s=%q; falling back to %q (fail closed).",
				config.EnvBootstrap, os.Getenv(config.EnvBootstrap), bootstrapMode))
		}
		if noPrompt && bootstrapMode != config.BootstrapPrompt {
			if bootstrapMode == config.BootstrapEmpty {
				empty := &config.Config{}
				empty.ApplyDefaults()
				if err := config.Save(empty); err != nil {
					// The command did not run and no config was written; surface a
					// non-zero exit rather than a misleading success.
					return fmt.Errorf("failed to save config: %w", err)
				}
				ui.PrintWarning(fmt.Sprintf("%s=%s: wrote an empty config (no protection) and proceeding.",
					config.EnvBootstrap, config.BootstrapEmpty))
				return runGuard(args)
			}

			// BootstrapDeny: refuse anything that is not a recognized safe read,
			// and write nothing. This fails closed on unknown/future verbs too:
			// the ticket's invariant is "an unconfigured guard must not run
			// state-altering commands", and IsStateAltering returns false for any
			// verb outside the classification map — so an unrecognized mutating
			// verb (e.g. `certificate approve`) would otherwise slip through. Reads
			// carry no mutation risk, so they pass. (Read-based secret exfiltration
			// is a separate axis: it requires configuring protected_resources,
			// which by definition does not exist on an unconfigured first run.)
			if !guard.IsSafeCommand(forwarded) {
				if jsonMode {
					jr := guard.JSONResult{
						Decision: "denied",
						Reason:   "no-config-bootstrap-deny",
						Command:  cmdStr,
					}
					if b, mErr := json.Marshal(jr); mErr == nil {
						fmt.Fprintln(os.Stderr, string(b))
					}
				} else {
					ui.PrintWarning("Refusing to run: the guard has no configuration, so it cannot confirm this command is a safe read on this cluster.")
					ui.PrintInfo("Configure it, then re-run:")
					ui.PrintInfo("  kubectl-guard config init --protected-contexts 'prod-*' --protected-resources secret")
					ui.PrintInfo("  or set KUBECTL_GUARD_PROTECTED_CONTEXTS / KUBECTL_GUARD_PROTECTED_RESOURCES")
					ui.PrintInfo(fmt.Sprintf("  or set %s=%s to run deliberately unprotected.",
						config.EnvBootstrap, config.BootstrapEmpty))
				}
				os.Exit(guard.ExitDenied)
			}
			ui.PrintWarning("No guard configuration found; this read-only command runs unprotected. Run 'kubectl-guard config init' to configure.")
			return execKubectl(forwarded)
		}
		if noPrompt {
			// bootstrapMode == prompt: an explicit opt-in to the wizard. Say so,
			// because it overrides --no-prompt and needs a TTY to complete.
			ui.PrintWarning(fmt.Sprintf("%s=%s overrides --no-prompt: launching the interactive setup wizard.",
				config.EnvBootstrap, config.BootstrapPrompt))
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
		// First-time setup: no prior config exists (Check returned SetupRequired),
		// so there is nothing to weaken or audit — save directly.
		config.RunSetup(contextNames, config.Save)
		return nil

	case guard.Blocked:
		// A Blocked result is either a protected-resource block or a block-mode
		// refusal (context_mode/namespace_mode: block). Determine which so the
		// message and audit reason are accurate.
		blockReason := "protected-resource"
		clusterServer := "" // set below when a protected-cluster match drove the block
		if !guard.MatchesProtectedResource(cfg, forwarded) {
			// Use the actor-effective modes, so an actor-policy upgrade (confirm →
			// block for a known agent) is labeled as a context/namespace block, the
			// same decision the guard made.
			ctxMode := config.ContextModeConfirm
			if cfg != nil {
				ctxMode, _ = guard.EffectiveTargetModes(cfg, forwarded, ctx)
			}
			// Resolve cluster-identity protection once for labeling (best-effort; no
			// kubeconfig read unless protected_clusters is configured).
			srv, clusterHit := guard.ClusterProtected(cfg, forwarded, ctx)
			clusterServer = srv
			switch {
			case cfg != nil && cfg.ReadOnlyActive() && !guard.IsSafeCommandWith(cfg, forwarded):
				// Global read-only/freeze is checked before context gating in the
				// core and blocks anything that is not a known-safe read, so a
				// non-safe block under read-only is that, not a context/namespace
				// block. (A genuine dry-run would not reach Blocked.)
				blockReason = "read-only-mode"
			case cfg != nil && cfg.IsContextProtected(ctx) && ctxMode == config.ContextModeBlock:
				blockReason = "protected-context-block-mode"
			case guard.IsSensitiveAccess(cfg, forwarded) && cfg != nil && cfg.SensitiveAccessMode() == config.SensitiveAccessBlock:
				blockReason = "sensitive-access-block"
			case guard.IsBlastRadiusActive(cfg, forwarded) && cfg != nil && cfg.BlastRadiusMode() == config.BlastRadiusBlock:
				blockReason = "blast-radius-block"
			case guard.IsSensitiveKindActive(cfg, forwarded) && cfg != nil && cfg.SensitiveKindMode() == config.SensitiveKindBlock:
				blockReason = "sensitive-kind-block"
			case clusterHit && cfg != nil && cfg.EffectiveClusterMode(clusterServer) == config.ContextModeBlock:
				// The context NAME is unprotected but the resolved API server matches
				// protected_clusters in block mode (#85).
				blockReason = "protected-cluster-block-mode"
			default:
				blockReason = "protected-namespace-block-mode"
			}
		}
		if jsonMode {
			jr := guard.JSONForResult(result, ctx, cmdStr, redacted, err)
			jr.Reason = blockReason
			if blockReason != "protected-resource" {
				jr.Resource = "" // block-mode is not about a specific resource
			}
			if b, mErr := json.Marshal(jr); mErr == nil {
				fmt.Fprintln(os.Stderr, string(b))
			}
		} else {
			cmdDesc := guard.GetCommandDescription(redacted)
			switch blockReason {
			case "protected-resource":
				ui.PrintWarning(fmt.Sprintf("Blocked: %s targets a protected resource (context: %s)", cmdDesc, ctx))
				if guard.HasRawPath(forwarded) {
					ui.PrintInfo("Command uses --raw, a literal API path the guard cannot map to a resource type; blocked because resource protection is active.")
				} else if guard.HasUninspectableSource(forwarded) {
					ui.PrintInfo("Command reads from stdin/URL/kustomize, which cannot be inspected; blocked as a precaution.")
				}
			case "protected-context-block-mode":
				ui.PrintWarning(fmt.Sprintf("Blocked: %s on protected context %q (block mode: no confirmation offered)", cmdDesc, ctx))
			case "read-only-mode":
				ui.PrintWarning(fmt.Sprintf("Blocked: %s — global read-only mode is active (freeze); everything except known-safe reads is refused, everywhere. Reads still pass. Run 'kubectl-guard unfreeze' or clear KUBECTL_GUARD_READONLY to lift.", cmdDesc))
			case "sensitive-access-block":
				ui.PrintWarning(fmt.Sprintf("Blocked: %s is a sensitive-access verb (sensitive_access: block; refused on every context)", cmdDesc))
			case "blast-radius-block":
				scope := "a wide-scope mutation"
				if _, why := guard.BlastRadius(forwarded); why != "" {
					scope = why
				}
				ui.PrintWarning(fmt.Sprintf("Blocked: %s — %s (blast_radius: block; refused on every context)", cmdDesc, scope))
			case "sensitive-kind-block":
				ui.PrintWarning(fmt.Sprintf("Blocked: %s mutates a sensitive kind (sensitive_kind_mode: block; refused on every context). Reads of the kind still pass.", cmdDesc))
			case "protected-cluster-block-mode":
				ui.PrintWarning(fmt.Sprintf("Blocked: %s on protected cluster %q (block mode: no confirmation offered)", cmdDesc, clusterServer))
			default: // protected-namespace-block-mode
				// Prefer the namespace OBJECT the command targets by name
				// (`delete namespace kube-system`) over the namespace it would
				// be considered to run in, which is "default" and misleading.
				ns, ok := guard.ProtectedNamespaceNameTarget(cfg, forwarded)
				switch {
				case ok:
				case parsed.AllNamespaces:
					ns = "all namespaces"
				default:
					ns = guard.ResolvedTargetNamespace(cfg, forwarded, ctx)
				}
				ui.PrintWarning(fmt.Sprintf("Blocked: %s on protected namespace %q (block mode: no confirmation offered)", cmdDesc, ns))
			}
		}
		audit(guard.OutcomeBlocked, blockReason)
		os.Exit(guard.ExitBlocked)

	case guard.RequireConfirmation:
		// Audited escape hatch: --yes / KUBECTL_GUARD_CONFIRM=yes auto-confirms
		// RequireConfirmation (state-altering on a protected context) as if the
		// user typed yes, but logs it as a distinct "auto-confirmed" outcome so
		// the audit trail records the bypass. Protected-resource Blocks are NOT
		// affected by this (they stay a hard block in their own branch).
		autoConfirm := yesFlag || boolEnv(config.EnvConfirm)
		if autoConfirm {
			// Justification: a non-interactive approval must carry --reason when
			// require_justification is on, else fail closed (the command must not run
			// without a recorded reason). A provided reason is recorded either way.
			if cfg != nil && cfg.RequireJustification {
				r := strings.TrimSpace(reasonFlag)
				if !hasReason || r == "" {
					audit(guard.OutcomeAborted, "justification-required")
					if jsonMode {
						jr := guard.JSONResult{Decision: "needs-confirmation", Reason: "justification-required", Context: ctx, Command: cmdStr, Prompt: "Re-run with --yes --reason \"<why>\" to supply the required justification."}
						if b, mErr := json.Marshal(jr); mErr == nil {
							fmt.Fprintln(os.Stderr, string(b))
						}
					} else {
						fmt.Fprintln(os.Stderr, "Aborted: this command requires a justification. Re-run with --reason \"<why>\".")
					}
					os.Exit(guard.ExitNeedsConfirm)
				}
				justification = r
			} else if hasReason {
				justification = strings.TrimSpace(reasonFlag)
			}
			if !jsonMode {
				ui.PrintWarning("Auto-confirming gated command (--yes / KUBECTL_GUARD_CONFIRM=yes); logged as auto-confirmed.")
			}
			audit(guard.OutcomeAutoConfirmed, "yes-flag")
			return execKubectl(forwarded)
		}

		cmdDesc := guard.GetCommandDescription(redacted)
		// Describe what is protected so the user knows why they're confirming.
		// Namespace protection (#19) may trigger gating even on an unprotected
		// context (including from the context's baked-in namespace), so the
		// message names whichever actually applies.
		reason := "protected context"
		target := ctx
		wide, blastReason := guard.BlastRadius(forwarded)
		clusterServer, clusterHit := guard.ClusterProtected(cfg, forwarded, ctx)
		switch nameTarget, byName := guard.ProtectedNamespaceNameTarget(cfg, forwarded); {
		case guard.IsSensitiveAccess(cfg, forwarded) && !cfg.IsContextProtected(ctx) && !byName:
			// Gated purely because it is a sensitive-access verb on an otherwise
			// unprotected target — name that, not a "protected context".
			reason, target = "sensitive access", "any context"
		case guard.IsSensitiveKindActive(cfg, forwarded) && !cfg.IsContextProtected(ctx) && !byName:
			// Gated as a mutation to a sensitive kind on an otherwise unprotected
			// target — name that.
			reason, target = "sensitive kind", "any context"
		case byName:
			// The command's OBJECT is a protected namespace (e.g.
			// `delete namespace kube-system`). Name that, rather than the
			// namespace the command would otherwise be considered to run in,
			// which is "default" and would read as nonsense.
			reason, target = "protected namespace", nameTarget
		case parsed.AllNamespaces && cfg != nil && cfg.HasProtectedNamespaces():
			reason, target = "protected namespace", "all namespaces"
		case parsed.HasNamespace && parsed.Namespace != "" && cfg != nil && cfg.IsNamespaceProtected(parsed.Namespace):
			reason, target = "protected namespace", parsed.Namespace
		case cfg != nil && cfg.IsContextProtected(ctx):
			reason, target = "protected context", ctx
		case clusterHit:
			// The context NAME is unprotected but the resolved API server matches
			// protected_clusters (#85) — name the cluster, not a "protected context".
			reason, target = "protected cluster", clusterServer
		case wide && cfg != nil && cfg.BlastRadiusMode() != config.BlastRadiusOff:
			// Gated as a wide-scope / bulk mutation with no protected context or
			// namespace in play — name the scope so the human sees WHY.
			reason, target = "blast radius", blastReason
		case cfg != nil && cfg.HasProtectedNamespaces():
			// Namespace-driven gating from the context's baked-in namespace.
			reason, target = "protected namespace", guard.ResolvedTargetNamespace(cfg, forwarded, ctx)
		}
		message := fmt.Sprintf("%s on %s: %s", cmdDesc, reason, target)

		// Agent-relay mode: instead of prompting stdin, emit a structured
		// needs-confirmation object (including a human-readable prompt) and exit
		// with the needs-confirmation code, so an agent framework can relay the
		// request to its own human and re-run with --yes once approved. This is a
		// decision axis independent of --json: it is active whenever the confirm
		// mode is agent-relay or KUBECTL_GUARD_AGENT_RELAY is set.
		agentRelay := (cfg != nil && cfg.ConfirmMode == config.ConfirmModeAgentRelay) || boolEnv(config.EnvAgentRelay)
		if agentRelay {
			rerun := "Re-run with --yes to proceed."
			if cfg != nil && cfg.RequireJustification {
				// The relayed request notes a reason is required so the agent can
				// collect it from its human before re-running.
				rerun = "Re-run with --yes --reason \"<why>\" to proceed (a justification is required)."
			}
			jr := guard.JSONResult{
				Decision: "needs-confirmation",
				Reason:   "agent-relay",
				Context:  ctx,
				Command:  cmdStr,
				Prompt:   fmt.Sprintf("Approve %q on %s %q? %s", cmdDesc, reason, target, rerun),
			}
			if b, mErr := json.Marshal(jr); mErr == nil {
				fmt.Fprintln(os.Stderr, string(b))
			}
			audit(guard.OutcomeRelayed, "agent-relay")
			os.Exit(guard.ExitNeedsConfirm)
		}

		if jsonMode {
			// An agent framework cannot answer an interactive prompt; abort
			// immediately with structured output instead of blocking on stdin.
			emitDecision()
			audit(guard.OutcomeAborted, "")
			os.Exit(guard.ExitNeedsConfirm)
		}

		// Install a signal handler for the duration of the preview + interactive
		// prompt — the one place the guard blocks (on a slow diff/get, or on stdin).
		// A Ctrl-C / SIGTERM here otherwise hits Go's default handler and kills the
		// process with no audit entry, so a gated command the operator abandoned
		// leaves no record. Record it as aborted ("interrupted") and exit non-zero.
		// Best-effort: AppendAudit is flock-serialized and fast, so it will not hang
		// shutdown. Torn down once we have an answer, so a signal arriving after
		// approval cannot spuriously abort an already-confirmed command.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sigDone := make(chan struct{})
		// decided makes the abort-vs-answer outcome mutually exclusive: whichever
		// of {a signal, the operator's answer} claims it FIRST acts, and the other
		// becomes a no-op. Without this, a signal that races the answer (arriving
		// after the prompt returns but before teardown) would still fire and write a
		// contradictory "interrupted" audit entry for a command that actually ran —
		// signal.Stop does not drain an already-buffered signal, and a bare select
		// gives the done channel no priority.
		var decided int32
		go func() {
			select {
			case <-sigCh:
				if atomic.CompareAndSwapInt32(&decided, 0, 1) {
					audit(guard.OutcomeAborted, "interrupted")
					fmt.Fprintln(os.Stderr, "\nInterrupted.")
					os.Exit(guard.ExitNeedsConfirm)
				}
				// The answer already committed and the command is proceeding; the
				// interrupt lost the race, so record nothing.
			case <-sigDone:
			}
		}()

		// Optional: preview what the command will affect before prompting.
		// A diffable apply (apply/create/replace -f) is previewed with
		// `kubectl diff`; a non-diffable destructive command (delete/scale/... with
		// a target or selector) is previewed with a read-only `kubectl get … -o
		// name`. diff_before_confirm covers only the diff; preview_before_confirm
		// covers both. A failed preview warns and prompts anyway.
		switch {
		case cfg != nil && (cfg.DiffBeforeConfirm || cfg.PreviewBeforeConfirm) && guard.IsDiffable(forwarded):
			if diffArgs := guard.DiffArgs(forwarded); diffArgs != nil {
				out, derr := guard.RunKubectl(diffArgs...)
				if derr != nil {
					if ee, ok := derr.(*exec.ExitError); ok && (ee.ExitCode() == 0 || ee.ExitCode() == 1) {
						derr = nil // exit 1 means diffs were found, which is normal
					}
				}
				if derr != nil {
					ui.PrintWarning("Could not generate a diff (server-side dry-run may be denied by RBAC); prompting anyway.")
				} else {
					fmt.Fprintln(os.Stderr, "--- preview: kubectl diff ---")
					if len(strings.TrimRight(string(out), "\n")) > 0 {
						fmt.Fprint(os.Stderr, string(out))
					}
					fmt.Fprintln(os.Stderr, "--- end diff ---")
				}
			}
		case cfg != nil && cfg.PreviewBeforeConfirm:
			if previewArgs := guard.PreviewArgs(forwarded); previewArgs != nil {
				printAffectedPreview(previewArgs)
			}
		}

		var timeout time.Duration
		if cfg != nil && cfg.ConfirmTimeoutSeconds > 0 {
			timeout = time.Duration(cfg.ConfirmTimeoutSeconds) * time.Second
		}

		var outcome ui.ConfirmOutcome
		if cfg != nil && cfg.ConfirmMode == config.ConfirmModeTypeName {
			outcome = ui.ConfirmWithName(message, target, timeout)
		} else {
			outcome = ui.Confirm(message, timeout)
		}

		// Claim the decision for the answer. If a signal won the race, the watcher
		// is committing an abort+exit; block until that os.Exit terminates us, so we
		// never run a command the operator interrupted. If the answer won, the
		// watcher's signal case becomes a no-op.
		if !atomic.CompareAndSwapInt32(&decided, 0, 1) {
			<-make(chan struct{})
		}
		// Stop handling signals and release the watcher goroutine so a late Ctrl-C
		// cannot abort an already-approved command and the goroutine does not leak.
		signal.Stop(sigCh)
		close(sigDone)

		switch outcome {
		case ui.ConfirmApproved:
			// Compliance justification: when require_justification is on, use a
			// reason supplied on the command line (--reason), otherwise prompt for
			// one after approval. An empty reason (neither given nor typed) aborts
			// (fail closed).
			if cfg != nil && cfg.RequireJustification {
				r := strings.TrimSpace(reasonFlag)
				if !hasReason || r == "" {
					r = ui.PromptReason(timeout)
				}
				if r == "" {
					audit(guard.OutcomeAborted, "justification-required")
					fmt.Fprintln(os.Stderr, "Aborted: a justification is required (empty reason).")
					os.Exit(guard.ExitNeedsConfirm)
				}
				justification = r
			} else if hasReason {
				justification = strings.TrimSpace(reasonFlag)
			}
			audit(guard.OutcomeConfirmed, "")
			return execKubectl(forwarded)
		case ui.ConfirmTimedOut:
			// Fail-safe: an unanswered prompt is a decline, recorded distinctly so
			// the audit trail shows the command was abandoned, not refused.
			audit(guard.OutcomeAborted, "timeout")
			fmt.Fprintln(os.Stderr, "Timed out — aborted (not confirmed).")
			os.Exit(guard.ExitNeedsConfirm)
		default: // ui.ConfirmDeclined
			audit(guard.OutcomeAborted, "")
			fmt.Fprintln(os.Stderr, "Aborted.")
			os.Exit(guard.ExitNeedsConfirm)
		}

	case guard.Allow:
		// Log BEFORE ExecKubectl: syscall.Exec replaces this process, so
		// anything after the call never runs.
		outcome := guard.OutcomeAllowed
		if guard.IsDryRun(forwarded) && guard.SupportsDryRun(forwarded) {
			outcome = guard.OutcomeDryRun
		}
		audit(outcome, "")
		return execKubectl(forwarded)
	}

	return nil
}

// firstArgComplete returns a ValidArgsFunction that dynamically completes only
// the FIRST positional argument from get(), with no fallback file completion.
func firstArgComplete(get func() []string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return get(), cobra.ShellCompDirectiveNoFileComp
	}
}

// loadProtectedList returns a slice from the on-disk config for completion
// (protected contexts/namespaces/resources), best-effort — nil on any error so
// completion never fails the shell.
func loadProtectedList(get func(*config.Config) []string) []string {
	exists, err := config.Exists()
	if err != nil || !exists {
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return nil
	}
	return get(cfg)
}

// availableContexts lists kubectl contexts for completing add-context,
// best-effort (nil if kubectl/kubeconfig is unavailable).
func availableContexts() []string {
	contexts, err := guard.GetAllContexts()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(contexts))
	for _, c := range contexts {
		names = append(names, c.Name)
	}
	return names
}

// commonResourceKinds is a static completion list for add-resource — common
// kinds users protect; not exhaustive (any kind is still accepted).
func commonResourceKinds() []string {
	return []string{
		"secret", "configmap", "pod", "deployment", "statefulset", "daemonset",
		"node", "namespace", "persistentvolume", "persistentvolumeclaim",
		"serviceaccount", "role", "rolebinding", "clusterrole", "clusterrolebinding",
		"ingress", "service", "job", "cronjob",
	}
}

// newConfigCommand builds the `config` cobra command tree (setup, init, list,
// the add/remove families, the mode setters, audit, validate, path). It is used
// both to execute a `config` invocation (runConfigCommand) and to model the CLI
// surface for shell-completion generation (newRootCommand).
func newConfigCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage kubectl-guard configuration",
		// Errors and usage are routed through the top-level reportError sink for a
		// consistent shape; usage is restored only for flag-parse errors.
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	rootCmd.SetFlagErrorFunc(guardFlagErrorFunc)

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
			// Route the wizard's write through saveConfig, so re-running setup on an
			// existing install (which rebuilds a contexts-only config, dropping other
			// protection) is audited and gated as the weakening it is.
			config.RunSetup(contextNames, saveConfig)
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
			if err := saveConfig(cfg); err != nil {
				return err
			}
			path, err := config.Path()
			if err != nil {
				return err
			}
			ui.PrintSuccess("Wrote config: " + path)
			if len(cfg.ProtectedContexts) > 0 {
				ui.PrintInfo("Protected contexts: " + strings.Join(cfg.ProtectedContextPatterns(), ", "))
			}
			if len(cfg.ProtectedResources) > 0 {
				ui.PrintInfo("Protected resources: " + strings.Join(cfg.ProtectedResources, ", "))
			}
			if len(cfg.ProtectedNamespaces) > 0 {
				ui.PrintInfo("Protected namespaces: " + strings.Join(cfg.ProtectedNamespacePatterns(), ", "))
			}
			if len(cfg.ProtectedClusters) > 0 {
				ui.PrintInfo("Protected clusters: " + strings.Join(cfg.ProtectedClusterKeys(), ", "))
			}
			ui.PrintInfo("Confirm mode: " + cfg.ConfirmMode)
			return nil
		},
	}
	initCmd.Flags().String("protected-contexts", "", "comma-separated context patterns to protect (e.g. 'prod-*,prod-cluster')")
	initCmd.Flags().String("protected-resources", "", "comma-separated resources to block on every context (e.g. 'secret')")
	initCmd.Flags().String("confirm-mode", "", "confirmation mode for protected contexts (simple|type-name|agent-relay)")
	rootCmd.AddCommand(initCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List protected contexts and resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			return printConfig()
		},
	})

	// add-context / add (alias) / remove-context / remove (alias) /
	// add-resource / remove-resource all share one shape. valid is an optional
	// dynamic ValidArgsFunction (nil for none).
	addCmd := func(use, short string, fn func(*config.Config, string) bool, doneTmpl, noopTmpl string, hidden bool, valid func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)) {
		rootCmd.AddCommand(&cobra.Command{
			Use:               use,
			Short:             short,
			Args:              cobra.ExactArgs(1),
			Hidden:            hidden,
			ValidArgsFunction: valid,
			RunE: func(_ *cobra.Command, a []string) error {
				return mutateConfig(func(c *config.Config) bool { return fn(c, a[0]) }, fmt.Sprintf(doneTmpl, a[0]), fmt.Sprintf(noopTmpl, a[0]))
			},
		})
	}
	// newAddProtectedCmd builds an add-context / add-namespace command with an
	// optional --mode flag for a per-pattern protection mode. When --mode is NOT
	// given, it calls the plain adder, which is a pure no-op on an existing pattern
	// (never touching its mode — so a bare re-add can never downgrade a block
	// pattern). When --mode IS given (confirm | block | - for inherit), it calls the
	// mode-aware adder, which adds or UPDATES the pattern's mode. The mode is
	// pre-validated here for a clear error, because the adder's false return also
	// means "no change", which must not be conflated with an invalid mode.
	newAddProtectedCmd := func(use, short, doneTmpl, noopTmpl string, hidden bool,
		plain func(*config.Config, string) bool,
		withMode func(*config.Config, string, string) bool,
		valid func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)) *cobra.Command {
		var modeRaw string
		cmd := &cobra.Command{
			Use:               use,
			Short:             short,
			Args:              cobra.ExactArgs(1),
			Hidden:            hidden,
			ValidArgsFunction: valid,
			RunE: func(c *cobra.Command, a []string) error {
				pattern := a[0]
				modeChanged := c.Flags().Changed("mode")
				mode := normalizeInheritMode(modeRaw)
				if modeChanged && mode != "" && !isValidProtectionMode(mode) {
					return fmt.Errorf("invalid --mode %q (want %q, %q, or %q to inherit the global mode)",
						modeRaw, config.ContextModeConfirm, config.ContextModeBlock, "-")
				}
				return mutateConfig(func(cfg *config.Config) bool {
					if modeChanged {
						return withMode(cfg, pattern, mode)
					}
					return plain(cfg, pattern)
				}, fmt.Sprintf(doneTmpl, pattern), fmt.Sprintf(noopTmpl, pattern))
			},
		}
		cmd.Flags().StringVar(&modeRaw, "mode", "", "per-pattern protection mode: confirm | block | - (inherit the global mode)")
		return cmd
	}

	// Dynamic completions: add-* offers candidates to add (available contexts,
	// common resource kinds), remove-* offers what is currently protected.
	completeAddContext := firstArgComplete(availableContexts)
	completeRemoveContext := firstArgComplete(func() []string {
		return loadProtectedList(func(c *config.Config) []string { return c.ProtectedContextPatterns() })
	})
	completeAddResource := firstArgComplete(commonResourceKinds)
	completeRemoveResource := firstArgComplete(func() []string {
		return loadProtectedList(func(c *config.Config) []string { return c.ProtectedResources })
	})
	completeRemoveNamespace := firstArgComplete(func() []string {
		return loadProtectedList(func(c *config.Config) []string { return c.ProtectedNamespacePatterns() })
	})
	completeRemoveCluster := firstArgComplete(func() []string {
		return loadProtectedList(func(c *config.Config) []string { return c.ProtectedClusterKeys() })
	})

	rootCmd.AddCommand(newAddProtectedCmd("add-context <pattern>", "Add a context/pattern to the protected list (optional --mode)", "Added context: %s", "Context already protected: %s", false, (*config.Config).AddContext, (*config.Config).AddContextWithMode, completeAddContext))
	rootCmd.AddCommand(newAddProtectedCmd("add <pattern>", "Alias for add-context", "Added context: %s", "Context already protected: %s", true, (*config.Config).AddContext, (*config.Config).AddContextWithMode, completeAddContext))
	addCmd("remove-context <pattern>", "Remove a context/pattern from the protected list", (*config.Config).RemoveContext, "Removed context: %s", "Context not in protected list: %s", false, completeRemoveContext)
	addCmd("remove <pattern>", "Alias for remove-context", (*config.Config).RemoveContext, "Removed context: %s", "Context not in protected list: %s", true, completeRemoveContext)
	addCmd("add-resource <name>", "Add a resource to block on every context (e.g. secret)", (*config.Config).AddResource, "Blocked resource: %s", "Resource already protected: %s", false, completeAddResource)
	addCmd("remove-resource <name>", "Remove a resource from the blocked list", (*config.Config).RemoveResource, "Unblocked resource: %s", "Resource not in protected list: %s", false, completeRemoveResource)
	rootCmd.AddCommand(newAddProtectedCmd("add-namespace <pattern>", "Add a namespace/pattern to the protected list (e.g. kube-system, prod-*; optional --mode)", "Protected namespace: %s", "Namespace already protected: %s", false, (*config.Config).AddNamespace, (*config.Config).AddNamespaceWithMode, nil))
	addCmd("remove-namespace <pattern>", "Remove a namespace/pattern from the protected list", (*config.Config).RemoveNamespace, "Removed namespace: %s", "Namespace not in protected list: %s", false, completeRemoveNamespace)

	// add-cluster protects by CLUSTER identity (the API server URL / a host glob),
	// not the spoofable context name. It cannot reuse newAddProtectedCmd because
	// AddProtectedCluster returns (changed, error): an invalid mode or empty value
	// must surface to the user rather than be conflated with a no-op. The value is
	// auto-detected as an exact server or a pattern (a glob metachar makes it a
	// pattern), and a --mode confirm|block (- to inherit) sets the per-entry mode.
	var clusterModeRaw string
	addClusterCmd := &cobra.Command{
		Use:   "add-cluster <server-or-pattern>",
		Short: "Protect by cluster identity: an API server URL or host glob (optional --mode)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, a []string) error {
			value := a[0]
			mode := normalizeInheritMode(clusterModeRaw)
			if c.Flags().Changed("mode") && mode != "" && !isValidProtectionMode(mode) {
				return fmt.Errorf("invalid --mode %q (want %q, %q, or %q to inherit the global mode)",
					clusterModeRaw, config.ContextModeConfirm, config.ContextModeBlock, "-")
			}
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			// AddProtectedCluster returns (changed, error): an invalid mode or empty
			// value surfaces to the user rather than being conflated with a no-op.
			changed, err := cfg.AddProtectedCluster(value, mode)
			if err != nil {
				return err
			}
			if !changed {
				ui.PrintInfo("Cluster already protected: " + value)
				return nil
			}
			// Route through saveConfig so a mode downgrade (block → confirm/inherit)
			// on an existing entry is gated/audited as the weakening it is.
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Protected cluster: " + value)
			return nil
		},
	}
	addClusterCmd.Flags().StringVar(&clusterModeRaw, "mode", "", "per-entry protection mode: confirm | block | - (inherit the global context_mode)")
	rootCmd.AddCommand(addClusterCmd)
	addCmd("remove-cluster <value>", "Remove a protected cluster (server URL, pattern, or its list key)", (*config.Config).RemoveProtectedCluster, "Removed protected cluster: %s", "Cluster not in protected list: %s", false, completeRemoveCluster)

	rootCmd.AddCommand(&cobra.Command{
		Use:   "confirm-mode [simple|type-name|agent-relay]",
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
				return fmt.Errorf("invalid mode %q (want %q, %q, or %q)", args[0], config.ConfirmModeSimple, config.ConfirmModeTypeName, config.ConfirmModeAgentRelay)
			}
			if err := saveConfig(cfg); err != nil {
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
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Audit mode set: " + cfg.AuditMode)
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "context-mode [confirm|block]",
		Short: "Show or set how protected contexts treat state-altering commands",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				ui.PrintInfo("Context mode: " + cfg.ContextMode)
				return nil
			}
			if !cfg.SetContextMode(args[0]) {
				return fmt.Errorf("invalid mode %q (want %q or %q)", args[0], config.ContextModeConfirm, config.ContextModeBlock)
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Context mode set: " + cfg.ContextMode)
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "namespace-mode [confirm|block]",
		Short: "Show or set how protected namespaces treat state-altering commands",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				ui.PrintInfo("Namespace mode: " + cfg.NamespaceMode)
				return nil
			}
			if !cfg.SetNamespaceMode(args[0]) {
				return fmt.Errorf("invalid mode %q (want %q or %q)", args[0], config.NamespaceModeConfirm, config.NamespaceModeBlock)
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Namespace mode set: " + cfg.NamespaceMode)
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "blast-radius [off|gate|block]",
		Short: "Show or set gating of wide-scope / bulk mutations on every context",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				ui.PrintInfo("Blast radius: " + cfg.BlastRadiusMode())
				return nil
			}
			if !cfg.SetBlastRadiusMode(args[0]) {
				return fmt.Errorf("invalid mode %q (want %q, %q, or %q)", args[0], config.BlastRadiusOff, config.BlastRadiusGate, config.BlastRadiusBlock)
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Blast radius set: " + cfg.BlastRadius)
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "sensitive-kind [off|confirm|block]",
		Short: "Show or set gating of state-altering commands on sensitive kinds",
		Long: "Gate mutations to a configured kind (node, namespace, persistentvolume,\n" +
			"a critical CRD) on every context, while leaving reads alone. Manage the\n" +
			"kind list with add-sensitive-kind / remove-sensitive-kind.\n\n" +
			"Matches a resource token, an inspectable -f manifest kind, and the\n" +
			"implicit node target of cordon/uncordon/drain. It does NOT gate\n" +
			"un-inspectable sources (-f -, a URL, -k kustomize, or --raw); use\n" +
			"protected_resources for a fail-closed block that also covers those.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				ui.PrintInfo("Sensitive-kind mode: " + cfg.SensitiveKindMode())
				if len(cfg.SensitiveKinds) > 0 {
					ui.PrintInfo("Sensitive kinds: " + strings.Join(cfg.SensitiveKinds, ", "))
				}
				return nil
			}
			if !cfg.SetSensitiveKindMode(args[0]) {
				return fmt.Errorf("invalid mode %q (want %q, %q, or %q)", args[0], config.SensitiveKindOff, config.SensitiveKindConfirm, config.SensitiveKindBlock)
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Sensitive-kind mode set: " + cfg.SensitiveKindMode())
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:               "add-sensitive-kind <kind>",
		Short:             "Gate state-altering commands on this kind on every context (e.g. node)",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeAddResource,
		RunE: func(_ *cobra.Command, a []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if !cfg.AddSensitiveKind(a[0]) {
				ui.PrintInfo("Kind already sensitive: " + a[0])
				return nil
			}
			// Adding a kind with the policy off would be a no-op; default it to
			// confirm so the kind actually takes effect (the user can tighten to
			// block or set it off explicitly).
			activated := false
			if cfg.SensitiveKindMode() == config.SensitiveKindOff {
				cfg.SetSensitiveKindMode(config.SensitiveKindConfirm)
				activated = true
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Sensitive kind added: " + a[0])
			if activated {
				ui.PrintInfo("Sensitive-kind mode was off; set to 'confirm'. Use 'config sensitive-kind block' to hard-refuse.")
			}
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "remove-sensitive-kind <kind>",
		Short: "Stop gating state-altering commands on this kind",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: firstArgComplete(func() []string {
			return loadProtectedList(func(c *config.Config) []string { return c.SensitiveKinds })
		}),
		RunE: func(_ *cobra.Command, a []string) error {
			return mutateConfig(func(c *config.Config) bool { return c.RemoveSensitiveKind(a[0]) },
				"Sensitive kind removed: "+a[0], "Kind not in sensitive list: "+a[0])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "actor-policy [<actor> <context-mode> [namespace-mode] | remove <actor>]",
		Short: "Show or set per-actor context/namespace mode overrides",
		Long: "Per-actor overrides of the global context/namespace mode, so a known\n" +
			"actor label (KUBECTL_GUARD_ACTOR, matched by glob) can be held to a\n" +
			"stricter posture than a human. An override can only tighten a mode\n" +
			"(confirm -> block), never weaken it.\n\n" +
			"  actor-policy                          list the policies\n" +
			"  actor-policy <actor> <ctx-mode> [ns]  set/replace a policy\n" +
			"  actor-policy remove <actor>           delete a policy\n\n" +
			"Modes are confirm|block. Use \"-\" for a mode to inherit the global one.",
		Args: cobra.MaximumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				printActorPolicies(cfg)
				return nil
			}
			if args[0] == "remove" {
				if len(args) != 2 {
					return fmt.Errorf("usage: config actor-policy remove <actor>")
				}
				if !cfg.RemoveActorPolicy(args[1]) {
					return fmt.Errorf("no actor policy for %q", args[1])
				}
				if err := saveConfig(cfg); err != nil {
					return err
				}
				ui.PrintSuccess("Removed actor policy: " + args[1])
				return nil
			}
			if len(args) < 2 {
				return fmt.Errorf("usage: config actor-policy <actor> <context-mode> [namespace-mode] (mode is confirm|block, or - to inherit)")
			}
			ctxMode := normalizeInheritMode(args[1])
			nsMode := ""
			if len(args) == 3 {
				nsMode = normalizeInheritMode(args[2])
			}
			if !cfg.SetActorPolicy(args[0], ctxMode, nsMode) {
				return fmt.Errorf("invalid actor policy (actor must be non-empty; modes must be %q, %q, or - to inherit)", config.ContextModeConfirm, config.ContextModeBlock)
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess(fmt.Sprintf("Actor policy set: %s (context=%s namespace=%s)", args[0], displayMode(ctxMode), displayMode(nsMode)))
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "audit-rotation [<max-size-mb> [max-files]]",
		Short: "Show or set audit-log size-based rotation",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				if cfg.AuditMaxSizeMB <= 0 {
					ui.PrintInfo("Audit rotation: off (log grows unbounded)")
				} else {
					ui.PrintInfo(fmt.Sprintf("Audit rotation: at %d MB, keeping %d archive(s)", cfg.AuditMaxSizeMB, cfg.AuditMaxFilesOrDefault()))
				}
				return nil
			}
			size, err := strconv.Atoi(args[0])
			if err != nil || size < 0 {
				return fmt.Errorf("max-size-mb must be a non-negative integer (0 disables rotation)")
			}
			cfg.AuditMaxSizeMB = size
			if len(args) == 2 {
				files, err := strconv.Atoi(args[1])
				if err != nil || files < 0 {
					return fmt.Errorf("max-files must be a non-negative integer")
				}
				cfg.AuditMaxFiles = files
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			if cfg.AuditMaxSizeMB == 0 {
				ui.PrintSuccess("Audit rotation disabled")
			} else {
				ui.PrintSuccess(fmt.Sprintf("Audit rotation set: %d MB, %d archive(s)", cfg.AuditMaxSizeMB, cfg.AuditMaxFilesOrDefault()))
			}
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "audit-webhook [<url>|off]",
		Short: "Show or set a webhook that receives each audit entry as JSON",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				if cfg.AuditWebhookURL == "" {
					ui.PrintInfo("Audit webhook: (none)")
				} else {
					ui.PrintInfo("Audit webhook: " + cfg.AuditWebhookURL)
				}
				return nil
			}
			if args[0] == "off" {
				cfg.AuditWebhookURL = ""
			} else {
				if !config.ValidWebhookURL(args[0]) {
					return fmt.Errorf("%q is not a valid http(s) URL", args[0])
				}
				cfg.AuditWebhookURL = args[0]
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			if cfg.AuditWebhookURL == "" {
				ui.PrintSuccess("Audit webhook cleared")
			} else {
				ui.PrintSuccess("Audit webhook set: " + cfg.AuditWebhookURL)
			}
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "audit-syslog [on|off]",
		Short: "Show or toggle shipping audit entries to local syslog",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				ui.PrintInfo("Audit syslog: " + onOff(cfg.AuditSyslog))
				return nil
			}
			switch args[0] {
			case "on":
				cfg.AuditSyslog = true
			case "off":
				cfg.AuditSyslog = false
			default:
				return fmt.Errorf("expected 'on' or 'off'")
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Audit syslog: " + onOff(cfg.AuditSyslog))
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "confirm-weakening [on|off]",
		Short: "Show or toggle requiring confirmation for protection-weakening config changes",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				ui.PrintInfo("Require confirm on weakening: " + onOff(cfg.RequireConfirmWeakening))
				return nil
			}
			switch args[0] {
			case "on":
				cfg.RequireConfirmWeakening = true
			case "off":
				cfg.RequireConfirmWeakening = false
			default:
				return fmt.Errorf("expected 'on' or 'off'")
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Require confirm on weakening: " + onOff(cfg.RequireConfirmWeakening))
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "require-justification [on|off]",
		Short: "Show or toggle requiring a free-text reason to approve a gated command",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				ui.PrintInfo("Require justification: " + onOff(cfg.RequireJustification))
				return nil
			}
			switch args[0] {
			case "on":
				cfg.RequireJustification = true
			case "off":
				cfg.RequireJustification = false
			default:
				return fmt.Errorf("expected 'on' or 'off'")
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Require justification: " + onOff(cfg.RequireJustification))
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "unknown-verb [allow|gate|deny]",
		Short: "Show or set how unrecognized verbs are treated on protected targets",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				ui.PrintInfo("Unknown verb: " + cfg.UnknownVerbMode())
				return nil
			}
			if !cfg.SetUnknownVerb(args[0]) {
				return fmt.Errorf("invalid mode %q (want %q, %q, or %q)", args[0], config.UnknownVerbAllow, config.UnknownVerbGate, config.UnknownVerbDeny)
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess("Unknown verb policy set: " + cfg.UnknownVerb)
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "command-override [safe <verb> | dangerous <verb> | remove <verb>]",
		Short: "Override the built-in safe/state-altering classification of a verb",
		Long: "Tailor command classification without forking. `safe` makes a verb\n" +
			"pass through as read-only; `dangerous` makes it require confirmation on\n" +
			"protected contexts (e.g. a custom plugin, or `logs` if apps log secrets).\n\n" +
			"  command-override                    list overrides\n" +
			"  command-override safe <verb>        classify <verb> as read-only\n" +
			"  command-override dangerous <verb>   classify <verb> as state-altering\n" +
			"  command-override remove <verb>      drop any override for <verb>",
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				printCommandOverrides(cfg)
				return nil
			}
			if len(args) != 2 {
				return fmt.Errorf("usage: config command-override <safe|dangerous|remove> <verb>")
			}
			action, verb := args[0], args[1]
			switch action {
			case "safe":
				if !cfg.SetCommandOverride(verb, config.ClassSafe) {
					return fmt.Errorf("invalid verb %q", verb)
				}
			case "dangerous":
				if !cfg.SetCommandOverride(verb, config.ClassStateAltering) {
					return fmt.Errorf("invalid verb %q", verb)
				}
			case "remove":
				if !cfg.RemoveCommandOverride(verb) {
					return fmt.Errorf("no override for %q", verb)
				}
			default:
				return fmt.Errorf("expected 'safe', 'dangerous', or 'remove', got %q", action)
			}
			if err := saveConfig(cfg); err != nil {
				return err
			}
			ui.PrintSuccess(fmt.Sprintf("Command override updated: %s %s", action, strings.ToLower(strings.TrimSpace(verb))))
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "audit [verify]",
		Short: "Show the audit log, or verify its tamper-evident chain",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrCreateConfig()
			if err != nil {
				return err
			}
			path, err := config.AuditPath(cfg)
			if err != nil {
				return err
			}
			if len(args) == 1 && args[0] == "verify" {
				return runAuditVerify(cfg, path)
			}
			if len(args) == 1 {
				return fmt.Errorf("unknown audit subcommand %q (want 'verify')", args[0])
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
		Use:   "validate",
		Short: "Check the config for problems (exit non-zero if any)",
		RunE: func(cmd *cobra.Command, args []string) error {
			exists, err := config.Exists()
			if err != nil {
				return err
			}
			if !exists {
				ui.PrintInfo("No configuration file; nothing to validate.")
				return nil
			}
			cfg, err := config.Load()
			if err != nil {
				// An unparseable config file is itself a fatal validation
				// failure. config.Load already wraps it as "config file <path> is
				// not valid YAML: ..."; print that verbatim (don't re-prefix, which
				// doubled the phrase) and exit non-zero directly, so the output is a
				// single clean line rather than cobra's usage dump.
				ui.PrintWarning(err.Error())
				os.Exit(1)
			}
			cfg.ApplyDefaults()
			problems := cfg.Validate()
			if len(problems) == 0 {
				ui.PrintSuccess("Config is valid.")
				return nil
			}
			ui.PrintWarning(fmt.Sprintf("Config has %d problem(s):", len(problems)))
			for _, p := range problems {
				fmt.Fprintln(os.Stderr, "  - "+p)
			}
			// Exit non-zero so CI / pre-flight checks fail on a bad config.
			os.Exit(1)
			return nil // unreachable
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

	return rootCmd
}

// runConfigCommand executes a `kubectl-guard config ...` invocation. It parses
// args starting after "config" (os.Args[2:]), matching the top-level dispatch.
func runConfigCommand() error {
	cmd := newConfigCommand()
	cmd.SetArgs(os.Args[2:])
	return cmd.Execute()
}

// newRootCommand builds a cobra command tree that models kubectl-guard's OWN
// subcommands (config + its subtree, doctor, explain). Its only job is to back
// shell-completion generation and dynamic completion — the actual top-level
// dispatch stays the manual switch in run(), because a cobra root would try to
// parse kubectl passthrough (`kubectl-guard get pods`) as its own command. Cobra
// auto-attaches the `completion` subcommand to a root that has children.
func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "kubectl-guard",
		Short:         "Protect production clusters and sensitive resources from accidental kubectl commands",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetFlagErrorFunc(guardFlagErrorFunc)
	root.AddCommand(newConfigCommand())
	root.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Check PATH-shadowing interception, config, and posture",
		RunE:  func(_ *cobra.Command, _ []string) error { return runDoctor(nil) },
	})
	root.AddCommand(&cobra.Command{
		Use:   "explain",
		Short: "Preflight: would a kubectl command be gated, and why?",
		RunE:  func(_ *cobra.Command, args []string) error { return runExplain(args) },
	})
	root.AddCommand(&cobra.Command{
		Use:   "uninstall",
		Short: "Remove the PATH-shadowing shim (and, with --purge, config + audit log)",
		RunE:  func(_ *cobra.Command, args []string) error { return runUninstall(args) },
	})
	return root
}

// invokedAsGuard reports whether the binary was invoked by its own name
// (kubectl-guard, or a dev/test build thereof) rather than as the `kubectl`
// shim. It disambiguates `completion`/`__complete`, which BOTH kubectl-guard and
// kubectl (both cobra-based) define: invoked as ourselves they mean the guard's
// completion; invoked as the kubectl shim they are kubectl's own and must pass
// through untouched.
func invokedAsGuard() bool {
	return strings.Contains(filepath.Base(os.Args[0]), "kubectl-guard")
}

// runRootCompletion drives the modeled root command for both `completion <shell>`
// (script generation) and cobra's hidden `__complete`/`__completeNoDesc` runtime
// requests (dynamic completion), which the sourced script issues.
func runRootCompletion() error {
	root := newRootCommand()
	root.SetArgs(os.Args[1:])
	return root.Execute()
}

// mutateConfig loads (or creates) the config, applies fn, saves on change, and
// prints the appropriate message.
func mutateConfig(fn func(*config.Config) bool, done, noop string) error {
	cfg, err := loadOrCreateConfig()
	if err != nil {
		return err
	}
	if fn(cfg) {
		if err := saveConfig(cfg); err != nil {
			return err
		}
		ui.PrintSuccess(done)
	} else {
		ui.PrintInfo(noop)
	}
	return nil
}

// saveConfig persists a change made by a `config` subcommand. It defends the
// guard's own config: every change is AUDITED (outcome config-change), and a
// change that WEAKENS protection is gated behind an interactive confirmation when
// require_confirm_weakening is set. The audit is written BEFORE the change takes
// effect, using the OLD config's audit policy — so even `audit-mode off` is
// recorded — and the weakening gate reads the OLD require_confirm_weakening, so
// turning that flag off is itself gated.
func saveConfig(newCfg *config.Config) error {
	old := currentOnDiskConfig()
	weakening := config.WeakensProtection(old, newCfg)
	cmdStr := configCommandString()

	if len(weakening) > 0 && old.RequireConfirmWeakening {
		ui.PrintWarning("This config change weakens kubectl-guard's protection:")
		for _, item := range weakening {
			fmt.Fprintln(os.Stderr, "  - "+item)
		}
		if ui.Confirm("Apply this protection-weakening change?", 0) != ui.ConfirmApproved {
			_ = guard.AppendAudit(old, guard.AuditEntry{
				Command: cmdStr,
				Outcome: guard.OutcomeConfigChange,
				Reason:  "weakening declined: " + strings.Join(weakening, "; "),
			})
			return fmt.Errorf("aborted: protection-weakening change not confirmed (re-run and confirm, or set require_confirm_weakening: false first)")
		}
	}

	reason := "config change"
	if len(weakening) > 0 {
		reason = "weakened protection: " + strings.Join(weakening, "; ")
	}
	_ = guard.AppendAudit(old, guard.AuditEntry{
		Command: cmdStr,
		Outcome: guard.OutcomeConfigChange,
		Reason:  reason,
	})

	return config.Save(newCfg)
}

// currentOnDiskConfig loads the config currently on disk (defaults applied) as
// the "before" state for weakening detection and auditing, or an empty
// default config when none exists yet.
func currentOnDiskConfig() *config.Config {
	exists, err := config.Exists()
	if err == nil && exists {
		if c, err := config.Load(); err == nil {
			c.ApplyDefaults()
			return c
		}
	}
	c := &config.Config{}
	c.ApplyDefaults()
	return c
}

// configCommandString renders the invoked `config` subcommand for the audit
// record (e.g. "config remove-resource secret"), recorded verbatim. Config args
// are policy values, not kubectl credential flags; the one exception is a webhook
// URL that embeds a token in its query string, which is stored as-is in the
// 0600-mode local audit log (json.Marshal escapes control characters, so a
// crafted arg cannot forge a log line).
func configCommandString() string {
	if len(os.Args) > 1 {
		return strings.Join(os.Args[1:], " ")
	}
	return "config"
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
		for _, pp := range cfg.ProtectedContexts {
			fmt.Printf("  - %s\n", formatPattern(pp))
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
		for _, pp := range cfg.ProtectedNamespaces {
			fmt.Printf("  - %s\n", formatPattern(pp))
		}
	}

	ui.PrintInfo("Protected clusters (by API server identity):")
	if len(cfg.ProtectedClusters) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, pc := range cfg.ProtectedClusters {
			fmt.Printf("  - %s\n", formatClusterKey(pc))
		}
	}

	ui.PrintInfo("Confirm mode: " + cfg.ConfirmMode)
	ui.PrintInfo("Blast radius: " + cfg.BlastRadiusMode())
	if cfg.HasSensitiveKinds() {
		ui.PrintInfo(fmt.Sprintf("Sensitive kinds (%s): %s", cfg.SensitiveKindMode(), strings.Join(cfg.SensitiveKinds, ", ")))
	}
	ui.PrintInfo("Unknown verb: " + cfg.UnknownVerbMode())
	ui.PrintInfo("Require confirm on weakening: " + onOff(cfg.RequireConfirmWeakening))

	printActorPolicies(cfg)
	printCommandOverrides(cfg)

	auditPath, _ := config.AuditPath(cfg)
	ui.PrintInfo("Audit log: " + auditPath)
	if cfg.AuditMaxSizeMB > 0 {
		ui.PrintInfo(fmt.Sprintf("Audit rotation: %d MB, %d archive(s)", cfg.AuditMaxSizeMB, cfg.AuditMaxFilesOrDefault()))
	}
	if cfg.AuditWebhookURL != "" {
		ui.PrintInfo("Audit webhook: " + cfg.AuditWebhookURL)
	}
	if cfg.AuditSyslog {
		ui.PrintInfo("Audit syslog: on")
	}

	return nil
}

// maxPreviewLines caps how many affected-object names the preview prints, so a
// selector matching thousands of objects does not flood the terminal before the
// prompt. Beyond the cap it prints a "… and N more" summary.
const maxPreviewLines = 20

// printAffectedPreview runs the read-only `kubectl get … -o name` preview and
// prints the affected objects to stderr before the confirmation prompt. It is
// best-effort: any failure warns and returns so the prompt still shows.
func printAffectedPreview(previewArgs []string) {
	out, err := guard.RunKubectl(previewArgs...)
	if err != nil {
		// exit 1 from `get` is "not found" — a valid, informative result (the
		// selector/name matches nothing), not a preview failure.
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			fmt.Fprintln(os.Stderr, "--- preview: affected resources ---")
			fmt.Fprintln(os.Stderr, "(no matching objects found)")
			fmt.Fprintln(os.Stderr, "--- end preview ---")
			return
		}
		ui.PrintWarning("Could not preview affected resources; prompting anyway.")
		return
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	fmt.Fprintln(os.Stderr, "--- preview: affected resources ---")
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "(no matching objects found)")
	} else {
		shown := lines
		if len(shown) > maxPreviewLines {
			shown = shown[:maxPreviewLines]
		}
		for _, l := range shown {
			fmt.Fprintln(os.Stderr, "  "+l)
		}
		if len(lines) > maxPreviewLines {
			fmt.Fprintf(os.Stderr, "  … and %d more (%d total)\n", len(lines)-maxPreviewLines, len(lines))
		} else {
			fmt.Fprintf(os.Stderr, "  (%d total)\n", len(lines))
		}
	}
	fmt.Fprintln(os.Stderr, "--- end preview ---")
}

// onOff renders a boolean toggle as "on"/"off" for config output.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// normalizeInheritMode maps the CLI "-" sentinel (and empty) to "", meaning
// "inherit the global mode", and passes any other value through for validation.
func normalizeInheritMode(m string) string {
	if m == "-" {
		return ""
	}
	return m
}

// displayMode renders an actor-policy mode for output: "" (inherit) shows as
// "(inherit)".
func displayMode(m string) string {
	if m == "" {
		return "(inherit)"
	}
	return m
}

// isValidProtectionMode reports whether m is a valid per-pattern protection mode
// (confirm or block). The two axes (context/namespace) share the same values.
func isValidProtectionMode(m string) bool {
	return m == config.ContextModeConfirm || m == config.ContextModeBlock
}

// formatPattern renders a protected pattern with its mode for `config list`:
// "prod-* (block)" for an explicit per-pattern mode, "staging-* (inherit)" when
// it inherits the global context_mode / namespace_mode.
func formatPattern(pp config.ProtectedPattern) string {
	mode := pp.Mode
	if mode == "" {
		mode = "inherit"
	}
	return fmt.Sprintf("%s (%s)", pp.Pattern, mode)
}

// formatClusterKey renders a protected cluster with its mode for `config list` /
// doctor, mirroring formatPattern: "server=https://prod (block)" or
// "server_pattern=*.prod.example.com (inherit)".
func formatClusterKey(pc config.ProtectedCluster) string {
	key := "server=" + pc.Server
	if pc.ServerPattern != "" {
		key = "server_pattern=" + pc.ServerPattern
	}
	mode := pc.Mode
	if mode == "" {
		mode = "inherit"
	}
	return fmt.Sprintf("%s (%s)", key, mode)
}

// printCommandOverrides lists the configured command classification overrides.
func printCommandOverrides(cfg *config.Config) {
	ui.PrintInfo("Command overrides:")
	o := cfg.CommandOverrides
	if len(o.Safe) == 0 && len(o.StateAltering) == 0 && len(o.UnsafeSafe) == 0 {
		fmt.Println("  (none)")
		return
	}
	for _, v := range o.Safe {
		fmt.Printf("  - %s: safe (read-only)\n", v)
	}
	for _, v := range append(append([]string{}, o.StateAltering...), o.UnsafeSafe...) {
		fmt.Printf("  - %s: state-altering (gated)\n", v)
	}
}

// printActorPolicies lists the configured per-actor mode overrides.
func printActorPolicies(cfg *config.Config) {
	ui.PrintInfo("Actor policies:")
	if cfg == nil || len(cfg.ActorPolicies) == 0 {
		fmt.Println("  (none)")
		return
	}
	for _, ap := range cfg.ActorPolicies {
		fmt.Printf("  - %s: context=%s namespace=%s\n", ap.Actor, displayMode(ap.ContextMode), displayMode(ap.NamespaceMode))
	}
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
	cfg := &config.Config{ProtectedContexts: []config.ProtectedPattern{}}
	cfg.ApplyDefaults()
	return cfg, nil
}

func printHelp() {
	help := `kubectl-guard - Protect production clusters and sensitive resources from accidental commands

Usage:
  kubectl-guard [kubectl args...]     Run kubectl with protection
  kubectl-guard config <subcommand>   Manage configuration
  kubectl-guard explain [--json] -- <kubectl args...>
                                      Preflight: would this be gated, and why?
                                      (runs the decision without kubectl/prompt/audit)
  kubectl-guard doctor [--json] [--require-interception]
                                      Health check: interception, config,
                                      audit, context resolution, and posture
                                      (exit non-zero if any check fails;
                                      --require-interception makes an inactive
                                      PATH-shadow a failure, for CI gating)
  kubectl-guard freeze                Global read-only mode: block ALL
                                      state-altering commands (incident switch)
  kubectl-guard unfreeze              Lift read-only mode
  kubectl-guard uninstall [--purge] [--shim-dir <dir>]
                                      Remove the PATH-shadowing shim and report
                                      the PATH line to strip; --purge also
                                      deletes the config + audit log (confirmed)
  kubectl-guard --version             Print version (or -V)
  kubectl-guard --help                Print this help

Protection model:
  - Protected CONTEXTS: state-altering commands require confirmation (or are
    hard-blocked in context_mode: block).
  - Protected CLUSTERS: same gating, but keyed on the API server URL (cluster
    identity) rather than the spoofable context name, so an aliased/renamed
    context or a crafted --kubeconfig still gates. Strictly additive to context
    protection.
  - Protected NAMESPACES: state-altering commands are gated when the target
    namespace (--namespace/-n, the context's namespace, or "default", and any
    namespace under --all-namespaces/-A) matches (or blocked in
    namespace_mode: block). A command whose TARGET OBJECT is a protected
    namespace is also gated, on any context and with no -n
    ("delete namespace kube-system", "delete ns/prod-app"); a namespace command
    naming no names ("delete ns --all", "delete ns -l x=y") is gated whenever
    any namespace is protected, since its targets cannot be known in advance.
  - Protected RESOURCES: any command touching the resource is blocked
    everywhere (reads included), e.g. block all secret access.
  - Dry-run (--dry-run=client|server) skips the prompt; real-mutation forms
    (--dry-run=none|false, plain apply) still gate. Resource blocks still apply.
  - The --context / --kubeconfig / --namespace flags are honored; --server
    (unverifiable cluster) is denied when contexts are protected; --as/--token
    are recorded in the audit log (and --as optionally blocked).

Guard-only flags (stripped before forwarding to kubectl):
  --json         Emit a structured decision object on stderr for non-allow
  --yes          Auto-confirm a gated command (audited; block mode not bypassed)
  --reason <why> Free-text justification recorded on the audit entry for a gated
                 command; required with --yes when require_justification is on
  --no-prompt    Headless: no interactive setup wizard. With no config, the
                 posture comes from KUBECTL_GUARD_BOOTSTRAP (deny by default:
                 state-altering commands are refused, reads pass, nothing is
                 written to disk).

Config subcommands:
  setup                      Run the setup wizard
  init                       Write config non-interactively (headless / CI)
  list                       Show protected contexts, resources, namespaces,
                             confirm mode, and audit log path
  add-context <pattern>      Protect matching contexts (glob)
  remove-context <pattern>   Stop protecting matching contexts
  add-resource <name>        Block a resource everywhere (e.g. secret)
  remove-resource <name>     Stop blocking a resource
  add-namespace <pattern>    Gate state changes in matching namespaces (glob)
  remove-namespace <pattern> Stop protecting matching namespaces
  add-cluster <server|glob>  Protect by CLUSTER identity (the API server URL, or
                             a host glob like '*.prod.example.com'), so an aliased
                             or renamed context cannot dodge protection (optional
                             --mode confirm|block)
  remove-cluster <value>     Stop protecting a cluster (server URL, pattern, or key)
  confirm-mode [simple|type-name|agent-relay]
                             Show or set the confirmation prompt style
                             (type-name requires typing the context/namespace name;
                             agent-relay emits a needs-confirmation JSON on stderr
                             and exits 4 instead of prompting, for agent frameworks)
  context-mode [confirm|block]
                             Show or set how protected contexts are enforced
  namespace-mode [confirm|block]
                             Show or set how protected namespaces are enforced
  blast-radius [off|gate|block]
                             Gate wide-scope / bulk mutations (delete --all,
                             apply --prune, a selector or --all-namespaces on a
                             destructive verb, a force delete) on every context
  actor-policy [<actor> <ctx-mode> [ns-mode] | remove <actor>]
                             Per-actor context/namespace mode overrides (an
                             agent label can be held to block where a human
                             confirms); an override can only tighten, never weaken
  audit-mode [all|gated|off] Show or set what the audit log records
  audit-rotation [<mb> [n]]  Rotate the audit log at <mb> megabytes, keeping n
                             archives (0 mb disables; default n is 5)
  audit-webhook [<url>|off]  POST each audit entry as JSON to a webhook
  audit-syslog [on|off]      Also write each audit entry to local syslog
  command-override [safe <verb> | dangerous <verb> | remove <verb>]
                             Override the built-in safe/state-altering
                             classification of a verb (e.g. a plugin, or treat
                             logs as requiring confirmation)
  unknown-verb [allow|gate|deny]
                             How to treat a verb the guard cannot classify on a
                             protected target: allow (default), gate (confirm),
                             or deny (refuse). Unprotected targets always pass
  confirm-weakening [on|off] Require confirmation for a config change that weakens
                             protection (every config change is audited regardless)
  audit                      Show the audit log path and recent entries
  validate                   Check the config for problems (exit non-zero if any;
                             an invalid config also fails closed at runtime)
  path                       Print the config file path

Examples:
  # Protect production contexts
  kubectl-guard config add-context 'prod-*'

  # Block all secret access on every cluster
  kubectl-guard config add-resource secret

  # Gate state changes in a protected namespace, or hard-block them
  kubectl-guard config add-namespace kube-system
  kubectl-guard config namespace-mode block

  # Require typing the context name to confirm dangerous commands
  kubectl-guard config confirm-mode type-name

  # Forward kubectl normally (alias recommended)
  alias kubectl='kubectl-guard'
  kubectl delete pod nginx    # Prompts on protected contexts

Environment:
  Config file: ~/.kubectl-guard.yaml   (override: KUBECTL_GUARD_CONFIG=/path)
  Audit log:   ~/.kubectl-guard-audit.log  (override: KUBECTL_GUARD_AUDIT_LOG=/path)
  KUBECTL_GUARD_BOOTSTRAP=deny|empty|prompt  Headless first-run posture when no
                 config exists (default deny: refuse state-altering commands,
                 allow reads, write nothing).
  See the README for the other KUBECTL_GUARD_* variables (actor, headless
  bootstrap, CONFIRM, BYPASS, STRICT).
`
	fmt.Print(strings.TrimSpace(help) + "\n")
}

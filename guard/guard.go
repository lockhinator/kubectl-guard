package guard

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/cameronlockhart/kubectl-guard/config"
)

// Result represents the outcome of checking a command.
type Result int

const (
	// Allow means the command should be forwarded to kubectl.
	Allow Result = iota
	// RequireConfirmation means the command needs user confirmation.
	RequireConfirmation
	// Blocked means the command targets a protected resource and is refused.
	Blocked
	// SetupRequired means the config doesn't exist and setup is needed.
	SetupRequired
)

// Check evaluates whether a command should be allowed, require confirmation,
// be blocked, or trigger setup.
func Check(args []string) (Result, string, error) {
	// Check if config exists
	exists, err := config.Exists()
	if err != nil {
		return Allow, "", err
	}
	if !exists {
		return SetupRequired, "", nil
	}

	cfg, err := config.Load()
	if err != nil {
		return Allow, "", err
	}
	cfg.ApplyDefaults()

	// Best-effort context resolution (for messaging). A failure here does not
	// block: kubectl will surface any real error itself.
	ctx, _ := ResolveContext(args)

	// Protected resources are blocked globally, regardless of context or verb.
	if MatchesProtectedResource(cfg, args) {
		return Blocked, ctx, nil
	}

	if ctx == "" {
		return Allow, "", nil
	}

	// Context is protected - check if command is state-altering.
	if cfg.IsContextProtected(ctx) && IsStateAltering(args) {
		return RequireConfirmation, ctx, nil
	}

	return Allow, ctx, nil
}

// LoadConfig loads the config with defaults applied. Returns nil if the config
// does not exist or cannot be read.
func LoadConfig() (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	cfg.ApplyDefaults()
	return cfg, nil
}

// ExecKubectl replaces the current process with kubectl.
func ExecKubectl(args []string) error {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		return err
	}

	// Prepend "kubectl" to args for proper argv[0]
	fullArgs := append([]string{"kubectl"}, args...)

	return syscall.Exec(kubectl, fullArgs, os.Environ())
}

// RunKubectl runs kubectl and returns its output.
func RunKubectl(args ...string) ([]byte, error) {
	cmd := exec.Command("kubectl", args...)
	return cmd.Output()
}

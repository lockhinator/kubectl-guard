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
	// SetupRequired means the config doesn't exist and setup is needed.
	SetupRequired
)

// Check evaluates whether a command should be allowed, require confirmation, or trigger setup.
func Check(args []string) (Result, string, error) {
	// Check if config exists
	exists, err := config.Exists()
	if err != nil {
		return Allow, "", err
	}
	if !exists {
		return SetupRequired, "", nil
	}

	// Load config
	cfg, err := config.Load()
	if err != nil {
		return Allow, "", err
	}

	// Get current context
	ctx, err := GetCurrentContext()
	if err != nil {
		// If we can't get context, allow the command (kubectl will handle errors)
		return Allow, "", nil
	}

	// Check if context is protected
	if !cfg.IsContextProtected(ctx) {
		return Allow, ctx, nil
	}

	// Context is protected - check if command is state-altering
	if IsStateAltering(args) {
		return RequireConfirmation, ctx, nil
	}

	return Allow, ctx, nil
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

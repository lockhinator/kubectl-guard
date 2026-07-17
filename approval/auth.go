package approval

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// Authenticator is intentionally small so a future corporate broker can
// replace local OS authentication without changing request/consumption logic.
type Authenticator interface{ Authenticate(reason string) error }

type OSAuthenticator struct{}

// Authenticate forces a fresh PAM transaction via sudo. On macOS this uses the
// host's sudo PAM policy (Touch ID when pam_tid is enabled, password otherwise).
// Linux likewise uses the machine's configured PAM modules. -k prevents a
// cached sudo timestamp from silently satisfying a new approval.
func (OSAuthenticator) Authenticate(reason string) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return fmt.Errorf("OS authentication is unsupported on %s", runtime.GOOS)
	}
	path, err := exec.LookPath("sudo")
	if err != nil {
		return errorsNoSudo()
	}
	prompt := "kubectl-guard approval — authenticate to run once: " + reason + "\nPassword: "
	cmd := exec.Command(path, "-k", "-p", prompt, "-v")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("OS authentication failed: %w", err)
	}
	// Validation normally creates a reusable sudo timestamp. Invalidate it before
	// returning so approval does not accidentally give the agent a fresh cached
	// sudo capability. This is best-effort; authentication already succeeded.
	cleanup := exec.Command(path, "-K")
	cleanup.Stdin, cleanup.Stdout, cleanup.Stderr = nil, nil, nil
	_ = cleanup.Run()
	return nil
}

func errorsNoSudo() error {
	return fmt.Errorf("OS authentication requires sudo/PAM; sudo was not found")
}

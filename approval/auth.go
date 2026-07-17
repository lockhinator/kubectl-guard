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

// HumanPresenceRequired probes the exact sudo validation path used by
// Authenticate, but forbids prompting. A successful non-interactive validation
// means NOPASSWD (or an equivalent policy) is active and an agent could approve
// its own request. The caller must fail closed in that case.
func HumanPresenceRequired() (bool, string) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return false, fmt.Sprintf("OS authentication is unsupported on %s", runtime.GOOS)
	}
	path, err := exec.LookPath("sudo")
	if err != nil {
		return false, "sudo/PAM is unavailable"
	}
	probe := exec.Command(path, "-n", "-k", "-v")
	probe.Stdin, probe.Stdout, probe.Stderr = nil, nil, nil
	if err := probe.Run(); err == nil {
		// A successful validation may create a timestamp even with -k. Remove it
		// before returning so the diagnostic never leaves reusable privilege.
		invalidateSudo(path)
		return false, "passwordless sudo/PAM validation is enabled; an agent could self-approve"
	}
	return true, "non-interactive sudo validation was rejected; human authentication is required"
}

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
	if required, detail := HumanPresenceRequired(); !required {
		return fmt.Errorf("refusing approval: %s", detail)
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
	invalidateSudo(path)
	return nil
}

func invalidateSudo(path string) {
	cleanup := exec.Command(path, "-K")
	cleanup.Stdin, cleanup.Stdout, cleanup.Stderr = nil, nil, nil
	_ = cleanup.Run()
}

func errorsNoSudo() error {
	return fmt.Errorf("OS authentication requires sudo/PAM; sudo was not found")
}

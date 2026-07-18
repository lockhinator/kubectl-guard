package approval

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Authenticator is intentionally small so a future corporate broker can
// replace local OS authentication without changing request/consumption logic.
type Authenticator interface{ Authenticate(reason string) error }

type OSAuthenticator struct{}

var TrustedSudoPath = "" // optional build-time override; never environment-derived
var TrustedSudoOwnerUID = "0"
var trustedSudoResolver = validateTrustedSudo

func validateTrustedSudo() (string, error) {
	paths := []string{TrustedSudoPath}
	if TrustedSudoPath == "" {
		paths = []string{"/usr/bin/sudo", "/run/wrappers/bin/sudo", "/bin/sudo"}
	}
	var failures []string
	for _, path := range paths {
		if valid, err := validateSudoPath(path); err == nil {
			return valid, nil
		} else {
			failures = append(failures, err.Error())
		}
	}
	return "", fmt.Errorf("no trusted sudo executable found: %s", strings.Join(failures, "; "))
}

func validateSudoPath(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("trusted sudo is unavailable at %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("trusted sudo path %s is not a regular, non-symlink file", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return "", fmt.Errorf("trusted sudo path %s is group/world-writable", path)
	}
	wantUID, err := strconv.ParseUint(TrustedSudoOwnerUID, 10, 32)
	if err != nil {
		return "", errors.New("invalid compiled trusted sudo owner")
	}
	if !ownedByUID(info, uint32(wantUID)) {
		return "", fmt.Errorf("trusted sudo path %s is not owned by uid %d", path, wantUID)
	}
	return path, nil
}

// HumanPresenceRequired probes the exact sudo validation path used by
// Authenticate, but forbids prompting. A successful non-interactive validation
// means NOPASSWD (or an equivalent policy) is active and an agent could approve
// its own request. The caller must fail closed in that case.
func HumanPresenceRequired() (bool, string) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return false, fmt.Sprintf("OS authentication is unsupported on %s", runtime.GOOS)
	}
	path, err := trustedSudoResolver()
	if err != nil {
		return false, err.Error()
	}
	probe := exec.Command(path, "-n", "-k", "-v")
	probe.Stdin, probe.Stdout, probe.Stderr = nil, nil, nil
	if err := probe.Run(); err == nil {
		// A successful validation may create a timestamp even with -k. Remove it
		// before returning so the diagnostic never leaves reusable privilege.
		if err := invalidateSudo(path); err != nil {
			return false, "passwordless sudo/PAM validation is enabled and its timestamp could not be invalidated"
		}
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
	path, err := trustedSudoResolver()
	if err != nil {
		return err
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
	// sudo capability. Cleanup failure is fatal: execution remains fail-closed.
	if err := invalidateSudo(path); err != nil {
		return fmt.Errorf("authentication succeeded but sudo timestamp cleanup failed; refusing approval: %w", err)
	}
	return nil
}

func invalidateSudo(path string) error {
	cleanup := exec.Command(path, "-K")
	cleanup.Stdin, cleanup.Stdout, cleanup.Stderr = nil, nil, nil
	return cleanup.Run()
}

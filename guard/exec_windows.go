//go:build windows

package guard

import "errors"

// execReplace on native Windows returns an error: Windows has no execve, and the
// guard's process-replacement + PATH-shadow interception model is unix-only.
// Native Windows is an explicit non-goal for v1.0 — use WSL2 (see the README
// "Platform support" section). The CLI short-circuits with a WSL2 message on
// GOOS=windows before this is reached, so it is a belt-and-braces guard.
func execReplace(path string, argv, env []string) error {
	return errors.New("native Windows is not supported (no execve); run kubectl-guard under WSL2")
}

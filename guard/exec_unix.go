//go:build !windows

package guard

import "syscall"

// execReplace replaces the current process image with the target binary via
// execve, so kubectl's real exit code, signals, and stdio pass straight through
// (there is no parent to proxy them). This is the unix implementation; Windows
// has no execve and is a documented non-goal (see exec_windows.go).
func execReplace(path string, argv, env []string) error {
	return syscall.Exec(path, argv, env)
}

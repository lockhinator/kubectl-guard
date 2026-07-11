//go:build windows

package guard

// shipSyslog is a no-op on native Windows: the standard library's log/syslog is
// unix-only, and native Windows is a non-goal (see the README "Platform
// support"). It exists only so the package compiles for GOOS=windows.
func shipSyslog(_ []byte) {}

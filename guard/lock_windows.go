//go:build windows

package guard

import "os"

// lockExclusive/unlockFile are no-ops on native Windows, which is an explicit
// non-goal for v1.0 (the CLI exits with a WSL2 message before any audit write, so
// these are never exercised). They exist only so the package compiles for
// GOOS=windows; a real Windows port would use LockFileEx (tracked with the
// Windows-support decision in the README).
func lockExclusive(_ *os.File) error { return nil }

func unlockFile(_ *os.File) {}

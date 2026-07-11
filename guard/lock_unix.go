//go:build !windows

package guard

import (
	"os"
	"syscall"
)

// lockExclusive takes an exclusive advisory lock (flock LOCK_EX) on f, blocking
// until it is acquired, so concurrent audit writers serialize on the lock file's
// stable inode and never interleave lines. unlockFile releases it.
func lockExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func unlockFile(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

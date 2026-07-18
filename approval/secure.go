package approval

import (
	"fmt"
	"os"
)

func ensureSecureDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("approval path %s is not a real directory", path)
	}
	if !currentUserOwned(info) {
		return fmt.Errorf("approval directory %s is not owned by the current user", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("approval directory %s has unsafe mode %#o (want 0700)", path, info.Mode().Perm())
	}
	return nil
}

func checkSecureFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("approval file %s is not a regular, non-symlink file", path)
	}
	if !currentUserOwned(info) {
		return fmt.Errorf("approval file %s is not owned by the current user", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("approval file %s has unsafe mode %#o (want 0600)", path, info.Mode().Perm())
	}
	return nil
}

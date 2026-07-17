//go:build windows

package approval

import "os"

func ownedByUID(os.FileInfo, uint32) bool { return false }
func currentUserOwned(os.FileInfo) bool   { return false }

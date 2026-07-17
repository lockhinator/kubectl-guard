package approval

import (
	"os"
	"testing"
)

func TestEnableState(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if enabled, err := Enabled(); err != nil || enabled {
		t.Fatalf("before setup: enabled=%v err=%v", enabled, err)
	}
	if err := Enable(); err != nil {
		t.Fatal(err)
	}
	if enabled, err := Enabled(); err != nil || !enabled {
		t.Fatalf("after setup: enabled=%v err=%v", enabled, err)
	}
	path, _ := StatePath()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state mode=%#o, want 0600", info.Mode().Perm())
	}
}

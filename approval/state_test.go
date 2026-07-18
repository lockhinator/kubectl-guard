package approval

import (
	"os"
	"path/filepath"
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

func TestStateRejectsMalformedUnsafeAndSymlinkFiles(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"malformed", "not-json"},
		{"provider", `{"enabled_at":"2026-01-01T00:00:00Z","provider":"fake"}`},
		{"timestamp", `{"enabled_at":"never","provider":"sudo-pam"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			path, _ := StatePath()
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Enabled(); err == nil {
				t.Fatal("invalid state accepted")
			}
		})
	}
	t.Run("unsafe-mode", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		path, _ := StatePath()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"enabled_at":"2026-01-01T00:00:00Z","provider":"sudo-pam"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := Enabled(); err == nil {
			t.Fatal("unsafe state accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		path, _ := StatePath()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "state")
		if err := os.WriteFile(target, []byte(`{}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := Enabled(); err == nil {
			t.Fatal("symlink state accepted")
		}
	})
}

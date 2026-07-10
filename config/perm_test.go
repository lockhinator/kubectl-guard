package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInsecureConfigPerms verifies the write-bit tamper check on the FILE: only
// group/world WRITABLE modes are flagged; read-only-to-others modes
// (0600/0640/0644) are not. A missing file is never insecure. The parent dir
// here (t.TempDir, 0700) is secure, so it isolates the file check. #34.
func TestInsecureConfigPerms(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".kubectl-guard.yaml")

	// Missing file: nothing to tamper.
	if insecure, _, err := InsecureConfigPerms(); err != nil || insecure {
		t.Fatalf("missing config: insecure=%v err=%v, want false/nil", insecure, err)
	}

	if err := os.WriteFile(path, []byte("protected_contexts: [prod-*]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		mode     os.FileMode
		insecure bool
	}{
		{0o600, false}, // rw-------
		{0o640, false}, // rw-r----- group read, no write
		{0o644, false}, // rw-r--r-- world read, no write (issue's "0644" is NOT writable)
		{0o660, true},  // rw-rw---- group write
		{0o664, true},  // rw-rw-r-- group write
		{0o666, true},  // rw-rw-rw- group+world write
		{0o602, true},  // rw-----w- other write only
	}
	for _, c := range cases {
		if err := os.Chmod(path, c.mode); err != nil {
			t.Fatal(err)
		}
		insecure, detail, err := InsecureConfigPerms()
		if err != nil {
			t.Fatalf("mode %#o: unexpected err %v", c.mode, err)
		}
		if insecure != c.insecure {
			t.Errorf("mode %#o: insecure=%v (detail=%q), want %v", c.mode, insecure, detail, c.insecure)
		}
		if c.insecure && !strings.Contains(detail, "file") {
			t.Errorf("mode %#o: detail should name the file, got %q", c.mode, detail)
		}
	}
}

// TestInsecureConfigPermsParentDir verifies the parent-directory tamper vector:
// a secure 0600 config in a group/world-writable, non-sticky directory is still
// insecure (an attacker can atomically replace the file), while a sticky writable
// directory (e.g. /tmp semantics) is exempt. #34.
func TestInsecureConfigPermsParentDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".kubectl-guard.yaml")
	if err := os.WriteFile(path, []byte("protected_contexts: [prod-*]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// World-writable, non-sticky parent dir -> insecure (file is 0600).
	if err := os.Chmod(home, 0o777); err != nil {
		t.Fatal(err)
	}
	insecure, detail, err := InsecureConfigPerms()
	if err != nil {
		t.Fatal(err)
	}
	if !insecure {
		t.Errorf("world-writable parent dir with 0600 file: insecure=false, want true")
	}
	if !strings.Contains(detail, "directory") {
		t.Errorf("detail should name the directory, got %q", detail)
	}

	// Add the sticky bit: now safe (only the owner can rename/delete the file).
	if err := os.Chmod(home, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if insecure, _, err := InsecureConfigPerms(); err != nil || insecure {
		t.Errorf("sticky world-writable parent dir: insecure=%v err=%v, want false/nil", insecure, err)
	}

	// Restore a private dir: secure.
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if insecure, _, err := InsecureConfigPerms(); err != nil || insecure {
		t.Errorf("0700 parent dir: insecure=%v err=%v, want false/nil", insecure, err)
	}
}

// TestLoadWrapsInvalidYAML: Load wraps a raw yaml library error with actionable
// context (the config path + "is not valid YAML") instead of leaking the bare
// library string. #38.
func TestLoadWrapsInvalidYAML(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvConfig, "")
	path := filepath.Join(home, ".kubectl-guard.yaml")
	if err := os.WriteFile(path, []byte(":::not valid yaml:::["), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "is not valid YAML") {
		t.Errorf("error not wrapped with context: %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("wrapped error missing the config path: %v", err)
	}
}

// TestStrictPerms verifies strict enforcement is on from either the config field
// or KUBECTL_GUARD_STRICT. #34.
func TestStrictPerms(t *testing.T) {
	if !(&Config{StrictConfigPerms: true}).StrictPerms() {
		t.Error("strict_config_perms: true should be strict")
	}
	if (&Config{}).StrictPerms() {
		t.Error("default should not be strict")
	}
	t.Setenv(EnvStrict, "1")
	if !(&Config{}).StrictPerms() {
		t.Error("KUBECTL_GUARD_STRICT=1 should enable strict")
	}
	t.Setenv(EnvStrict, "0")
	if (&Config{}).StrictPerms() {
		t.Error("KUBECTL_GUARD_STRICT=0 should not enable strict")
	}
}

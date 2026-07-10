package guard

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfigMode writes a config into an isolated HOME at the given permission
// mode (bypassing config.Save, which always writes 0600). HOME is restored by
// t.Setenv. #34.
func writeConfigMode(t *testing.T, yaml string, mode os.FileMode) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".kubectl-guard.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// TestStrictConfigPermsFailsClosed: strict mode (config field) denies EVERY
// command — reads included — when the config is group/world-writable. #34.
func TestStrictConfigPermsFailsClosed(t *testing.T) {
	writeConfigMode(t, "protected_contexts: [prod-*]\nstrict_config_perms: true\n", 0o666)
	for _, args := range [][]string{{"get", "pods"}, {"delete", "pod", "x"}} {
		res, _, _, err := checkWith(args, staticContext("dev"))
		if res != Deny {
			t.Errorf("checkWith(%v), writable config + strict = %v, want Deny", args, res)
		}
		if err == nil {
			t.Errorf("checkWith(%v): expected a tamper error", args)
		}
	}
}

// TestStrictConfigPermsViaEnv: KUBECTL_GUARD_STRICT enables the fail-closed
// behavior without a config field. #34.
func TestStrictConfigPermsViaEnv(t *testing.T) {
	writeConfigMode(t, "protected_contexts: [prod-*]\n", 0o664)
	t.Setenv("KUBECTL_GUARD_STRICT", "1")
	if res, _, _, _ := checkWith([]string{"get", "pods"}, staticContext("dev")); res != Deny {
		t.Errorf("writable config + KUBECTL_GUARD_STRICT = %v, want Deny", res)
	}
}

// TestNonStrictWritableConfigDoesNotDeny: without strict mode the decision core
// does NOT deny a writable config (the warning is main's job); a safe read still
// Allows, so default behavior is unchanged. #34.
func TestNonStrictWritableConfigDoesNotDeny(t *testing.T) {
	writeConfigMode(t, "protected_contexts: [prod-*]\n", 0o666)
	if res, _, _, err := checkWith([]string{"get", "pods"}, staticContext("dev")); res != Allow {
		t.Errorf("writable config non-strict, get pods = %v (err %v), want Allow", res, err)
	}
}

// TestStrictParentDirTamperFailsClosed: a SECURE 0600 config in a group/world-
// writable parent directory is a tamper vector (the file can be atomically
// replaced), so strict mode fails closed even though the file's own mode is fine.
// #34.
func TestStrictParentDirTamperFailsClosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".kubectl-guard.yaml")
	if err := os.WriteFile(path, []byte("protected_contexts: [prod-*]\nstrict_config_perms: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o777); err != nil {
		t.Fatal(err)
	}
	if res, _, _, err := checkWith([]string{"get", "pods"}, staticContext("dev")); res != Deny {
		t.Errorf("writable parent dir + strict, get pods = %v (err %v), want Deny", res, err)
	}
}

// TestSecureConfigNotDeniedUnderStrict: a 0600 config loads and runs normally
// even with strict mode on. #34.
func TestSecureConfigNotDeniedUnderStrict(t *testing.T) {
	writeConfigMode(t, "protected_contexts: [prod-*]\nstrict_config_perms: true\n", 0o600)
	if res, _, _, err := checkWith([]string{"get", "pods"}, staticContext("dev")); res != Allow {
		t.Errorf("0600 config under strict, get pods = %v (err %v), want Allow", res, err)
	}
}

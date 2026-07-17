//go:build !windows

package approval

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeSudo(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sudo")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	original := trustedSudoResolver
	trustedSudoResolver = func() (string, error) { return path, nil }
	t.Cleanup(func() { trustedSudoResolver = original })
	return path
}

func TestHumanPresenceRejectsPasswordlessSudo(t *testing.T) {
	fakeSudo(t, `exit 0`)
	required, detail := HumanPresenceRequired()
	if required {
		t.Fatal("passwordless sudo reported as requiring a human")
	}
	if !strings.Contains(detail, "self-approve") {
		t.Fatalf("detail = %q", detail)
	}
	if err := (OSAuthenticator{}).Authenticate("delete pod api"); err == nil || !strings.Contains(err.Error(), "refusing approval") {
		t.Fatalf("Authenticate error = %v, want fail-closed refusal", err)
	}
}

func TestAuthenticationFailsWhenTimestampCleanupFails(t *testing.T) {
	fakeSudo(t, `case " $* " in *" -n "*) exit 1;; *" -K "*) exit 1;; *) exit 0;; esac`)
	if err := (OSAuthenticator{}).Authenticate("delete pod api"); err == nil || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("Authenticate error=%v, want cleanup failure", err)
	}
}

func TestTrustedSudoIgnoresPATHAndRejectsUnsafeFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	originalPath, originalUID := TrustedSudoPath, TrustedSudoOwnerUID
	TrustedSudoPath, TrustedSudoOwnerUID = filepath.Join(t.TempDir(), "sudo"), fmt.Sprint(os.Geteuid())
	t.Cleanup(func() { TrustedSudoPath, TrustedSudoOwnerUID = originalPath, originalUID })
	if err := os.WriteFile(TrustedSudoPath, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := validateTrustedSudo(); err != nil || got != TrustedSudoPath {
		t.Fatalf("trusted path=%q err=%v, want compiled path %q", got, err, TrustedSudoPath)
	}
	if err := os.Chmod(TrustedSudoPath, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := validateTrustedSudo(); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("error=%v", err)
	}
}

func TestHumanPresenceAcceptsInteractivePolicy(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls")
	fakeSudo(t, `printf '%s\n' "$*" >> "`+log+`"; case " $* " in *" -n "*) exit 1;; *) exit 0;; esac`)
	required, _ := HumanPresenceRequired()
	if !required {
		t.Fatal("interactive sudo policy reported unsafe")
	}
	if err := (OSAuthenticator{}).Authenticate("delete pod api"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "-n -k -v") || !strings.Contains(string(b), "-K") {
		t.Fatalf("expected probe and timestamp invalidation, calls:\n%s", b)
	}
}

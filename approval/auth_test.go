//go:build !windows

package approval

import (
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
	t.Setenv("PATH", dir)
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

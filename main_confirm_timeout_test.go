//go:build !windows

// This test uses syscall.Mkfifo (a named pipe) to simulate a slow/blocking stdin
// for the confirm-timeout path; Mkfifo is unix-only. Native Windows is a non-goal
// (see the README "Platform support"), so the whole test file is unix-tagged to
// keep `GOOS=windows go test ./...` compiling.

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestConfirmTimeoutFiresAndAuditsTimeout is the end-to-end proof of #84: with
// confirm_timeout_seconds set and stdin open but idle, the prompt aborts after
// the window with the needs-confirmation exit code, audited as aborted/timeout,
// and kubectl never runs. stdin is an open FIFO with no writer feeding it, which
// blocks the read exactly like an unattended terminal.
func TestConfirmTimeoutFiresAndAuditsTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - fake-*\nconfirm_timeout_seconds: 1\naudit_mode: all\n")
	kubectlDir := writeFakeKubectl(t)

	// Give the guard an open-but-idle stdin: a FIFO whose read end it consumes
	// while a writer is held open feeding nothing, so its read blocks (as at an
	// unattended terminal) instead of hitting EOF. The read end must be BLOCKING
	// (not O_NONBLOCK, which would make the guard's read return EAGAIN and decline
	// immediately). Opening the two ends rendezvous: each blocks until the other
	// opens, so open the write end from a goroutine.
	fifo := filepath.Join(t.TempDir(), "stdin.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	type opened struct {
		f   *os.File
		err error
	}
	wch := make(chan opened, 1)
	go func() {
		f, e := os.OpenFile(fifo, os.O_WRONLY, 0)
		wch <- opened{f, e}
	}()
	readEnd, err := os.OpenFile(fifo, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open fifo read end: %v", err)
	}
	defer func() { _ = readEnd.Close() }()
	w := <-wch
	if w.err != nil {
		t.Fatalf("open fifo write end: %v", w.err)
	}
	defer func() { _ = w.f.Close() }() // hold the write end open, write nothing

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--context=fake-context", "delete", "pod", "nginx")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	cmd.Stdin = readEnd

	start := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(start)

	code := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("unexpected error running guard: %v", runErr)
	}

	if code != 4 {
		t.Errorf("exit code = %d, want 4 (needs-confirmation after timeout)", code)
	}
	// It must abort roughly at the 1s deadline, not hang for the 30s ctx budget.
	if elapsed > 10*time.Second {
		t.Errorf("guard took %v, expected ~1s (the timeout did not fire)", elapsed)
	}

	data, rerr := os.ReadFile(filepath.Join(home, ".kubectl-guard-audit.log"))
	if rerr != nil {
		t.Fatalf("audit log not written: %v", rerr)
	}
	s := string(data)
	if !strings.Contains(s, `"outcome":"aborted"`) {
		t.Errorf("audit should record aborted, got:\n%s", s)
	}
	if !strings.Contains(s, `"reason":"timeout"`) {
		t.Errorf("audit reason should be timeout, got:\n%s", s)
	}
}

// TestConfirmTimeoutTimelyAnswerRuns: with a timeout configured, a prompt that is
// answered "y" in time runs exactly as it would with no timeout.
func TestConfirmTimeoutTimelyAnswerRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - fake-*\nconfirm_timeout_seconds: 30\naudit_mode: all\n")
	kubectlDir := writeFakeKubectl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--context=fake-context", "delete", "pod", "nginx")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}
	cmd.Stdin = strings.NewReader("y\n")
	out, _ := cmd.Output()

	if !strings.Contains(string(out), "delete pod nginx") {
		t.Errorf("a timely 'y' must run kubectl; stdout = %q", out)
	}
	data, _ := os.ReadFile(filepath.Join(home, ".kubectl-guard-audit.log"))
	if !strings.Contains(string(data), `"outcome":"confirmed"`) {
		t.Errorf("audit should record confirmed, got:\n%s", data)
	}
}

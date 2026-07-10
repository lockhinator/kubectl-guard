package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// syncBuf is a concurrency-safe io.Writer, so the test can poll captured stderr
// while os/exec's copier goroutine writes to it (bytes.Buffer alone would race).
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestSignalDuringPromptAudits: a SIGINT while the guard blocks on a confirmation
// prompt records an aborted/"interrupted" audit entry, prints "Interrupted.", and
// exits non-zero — rather than dying via Go's default handler with no record. #35.
func TestSignalDuringPromptAudits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := buildGuardBin(t)
	home := t.TempDir()
	writeConfig(t, home, "protected_contexts:\n  - prod-*\naudit_mode: all\n")
	kubectlDir := writeFakeKubectl(t)

	cmd := exec.Command(bin, "--context=prod-cluster", "delete", "pod", "nginx")
	cmd.Env = []string{"HOME=" + home, "PATH=" + kubectlDir + ":/usr/bin:/bin"}

	// Keep stdin open but silent so the guard blocks in the prompt's readLine.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdinW.Close() }()
	cmd.Stdin = stdinR

	sb := &syncBuf{}
	cmd.Stderr = sb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = stdinR.Close() // the child holds its own copy

	// Wait until the prompt is on screen (handler installed, blocked on stdin)
	// before signaling, so we exercise the real interrupt path deterministically.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(sb.String(), "Confirm?") {
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("prompt never appeared; stderr so far:\n%s", sb.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}

	waitErr := cmd.Wait()
	code := 0
	if ee, ok := waitErr.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if waitErr != nil {
		t.Fatalf("unexpected wait error: %v", waitErr)
	}

	if code == 0 {
		t.Errorf("interrupted prompt exited 0, want non-zero")
	}
	if !strings.Contains(sb.String(), "Interrupted.") {
		t.Errorf("expected 'Interrupted.' on stderr, got:\n%s", sb.String())
	}

	auditData, rerr := os.ReadFile(home + "/.kubectl-guard-audit.log")
	if rerr != nil {
		t.Fatalf("audit log not written on interrupt: %v", rerr)
	}
	audit := string(auditData)
	if !strings.Contains(audit, "interrupted") {
		t.Errorf("audit log missing the interrupted entry:\n%s", audit)
	}
	// The abandoned command must NOT have run: the fake kubectl echoes "delete ..."
	// to STDOUT (not captured here), but a "confirmed"/"allowed" outcome in the
	// audit would mean it slipped through. Assert it was recorded only as aborted.
	if strings.Contains(audit, `"outcome":"confirmed"`) || strings.Contains(audit, `"outcome":"allowed"`) {
		t.Errorf("interrupted command was recorded as run:\n%s", audit)
	}
}

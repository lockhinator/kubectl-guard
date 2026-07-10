package ui

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestPromptConfirmSimple(t *testing.T) {
	yes := func(s string) bool {
		r := strings.ToLower(strings.TrimSpace(s))
		return r == "y" || r == "yes"
	}
	tests := []struct {
		name  string
		input string
		want  ConfirmOutcome
	}{
		{"y approves", "y\n", ConfirmApproved},
		{"yes approves", "yes\n", ConfirmApproved},
		{"uppercase Y approves", "Y\n", ConfirmApproved},
		{"trailing spaces approve", "  y  \n", ConfirmApproved},
		{"n declines", "n\n", ConfirmDeclined},
		{"empty declines", "\n", ConfirmDeclined},
		{"garbage declines", "maybe\n", ConfirmDeclined},
		{"eof declines", "", ConfirmDeclined},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			got := promptConfirm(&out, strings.NewReader(tt.input), 0, "msg", "Confirm? [y/N]: ", yes)
			if got != tt.want {
				t.Errorf("promptConfirm(%q) = %v, want %v", tt.input, got, tt.want)
			}
			if !strings.Contains(out.String(), "Confirm? [y/N]:") {
				t.Errorf("prompt not written: %q", out.String())
			}
		})
	}
}

func TestPromptConfirmWithName(t *testing.T) {
	matches := func(name string) func(string) bool {
		return func(s string) bool { return strings.TrimSpace(s) == name }
	}
	if got := promptConfirm(io.Discard, strings.NewReader("prod-cluster\n"), 0, "m", "type: ", matches("prod-cluster")); got != ConfirmApproved {
		t.Errorf("exact name = %v, want ConfirmApproved", got)
	}
	if got := promptConfirm(io.Discard, strings.NewReader("y\n"), 0, "m", "type: ", matches("prod-cluster")); got != ConfirmDeclined {
		t.Errorf("a bare y must NOT satisfy the type-name gate: %v", got)
	}
	if got := promptConfirm(io.Discard, strings.NewReader("prod-clustre\n"), 0, "m", "type: ", matches("prod-cluster")); got != ConfirmDeclined {
		t.Errorf("a typo'd name = %v, want ConfirmDeclined", got)
	}
}

// TestPromptConfirmTimeout is the heart of #84: a prompt with a positive timeout
// and no input resolves to ConfirmTimedOut (fail-safe decline), and does so
// promptly — it does not block for anywhere near the wall-clock test budget.
func TestPromptConfirmTimeout(t *testing.T) {
	// A pipe whose write end is never written blocks Read forever, simulating an
	// open-but-unattended stdin.
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()

	done := make(chan ConfirmOutcome, 1)
	start := time.Now()
	go func() {
		done <- promptConfirm(io.Discard, pr, 50*time.Millisecond, "m", "Confirm? [y/N]: ",
			func(string) bool { return true })
	}()

	select {
	case got := <-done:
		if got != ConfirmTimedOut {
			t.Errorf("outcome = %v, want ConfirmTimedOut", got)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("timeout took %v, expected ~50ms", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("promptConfirm did not return; the timeout did not fire")
	}
}

// TestPromptConfirmTimeoutAnswerBeforeDeadline: a timely answer works exactly as
// without a timeout — the timeout must not interfere with a normal confirm.
func TestPromptConfirmTimeoutAnswerBeforeDeadline(t *testing.T) {
	got := promptConfirm(io.Discard, strings.NewReader("y\n"), 5*time.Second, "m", "Confirm? [y/N]: ",
		func(s string) bool { return strings.TrimSpace(s) == "y" })
	if got != ConfirmApproved {
		t.Errorf("outcome = %v, want ConfirmApproved (answer arrived before the deadline)", got)
	}
}

// TestReadLineNoTimeoutBlocksForAnswer: with timeout 0, readLine waits for the
// line rather than returning a timeout.
func TestReadLineNoTimeout(t *testing.T) {
	line, timedOut := readLine(strings.NewReader("hello\n"), 0)
	if timedOut {
		t.Error("timeout with a 0 deadline")
	}
	if line != "hello\n" {
		t.Errorf("line = %q, want %q", line, "hello\n")
	}
}

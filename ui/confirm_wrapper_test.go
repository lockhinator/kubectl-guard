package ui

import (
	"os"
	"testing"
)

// withStdin redirects os.Stdin to a pipe carrying input for the duration of fn,
// so the exported Confirm/ConfirmWithName wrappers (which read os.Stdin
// directly) can be driven without a terminal.
func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	go func() {
		_, _ = w.WriteString(input)
		_ = w.Close()
	}()
	fn()
	os.Stdin = old
	_ = r.Close()
}

// TestConfirmWrapperStdin exercises the exported Confirm wrapper via stdin
// injection (the underlying promptConfirm is tested separately). #32.
func TestConfirmWrapperStdin(t *testing.T) {
	withStdin(t, "y\n", func() {
		if got := Confirm("proceed?", 0); got != ConfirmApproved {
			t.Errorf("Confirm(y) = %v, want ConfirmApproved", got)
		}
	})
	withStdin(t, "n\n", func() {
		if got := Confirm("proceed?", 0); got != ConfirmDeclined {
			t.Errorf("Confirm(n) = %v, want ConfirmDeclined", got)
		}
	})
}

// TestConfirmWithNameWrapperStdin exercises the exported ConfirmWithName wrapper:
// only the exact name approves. #32.
func TestConfirmWithNameWrapperStdin(t *testing.T) {
	withStdin(t, "prod-cluster\n", func() {
		if got := ConfirmWithName("proceed?", "prod-cluster", 0); got != ConfirmApproved {
			t.Errorf("ConfirmWithName(exact) = %v, want ConfirmApproved", got)
		}
	})
	withStdin(t, "prod\n", func() {
		if got := ConfirmWithName("proceed?", "prod-cluster", 0); got != ConfirmDeclined {
			t.Errorf("ConfirmWithName(wrong) = %v, want ConfirmDeclined", got)
		}
	})
}

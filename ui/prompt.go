// Package ui provides interactive terminal prompts for kubectl-guard.
package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// ConfirmOutcome is the result of a confirmation prompt. It distinguishes a
// timeout from an ordinary decline so the caller can audit them differently
// (aborted vs aborted/timeout) and print the right message.
type ConfirmOutcome int

const (
	// ConfirmDeclined means the user answered no, gave an unrecognized answer,
	// or stdin closed (EOF) — anything that is not an explicit yes.
	ConfirmDeclined ConfirmOutcome = iota
	// ConfirmApproved means the user explicitly approved.
	ConfirmApproved
	// ConfirmTimedOut means no answer arrived within the timeout. It is a
	// fail-safe decline: an unanswered "are you sure?" resolves to no.
	ConfirmTimedOut
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12"))

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10"))

	cursorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("14"))

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("11"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8"))
)

// Confirm prompts the user for a yes/no confirmation, waiting at most timeout for
// an answer (timeout <= 0 waits forever). An unanswered prompt resolves to
// ConfirmTimedOut — a fail-safe decline — rather than blocking indefinitely.
func Confirm(message string, timeout time.Duration) ConfirmOutcome {
	return promptConfirm(os.Stderr, os.Stdin, timeout, message, "Confirm? [y/N]: ",
		func(response string) bool {
			r := strings.ToLower(strings.TrimSpace(response))
			return r == "y" || r == "yes"
		})
}

// ConfirmWithName requires the user to type name exactly to confirm. This is a
// stronger gate than Confirm, designed to defeat muscle-memory "y" on
// production contexts. It honors timeout the same way.
func ConfirmWithName(message, name string, timeout time.Duration) ConfirmOutcome {
	prompt := fmt.Sprintf("Type %q to confirm (anything else aborts): ", name)
	return promptConfirm(os.Stderr, os.Stdin, timeout, message, prompt,
		func(response string) bool {
			return strings.TrimSpace(response) == name
		})
}

// promptConfirm writes the warning and prompt to out, reads one line from in
// (bounded by timeout), and classifies it with approved. It is the testable core
// of Confirm/ConfirmWithName: injecting in and out lets tests drive the answer,
// the EOF path, and the timeout without a real terminal.
func promptConfirm(out io.Writer, in io.Reader, timeout time.Duration, message, prompt string, approved func(string) bool) ConfirmOutcome {
	_, _ = fmt.Fprintln(out, warningStyle.Render("⚠️  "+message))
	_, _ = fmt.Fprint(out, prompt)

	response, timedOut := readLine(in, timeout)
	if timedOut {
		return ConfirmTimedOut
	}
	if approved(response) {
		return ConfirmApproved
	}
	return ConfirmDeclined
}

// readLine reads a single line from r. With timeout <= 0 it blocks until a line
// or EOF. With a positive timeout it returns (", true) if no line arrives in
// time. A read error (EOF, closed stdin) yields ("", false) so the caller treats
// it as a decline, matching the previous behavior.
//
// The timeout path reads in a goroutine and selects on a timer. On timeout the
// goroutine is left blocked on the read; that is intentional and harmless — the
// process exits immediately after a timeout (the command was declined), so the
// leaked goroutine never outlives it.
func readLine(r io.Reader, timeout time.Duration) (line string, timedOut bool) {
	read := func() string {
		s, err := bufio.NewReader(r).ReadString('\n')
		if err != nil {
			return ""
		}
		return s
	}

	if timeout <= 0 {
		return read(), false
	}

	ch := make(chan string, 1)
	go func() { ch <- read() }()
	select {
	case s := <-ch:
		return s, false
	case <-time.After(timeout):
		return "", true
	}
}

// PrintSuccess prints a success message.
func PrintSuccess(message string) {
	fmt.Fprintln(os.Stderr, successStyle.Render("✓ "+message))
}

// PrintWarning prints a warning message.
func PrintWarning(message string) {
	fmt.Fprintln(os.Stderr, warningStyle.Render("⚠️  "+message))
}

// PrintInfo prints an info message.
func PrintInfo(message string) {
	fmt.Fprintln(os.Stderr, message)
}

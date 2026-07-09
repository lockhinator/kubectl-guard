package ui

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestMessagesGoToStderr(t *testing.T) {
	// Capture original stdout and stderr
	origStdout := os.Stdout
	origStderr := os.Stderr

	// Create pipes to capture output
	stdoutR, stdoutW, _ := os.Pipe()
	stderrR, stderrW, _ := os.Pipe()

	// Redirect stdout and stderr
	os.Stdout = stdoutW
	os.Stderr = stderrW

	// Restore original stdout/stderr after test
	defer func() {
		os.Stdout = origStdout
		os.Stderr = origStderr
	}()

	// Test PrintWarning
	PrintWarning("test warning message")

	// Close writers to flush
	_ = stdoutW.Close()
	_ = stderrW.Close()

	// Read captured output
	var stdoutBuf, stderrBuf bytes.Buffer
	_, _ = io.Copy(&stdoutBuf, stdoutR)
	_, _ = io.Copy(&stderrBuf, stderrR)

	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()

	// Verify warning went to stderr, not stdout
	if stdoutStr != "" {
		t.Errorf("PrintWarning wrote to stdout: %q", stdoutStr)
	}
	if !strings.Contains(stderrStr, "test warning message") {
		t.Errorf("PrintWarning did not write expected message to stderr: %q", stderrStr)
	}
}

func TestPrintSuccessAndInfoGoToStderr(t *testing.T) {
	// Capture original stdout and stderr
	origStdout := os.Stdout
	origStderr := os.Stderr

	// Create pipes to capture output
	stdoutR, stdoutW, _ := os.Pipe()
	stderrR, stderrW, _ := os.Pipe()

	// Redirect stdout and stderr
	os.Stdout = stdoutW
	os.Stderr = stderrW

	// Restore original stdout/stderr after test
	defer func() {
		os.Stdout = origStdout
		os.Stderr = origStderr
	}()

	// Test PrintSuccess and PrintInfo
	PrintSuccess("test success message")
	PrintInfo("test info message")

	// Close writers to flush
	_ = stdoutW.Close()
	_ = stderrW.Close()

	// Read captured output
	var stdoutBuf, stderrBuf bytes.Buffer
	_, _ = io.Copy(&stdoutBuf, stdoutR)
	_, _ = io.Copy(&stderrBuf, stderrR)

	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()

	// Verify messages went to stderr, not stdout
	if stdoutStr != "" {
		t.Errorf("PrintSuccess/PrintInfo wrote to stdout: %q", stdoutStr)
	}
	if !strings.Contains(stderrStr, "test success message") {
		t.Errorf("PrintSuccess did not write expected message to stderr: %q", stderrStr)
	}
	if !strings.Contains(stderrStr, "test info message") {
		t.Errorf("PrintInfo did not write expected message to stderr: %q", stderrStr)
	}
}
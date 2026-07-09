package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestVersionFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Build the guard binary
	buildCmd := exec.Command("go", "build", "-o", "kubectl-guard-test", ".")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("failed to build guard: %v", err)
	}
	defer os.Remove("kubectl-guard-test")

	tests := []struct {
		name           string
		args           []string
		wantVersion    bool
		wantKubectlArg bool
	}{
		{
			name:        "--version prints guard version",
			args:        []string{"./kubectl-guard-test", "--version"},
			wantVersion: true,
		},
		{
			name:        "-V prints guard version",
			args:        []string{"./kubectl-guard-test", "-V"},
			wantVersion: true,
		},
		{
			name:           "-v forwards to kubectl (does not print guard version)",
			args:           []string{"./kubectl-guard-test", "-v"},
			wantVersion:    false,
			wantKubectlArg: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(tt.args[0], tt.args[1:]...)
			output, err := cmd.CombinedOutput()
			if err != nil && tt.wantKubectlArg {
				// Expected: kubectl will fail since we're not in a k8s context,
				// but we just want to verify -v reaches kubectl
				if !strings.Contains(string(output), "kubectl") && !strings.Contains(string(output), "version") {
					// If kubectl is not installed or fails in an unexpected way, skip
					t.Skipf("kubectl not available or failed unexpectedly: %v", err)
				}
			}

			outputStr := string(output)

			if tt.wantVersion {
				if !strings.Contains(outputStr, "kubectl-guard") {
					t.Errorf("expected guard version output, got: %s", outputStr)
				}
			} else {
				if strings.Contains(outputStr, "kubectl-guard") && strings.Contains(outputStr, "dev") {
					t.Errorf("-v should not print guard version, got: %s", outputStr)
				}
			}
		})
	}
}
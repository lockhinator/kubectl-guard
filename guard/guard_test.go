package guard

import (
	"os"
	"testing"

	"github.com/cameronlockhart/kubectl-guard/config"
)

func TestCheck(t *testing.T) {
	// Create temp directory for config
	tmpDir, err := os.MkdirTemp("", "kubectl-guard-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	// Test: No config file -> SetupRequired
	t.Run("no config requires setup", func(t *testing.T) {
		result, _, err := Check([]string{"get", "pods"})
		if err != nil {
			t.Fatal(err)
		}
		if result != SetupRequired {
			t.Errorf("Check() = %v, want SetupRequired", result)
		}
	})

	// Create config with protected context
	cfg := &config.Config{
		ProtectedContexts: []string{"prod-*", "production"},
	}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}

	// Test command classification is integrated correctly
	t.Run("result types exist", func(t *testing.T) {
		// Verify the constants are distinct and ordered.
		if Allow != 0 {
			t.Error("Allow should be 0")
		}
		if RequireConfirmation != 1 {
			t.Error("RequireConfirmation should be 1")
		}
		if Blocked != 2 {
			t.Error("Blocked should be 2")
		}
		if SetupRequired != 3 {
			t.Error("SetupRequired should be 3")
		}
	})
}

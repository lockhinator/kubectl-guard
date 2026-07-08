package guard

import (
	"os"
	"path/filepath"
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
		result, _, _, err := Check([]string{"get", "pods"})
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

	// Test result ordinals and the fail-closed posture.
	t.Run("result types exist", func(t *testing.T) {
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
		if Deny != 4 {
			t.Error("Deny should be 4")
		}
	})

	// S2: a corrupt config must fail closed (Deny), never pass through.
	t.Run("corrupt config fails closed", func(t *testing.T) {
		path := filepath.Join(tmpDir, ".kubectl-guard.yaml")
		if err := os.WriteFile(path, []byte(":::not valid yaml:::["), 0600); err != nil {
			t.Fatal(err)
		}
		result, _, _, err := Check([]string{"delete", "pod", "nginx"})
		if result != Deny {
			t.Errorf("Check() = %v, want Deny on corrupt config", result)
		}
		if err == nil {
			t.Error("expected an error describing the failure")
		}
	})
}

package guard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cameronlockhart/kubectl-guard/config"
)

// withTempHome points HOME at a fresh temp dir, saves cfg there, and returns a
// cleanup. Lets each test exercise Check against a controlled config without a
// real kubeconfig or kubectl.
func withTempHome(t *testing.T, cfg *config.Config) func() {
	t.Helper()
	tmpDir := t.TempDir()
	orig := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	if cfg != nil {
		if err := config.Save(cfg); err != nil {
			t.Fatal(err)
		}
	}
	return func() { os.Setenv("HOME", orig) }
}

func TestCheck(t *testing.T) {
	withTempHome(t, nil)

	// No config file -> SetupRequired.
	t.Run("no config requires setup", func(t *testing.T) {
		result, _, _, err := Check([]string{"get", "pods"})
		if err != nil {
			t.Fatal(err)
		}
		if result != SetupRequired {
			t.Errorf("Check() = %v, want SetupRequired", result)
		}
	})

	t.Run("result ordinals", func(t *testing.T) {
		if Allow != 0 || RequireConfirmation != 1 || Blocked != 2 || SetupRequired != 3 || Deny != 4 {
			t.Errorf("result ordinals shifted: Allow=%d RequireConfirmation=%d Blocked=%d SetupRequired=%d Deny=%d",
				Allow, RequireConfirmation, Blocked, SetupRequired, Deny)
		}
	})
}

// TestCheckFailClosed locks down S2: the guard must never pass a command
// through when it cannot verify it is safe.
func TestCheckFailClosed(t *testing.T) {
	t.Run("corrupt config is denied", func(t *testing.T) {
		cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
		// Corrupt the file after it was written.
		path := filepath.Join(os.Getenv("HOME"), ".kubectl-guard.yaml")
		if err := os.WriteFile(path, []byte(":::not valid yaml:::["), 0600); err != nil {
			t.Fatal(err)
		}
		defer cleanup()

		result, _, _, err := Check([]string{"delete", "pod", "nginx"})
		if result != Deny {
			t.Errorf("result = %v, want Deny on corrupt config", result)
		}
		if err == nil {
			t.Error("expected an error describing the failure")
		}
	})

	t.Run("unresolvable context with protected contexts is denied", func(t *testing.T) {
		cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
		defer cleanup()
		bad := func(string) (string, error) { return "", errors.New("kubectl not found") }

		result, _, _, err := checkWith([]string{"delete", "pod", "nginx"}, bad)
		if result != Deny {
			t.Errorf("result = %v, want Deny when context is unresolvable", result)
		}
		if err == nil {
			t.Error("expected an error describing the failure")
		}
	})

	t.Run("unresolvable context with no protected contexts is allowed", func(t *testing.T) {
		// Nothing to enforce, so a context resolution failure must not block.
		cleanup := withTempHome(t, &config.Config{})
		defer cleanup()
		bad := func(string) (string, error) { return "", errors.New("kubectl not found") }

		result, _, _, err := checkWith([]string{"delete", "pod", "nginx"}, bad)
		if result != Allow {
			t.Errorf("result = %v, want Allow (nothing to protect)", result)
		}
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestCheckContextProtection locks down S1: a context spoofed after "--" must
// not bypass the guard, because kubectl (and now the guard) ignores flags
// after "--".
func TestCheckContextProtection(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: []string{"prod-*"}})
	defer cleanup()

	prod := func(string) (string, error) { return "prod-cluster", nil }
	dev := func(string) (string, error) { return "dev", nil }

	t.Run("S1: context after -- is ignored, real context governs", func(t *testing.T) {
		// kubectl's real current context is prod-cluster; args try to hide it.
		result, ctx, _, err := checkWith([]string{"delete", "pod", "nginx", "--", "--context=dev"}, prod)
		if err != nil {
			t.Fatal(err)
		}
		if result != RequireConfirmation {
			t.Errorf("result = %v, want RequireConfirmation (spoof must not bypass)", result)
		}
		if ctx != "prod-cluster" {
			t.Errorf("ctx = %q, want prod-cluster", ctx)
		}
	})

	t.Run("explicit context before -- is honored", func(t *testing.T) {
		// Even though the current context is dev, --context=prod wins and gates.
		result, ctx, _, err := checkWith([]string{"--context=prod-cluster", "delete", "pod", "nginx"}, dev)
		if err != nil {
			t.Fatal(err)
		}
		if result != RequireConfirmation {
			t.Errorf("result = %v, want RequireConfirmation", result)
		}
		if ctx != "prod-cluster" {
			t.Errorf("ctx = %q, want prod-cluster", ctx)
		}
	})

	t.Run("safe command on protected context is allowed", func(t *testing.T) {
		result, _, _, err := checkWith([]string{"get", "pods"}, prod)
		if err != nil {
			t.Fatal(err)
		}
		if result != Allow {
			t.Errorf("result = %v, want Allow", result)
		}
	})

	t.Run("state-altering command on unprotected context is allowed", func(t *testing.T) {
		result, _, _, err := checkWith([]string{"delete", "pod", "nginx"}, dev)
		if err != nil {
			t.Fatal(err)
		}
		if result != Allow {
			t.Errorf("result = %v, want Allow", result)
		}
	})
}

// TestCheckResourceProtection locks down S3 and S4 at the Check level:
// protected resources are blocked globally, including un-inspectable sources
// and short-name aliases.
func TestCheckResourceProtection(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: []string{"prod-*"},
		ProtectedResources: []string{"secret", "configmap"},
	})
	defer cleanup()
	dev := func(string) (string, error) { return "dev", nil } // unprotected context

	t.Run("S3: stdin source is blocked", func(t *testing.T) {
		result, _, _, err := checkWith([]string{"apply", "-f", "-"}, dev)
		if err != nil {
			t.Fatal(err)
		}
		if result != Blocked {
			t.Errorf("result = %v, want Blocked for stdin source", result)
		}
	})

	t.Run("S3: url source is blocked", func(t *testing.T) {
		result, _, _, _ := checkWith([]string{"apply", "-f", "https://example.com/secret.yaml"}, dev)
		if result != Blocked {
			t.Errorf("result = %v, want Blocked for url source", result)
		}
	})

	t.Run("S3: kustomize source is blocked", func(t *testing.T) {
		result, _, _, _ := checkWith([]string{"apply", "-k", "./dir"}, dev)
		if result != Blocked {
			t.Errorf("result = %v, want Blocked for kustomize source", result)
		}
	})

	t.Run("S4: short name cm is blocked when configmap protected", func(t *testing.T) {
		result, _, _, _ := checkWith([]string{"get", "cm"}, dev)
		if result != Blocked {
			t.Errorf("result = %v, want Blocked for short name", result)
		}
	})

	t.Run("S4: singular/plural secret forms are blocked", func(t *testing.T) {
		for _, args := range [][]string{
			{"get", "secret"},
			{"get", "secrets"},
			{"describe", "secret", "db"},
		} {
			result, _, _, _ := checkWith(args, dev)
			if result != Blocked {
				t.Errorf("Check(%v) = %v, want Blocked", args, result)
			}
		}
	})

	t.Run("non-protected resource on unprotected context is allowed", func(t *testing.T) {
		result, _, _, _ := checkWith([]string{"get", "pods"}, dev)
		if result != Allow {
			t.Errorf("result = %v, want Allow", result)
		}
	})
}

// TestCheckResourceProtectionRound2 locks down the second-round fixes at the
// Check level: G1 (clustered -f), G5 (comma resource lists), G7 (all/*).
func TestCheckResourceProtectionRound2(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts:  []string{"prod-*"},
		ProtectedResources: []string{"secret"},
	})
	defer cleanup()
	dev := func(string) (string, error) { return "dev", nil } // unprotected

	t.Run("G5: comma list with secret is blocked", func(t *testing.T) {
		for _, args := range [][]string{
			{"get", "secret,configmap"},
			{"get", "configmap,secret"},
			{"get", "pods,secret,services"},
		} {
			result, _, _, _ := checkWith(args, dev)
			if result != Blocked {
				t.Errorf("Check(%v) = %v, want Blocked", args, result)
			}
		}
	})

	t.Run("G7: get all is blocked when a resource is protected", func(t *testing.T) {
		for _, args := range [][]string{{"get", "all"}, {"get", "*"}, {"delete", "all"}} {
			result, _, _, _ := checkWith(args, dev)
			if result != Blocked {
				t.Errorf("Check(%v) = %v, want Blocked", args, result)
			}
		}
	})

	t.Run("G1: clustered -Rf <dir with secret> is blocked", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "s.yaml"),
			[]byte("apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		result, _, _, _ := checkWith([]string{"apply", "-Rf", dir}, dev)
		if result != Blocked {
			t.Errorf("result = %v, want Blocked for -Rf <dir with secret>", result)
		}
	})

	t.Run("H4: resource after -- is blocked", func(t *testing.T) {
		for _, args := range [][]string{
			{"get", "--", "secret"},
			{"delete", "--", "secret", "db"},
			{"get", "pods", "--", "secret"},
		} {
			result, _, _, _ := checkWith(args, dev)
			if result != Blocked {
				t.Errorf("Check(%v) = %v, want Blocked", args, result)
			}
		}
	})
}

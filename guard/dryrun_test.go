package guard

import (
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

func TestParseArgsDryRun(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"client", []string{"apply", "--dry-run=client", "-f", "x.yaml"}, true},
		{"server", []string{"apply", "--dry-run=server", "-f", "x.yaml"}, true},
		{"bare", []string{"apply", "--dry-run", "-f", "x.yaml"}, true},
		{"true", []string{"apply", "--dry-run=true", "-f", "x.yaml"}, true},
		{"none", []string{"apply", "--dry-run=none", "-f", "x.yaml"}, false},
		{"false", []string{"apply", "--dry-run=false", "-f", "x.yaml"}, false},
		{"absent", []string{"apply", "-f", "x.yaml"}, false},
		// Boolean-false forms kubectl accepts (ParseBool) are REAL mutations,
		// so they must not read as dry-runs (previously they bypassed gating).
		{"zero", []string{"apply", "--dry-run=0", "-f", "x.yaml"}, false},
		{"f", []string{"apply", "--dry-run=f", "-f", "x.yaml"}, false},
		{"F-caps", []string{"apply", "--dry-run=F", "-f", "x.yaml"}, false},
		{"False", []string{"apply", "--dry-run=False", "-f", "x.yaml"}, false},
		{"FALSE", []string{"apply", "--dry-run=FALSE", "-f", "x.yaml"}, false},
		// Boolean-true and "unchanged" forms are genuine dry-runs.
		{"one", []string{"apply", "--dry-run=1", "-f", "x.yaml"}, true},
		{"t", []string{"apply", "--dry-run=t", "-f", "x.yaml"}, true},
		{"unchanged", []string{"apply", "--dry-run=unchanged", "-f", "x.yaml"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDryRun(tt.args); got != tt.want {
				t.Errorf("IsDryRun(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

// TestDryRunSkipsContextGating: a state-altering command in dry-run mode on a
// protected context is Allowed (no prompt). Reverting the dry-run check makes
// this RequireConfirmation.
func TestDryRunSkipsContextGating(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"--context=prod-cluster", "apply", "--dry-run=client", "-f", "x.yaml"}, staticContext("prod-cluster"))
	if res != Allow {
		t.Errorf("result = %v, want Allow (dry-run skips gating)", res)
	}
}

// TestDryRunServerSkipsGating: --dry-run=server also skips gating.
func TestDryRunServerSkipsGating(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"--context=prod-cluster", "apply", "--dry-run=server", "-f", "x.yaml"}, staticContext("prod-cluster"))
	if res != Allow {
		t.Errorf("result = %v, want Allow", res)
	}
}

// TestDryRunNoneStillGates: --dry-run=none is a real apply and must still gate.
func TestDryRunNoneStillGates(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"--context=prod-cluster", "apply", "--dry-run=none", "-f", "x.yaml"}, staticContext("prod-cluster"))
	if res != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation (none = real apply)", res)
	}
}

// TestNoDryRunStillGates: an apply with no --dry-run still requires confirmation.
func TestNoDryRunStillGates(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"--context=prod-cluster", "apply", "-f", "x.yaml"}, staticContext("prod-cluster"))
	if res != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation", res)
	}
}

// TestDryRunProtectedResourceStillBlocked: a dry-run of a protected resource is
// still Blocked (resource protection is independent of dry-run).
func TestDryRunProtectedResourceStillBlocked(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedResources: []string{"secret"}})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"get", "secret", "--dry-run=client"}, staticContext("dev"))
	if res != Blocked {
		t.Errorf("result = %v, want Blocked (dry-run of protected resource)", res)
	}
}

// TestDryRunNamespaceGatingSkipped: dry-run also skips namespace protection.
func TestDryRunNamespaceGatingSkipped(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedNamespaces: config.Patterns("kube-system")})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"apply", "--dry-run=client", "-f", "x.yaml", "-n", "kube-system"}, staticContext("dev"))
	if res != Allow {
		t.Errorf("result = %v, want Allow (dry-run skips namespace gating)", res)
	}
}

// TestDryRunFalseFormsDoNotBypassBlockMode: a boolean-false --dry-run value is a
// REAL mutation in kubectl, so it must not skip gating. On a block-mode context
// these must stay Blocked (regression: --dry-run=0 previously slipped through as
// an Allow, defeating "absolute" block mode).
func TestDryRunFalseFormsDoNotBypassBlockMode(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{
		ProtectedContexts: config.Patterns("prod-*"),
		ContextMode:       config.ContextModeBlock,
	})
	defer cleanup()
	for _, v := range []string{"0", "f", "F", "False", "FALSE"} {
		args := []string{"--context=prod-cluster", "delete", "pod", "nginx", "--dry-run=" + v}
		if res, _, _, _ := checkWith(args, staticContext("prod-cluster")); res != Blocked {
			t.Errorf("--dry-run=%s: result = %v, want Blocked (false form is a real mutation)", v, res)
		}
	}
}

// TestDryRunFalseFormStillGatesConfirm: the same false forms still require
// confirmation on a confirm-mode protected context (not Allowed).
func TestDryRunFalseFormStillGatesConfirm(t *testing.T) {
	cleanup := withTempHome(t, &config.Config{ProtectedContexts: config.Patterns("prod-*")})
	defer cleanup()
	res, _, _, _ := checkWith([]string{"--context=prod-cluster", "delete", "pod", "nginx", "--dry-run=0"}, staticContext("prod-cluster"))
	if res != RequireConfirmation {
		t.Errorf("result = %v, want RequireConfirmation (--dry-run=0 is a real mutation)", res)
	}
}

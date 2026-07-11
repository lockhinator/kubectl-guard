package main

import (
	"strings"
	"testing"

	"github.com/lockhinator/kubectl-guard/config"
)

// TestJustificationIntegration exercises #95 end to end via the built binary:
// require_justification forces a reason on approval, --yes needs --reason, an
// empty reason aborts, the reason lands in the audit entry, and the default is
// unchanged.
func TestJustificationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	const req = "protected_contexts: [prod-*]\nrequire_justification: true\naudit_mode: all\n"
	gated := func(stdin string, extra ...string) (int, string) {
		args := append([]string{"--context=prod-cluster"}, extra...)
		args = append(args, "delete", "pod", "nginx")
		return runGuardAudit(t, req, stdin, args...)
	}

	// --yes without --reason: fail closed, audited justification-required.
	if code, audit := gated("", "--yes"); code != 4 {
		t.Errorf("--yes no reason exit %d, want 4", code)
	} else if !strings.Contains(audit, "justification-required") {
		t.Errorf("audit missing justification-required:\n%s", audit)
	}

	// --yes --reason: runs and records the reason.
	if code, audit := gated("", "--yes", "--reason", "hotfix INC-9"); code != 0 {
		t.Errorf("--yes --reason exit %d, want 0", code)
	} else if !strings.Contains(audit, `"justification":"hotfix INC-9"`) {
		t.Errorf("audit missing justification:\n%s", audit)
	}

	// Interactive: y then a reason runs and records confirmed + the reason (also
	// exercises the readLine over-read fix — answer line then reason line).
	if code, audit := gated("y\nfixing outage\n"); code != 0 {
		t.Errorf("interactive y+reason exit %d, want 0", code)
	} else if !strings.Contains(audit, `"outcome":"confirmed"`) || !strings.Contains(audit, "fixing outage") {
		t.Errorf("audit wrong for interactive confirm:\n%s", audit)
	}

	// Interactive: y then an EMPTY reason aborts.
	if code, _ := gated("y\n\n"); code != 4 {
		t.Errorf("interactive empty reason exit %d, want 4 (abort)", code)
	}

	// Interactive with a --reason supplied on the CLI: the reason satisfies the
	// requirement without a second prompt (just the y/N answer needed).
	if code, audit := gated("y\n", "--reason", "provided-on-cli"); code != 0 {
		t.Errorf("interactive y + --reason exit %d, want 0", code)
	} else if !strings.Contains(audit, "provided-on-cli") {
		t.Errorf("CLI --reason not honored on interactive path:\n%s", audit)
	}

	// Default (require_justification off): a y confirms and runs with no reason
	// prompt — behavior unchanged.
	if code, _ := runGuardAudit(t, "protected_contexts: [prod-*]\naudit_mode: all\n", "y\n",
		"--context=prod-cluster", "delete", "pod", "nginx"); code != 0 {
		t.Errorf("default interactive y exit %d, want 0", code)
	}

	// --reason is recorded even when not required (optional justification).
	if _, audit := runGuardAudit(t, "protected_contexts: [prod-*]\naudit_mode: all\n", "",
		"--context=prod-cluster", "--yes", "--reason", "optional note", "delete", "pod", "nginx"); !strings.Contains(audit, "optional note") {
		t.Errorf("optional --reason not recorded:\n%s", audit)
	}
}

// TestRequireJustificationWeakening: turning require_justification off weakens
// protection. #95.
func TestRequireJustificationWeakening(t *testing.T) {
	old := &config.Config{RequireJustification: true}
	if w := config.WeakensProtection(old, &config.Config{}); len(w) == 0 {
		t.Error("disabling require_justification should be weakening")
	}
}

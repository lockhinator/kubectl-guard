package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// parseLastJSONLine extracts the final line of stderr as a JSON decision object.
func parseLastJSONLine(t *testing.T, stderr string) map[string]any {
	t.Helper()
	line := strings.TrimSpace(stderr)
	if i := strings.LastIndex(line, "\n"); i >= 0 {
		line = line[i+1:]
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("stderr is not a JSON object: %v\nstderr=%q", err, stderr)
	}
	return m
}

// TestAgentRelayEmitsNeedsConfirmation is the headline #23 criterion: in
// agent-relay mode, a state-altering command on a protected context exits 4 with
// a JSON needs-confirmation object on stderr, and does NOT prompt or run.
func TestAgentRelayEmitsNeedsConfirmation(t *testing.T) {
	for _, cfg := range []string{
		"protected_contexts:\n  - prod-*\nconfirm_mode: agent-relay\naudit_mode: all\n",
	} {
		stdout, stderr, code, audit := runGuardBin(t, cfg,
			"--context=prod-cluster", "delete", "pod", "nginx")

		if code != 4 {
			t.Fatalf("exit code = %d, want 4 (needs-confirmation)", code)
		}
		if strings.Contains(stdout, "delete") {
			t.Errorf("the command must NOT run in agent-relay mode, got stdout=%q", stdout)
		}
		if strings.Contains(strings.ToLower(stderr), "aborted") {
			t.Errorf("agent-relay must not print an interactive abort, got %q", stderr)
		}
		m := parseLastJSONLine(t, stderr)
		if m["decision"] != "needs-confirmation" {
			t.Errorf("decision = %v, want needs-confirmation", m["decision"])
		}
		if m["context"] != "prod-cluster" {
			t.Errorf("context = %v, want prod-cluster", m["context"])
		}
		if cmd, _ := m["command"].(string); !strings.Contains(cmd, "delete pod nginx") {
			t.Errorf("command = %v, want it to contain the kubectl command", m["command"])
		}
		if prompt, _ := m["prompt"].(string); prompt == "" {
			t.Errorf("expected a human-readable prompt, got %v", m["prompt"])
		}
		if !strings.Contains(audit, `"outcome":"relayed"`) {
			t.Errorf("audit should record outcome relayed, got:\n%s", audit)
		}
	}
}

// TestAgentRelayViaEnvVar: KUBECTL_GUARD_AGENT_RELAY=1 triggers the same
// behavior without a config setting.
func TestAgentRelayViaEnvVar(t *testing.T) {
	stdout, stderr, code, _ := runGuardEnv(t,
		"protected_contexts:\n  - prod-*\n",
		[]string{"KUBECTL_GUARD_AGENT_RELAY=1"},
		"--context=prod-cluster", "delete", "pod", "nginx")

	if code != 4 {
		t.Fatalf("exit code = %d, want 4", code)
	}
	if strings.Contains(stdout, "delete") {
		t.Errorf("command must not run, got stdout=%q", stdout)
	}
	m := parseLastJSONLine(t, stderr)
	if m["decision"] != "needs-confirmation" {
		t.Errorf("decision = %v, want needs-confirmation", m["decision"])
	}
}

// TestAgentRelayResumeWithYes is the resume path: after the human approves via
// the agent, re-running with --yes runs the command (audited as auto-confirmed).
func TestAgentRelayResumeWithYes(t *testing.T) {
	stdout, _, code, audit := runGuardBin(t,
		"protected_contexts:\n  - prod-*\nconfirm_mode: agent-relay\naudit_mode: all\n",
		"--context=prod-cluster", "--yes", "delete", "pod", "nginx")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (--yes resume runs the command)", code)
	}
	if !strings.Contains(stdout, "delete") {
		t.Errorf("expected the command to run, got stdout=%q", stdout)
	}
	if !strings.Contains(audit, `"outcome":"auto-confirmed"`) {
		t.Errorf("audit should record auto-confirmed on the resume, got:\n%s", audit)
	}
}

// TestAgentRelayDoesNotAffectBlocked: a protected-resource block is a hard block
// regardless of confirm mode — agent-relay must not turn it into a relayable
// needs-confirmation.
func TestAgentRelayDoesNotAffectBlocked(t *testing.T) {
	stdout, stderr, code, _ := runGuardBin(t,
		"protected_resources:\n  - secret\nconfirm_mode: agent-relay\n",
		"--json", "get", "secret", "db")

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (blocked, not relayed)", code)
	}
	if strings.Contains(stdout, "secret") {
		t.Errorf("blocked command must not run, got stdout=%q", stdout)
	}
	m := parseLastJSONLine(t, stderr)
	if m["decision"] != "blocked" {
		t.Errorf("decision = %v, want blocked", m["decision"])
	}
}

// TestAgentRelayDoesNotAffectBlockMode: context_mode block hard-refuses too;
// agent-relay must not downgrade it to a relay.
func TestAgentRelayDoesNotAffectBlockMode(t *testing.T) {
	_, stderr, code, _ := runGuardBin(t,
		"protected_contexts:\n  - prod-*\ncontext_mode: block\nconfirm_mode: agent-relay\n",
		"--json", "--context=prod-cluster", "delete", "pod", "nginx")

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (block mode, not relayed)", code)
	}
	m := parseLastJSONLine(t, stderr)
	if m["decision"] != "blocked" {
		t.Errorf("decision = %v, want blocked", m["decision"])
	}
}

// TestAgentRelayReadsPassThrough: reads are never gated, so agent-relay does
// nothing to them.
func TestAgentRelayReadsPassThrough(t *testing.T) {
	stdout, _, code, _ := runGuardBin(t,
		"protected_contexts:\n  - prod-*\nconfirm_mode: agent-relay\n",
		"--context=prod-cluster", "get", "pods")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (reads pass)", code)
	}
	if !strings.Contains(stdout, "get pods") {
		t.Errorf("expected the read to run, got stdout=%q", stdout)
	}
}

// TestAgentRelayRedactsCommand: the emitted command must be redacted (#89).
func TestAgentRelayRedactsCommand(t *testing.T) {
	_, stderr, code, _ := runGuardBin(t,
		"protected_contexts:\n  - prod-*\nconfirm_mode: agent-relay\n",
		"--context=prod-cluster", "delete", "pod", "nginx", "--token=supersecret")

	if code != 4 {
		t.Fatalf("exit code = %d, want 4", code)
	}
	if strings.Contains(stderr, "supersecret") {
		t.Fatalf("agent-relay JSON leaked the token:\n%s", stderr)
	}
	m := parseLastJSONLine(t, stderr)
	if cmd, _ := m["command"].(string); !strings.Contains(cmd, "--token=***") {
		t.Errorf("command should be redacted, got %v", m["command"])
	}
}

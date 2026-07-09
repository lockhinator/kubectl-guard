package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRawSecretReadBlockedEndToEnd is the #80 headline: a raw secret read must
// be blocked (exit 2), never reach kubectl, and be audited. Before the fix this
// returned the secret's value.
func TestRawSecretReadBlockedEndToEnd(t *testing.T) {
	stdout, stderr, code, audit := runGuardBin(t,
		"protected_resources:\n  - secret\naudit_mode: all\n",
		"get", "--raw", "/api/v1/namespaces/default/secrets/db-creds")

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (blocked): stderr=%s", code, stderr)
	}
	if strings.Contains(stdout, "--raw") {
		t.Errorf("the raw request must NOT reach kubectl, got stdout=%q", stdout)
	}
	if !strings.Contains(audit, `"outcome":"blocked"`) {
		t.Errorf("audit should record outcome blocked, got:\n%s", audit)
	}
	if !strings.Contains(stderr, "--raw") {
		t.Errorf("stderr should explain the --raw block, got %q", stderr)
	}
}

// TestRawHealthzAllowedEndToEnd: with no resource protection, --raw passes.
func TestRawHealthzAllowedEndToEnd(t *testing.T) {
	stdout, stderr, code, _ := runGuardBin(t,
		"protected_contexts:\n  - prod-*\naudit_mode: all\n",
		"get", "--raw", "/healthz")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (no resource protection): stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "/healthz") {
		t.Errorf("expected the command forwarded to kubectl, got stdout=%q", stdout)
	}
}

// TestRawBlockedJSONDecision: --json mode emits a structured blocked decision.
func TestRawBlockedJSONDecision(t *testing.T) {
	_, stderr, code, _ := runGuardBin(t,
		"protected_resources:\n  - secret\n",
		"--json", "get", "--raw", "/api/v1/namespaces/default/secrets/db-creds")

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	var jr struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
		Command  string `json:"command"`
	}
	line := strings.TrimSpace(stderr)
	if i := strings.LastIndex(line, "\n"); i >= 0 {
		line = line[i+1:]
	}
	if err := json.Unmarshal([]byte(line), &jr); err != nil {
		t.Fatalf("stderr is not a JSON decision object: %v\nstderr=%q", err, stderr)
	}
	if jr.Decision != "blocked" || jr.Reason != "protected-resource" {
		t.Errorf("decision=%q reason=%q, want blocked/protected-resource", jr.Decision, jr.Reason)
	}
	// --json must never be forwarded to kubectl.
	if strings.Contains(jr.Command, "--json") {
		t.Errorf("guard-only --json leaked into the command string: %q", jr.Command)
	}
}

// TestExecPayloadPathAllowedEndToEnd: `exec -- ls /tmp` must not be blocked by
// the API-path rule just because a resource is protected.
func TestExecPayloadPathAllowedEndToEnd(t *testing.T) {
	_, stderr, code, _ := runGuardBin(t,
		"protected_resources:\n  - secret\naudit_mode: all\n",
		"--context=dev-cluster", "exec", "nginx", "--", "ls", "/tmp")

	if code == 2 {
		t.Fatalf("exec payload path must not be blocked as an API path: stderr=%s", stderr)
	}
}
